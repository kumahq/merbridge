#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "headers/loader_helpers.h"
#include "mb_redir.skel.h"

static struct env {
    bool verbose;
    char *bpffs;
} env;

const char *argp_program_version = "mb_redir 0.1";
const char argp_program_doc[] =
    "BPF mb_redir loader.\n"
    "\n"
    "USAGE: ./mb_redir [-v|--verbose] [-b|--bpffs <path>]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"bpffs", 'b', "/sys/fs/bpf", 0, "BPF filesystem path"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct env *env = state->input;

    switch (key) {
    case 'v':
        env->verbose = true;
        break;
    case 'b':
        env->bpffs = arg;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;

    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

void print_env_maybe()
{
    if (!env.verbose)
        return;

    printf("#### ENV\n");
    printf("%-15s : %s\n", "bpffs", env.bpffs);
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

int main(int argc, char **argv)
{
    struct mb_redir_bpf *skel;
    int err;
    int map_fd;

    env.bpffs = "/sys/fs/bpf";

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
    if (err) {
        printf("parsing arguments failed with error: %d\n", err);
        return err;
    }

    char *prog_pin_path = concat(env.bpffs, "/redir");

    print_env_maybe();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* If program is already pinned, skip as it's probably already attached */
    if (access(prog_pin_path, F_OK) == 0) {
        printf("found pinned program %s - skipping\n", prog_pin_path);
        return 0;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_redir_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        printf("opening program failed with error: %d\n", err);
        return err;
    }

    err = mb_redir_bpf__load(skel);
    if (err) {
        printf("loading program skeleton failed with error: %d\n", err);
        mb_redir_bpf__destroy(skel);
        return err;
    }

    err = bpf_program__pin(skel->progs.mb_msg_redir, prog_pin_path);
    if (err) {
        printf("pinning mb_redir4 program to %s failed with error: %d\n",
               prog_pin_path, err);
        mb_redir_bpf__destroy(skel);
        return err;
    }

    map_fd = bpf_map__fd(skel->maps.sock_pair_map);
    err = bpf_prog_attach(bpf_program__fd(skel->progs.mb_msg_redir), map_fd,
                          BPF_SK_MSG_VERDICT, 0);
    if (err) {
        printf("attaching mb_redir4 program failed with error: %d\n", err);
        mb_redir_bpf__destroy(skel);
        return err;
    }

    return 0;
}
