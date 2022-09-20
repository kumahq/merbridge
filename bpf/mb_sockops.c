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

#include "mb_sockops.skel.h"

static struct env {
    bool verbose;
    char *cgroups_path;
    char *bpffs;
} env;

const char *argp_program_version = "mb_sockops 0.1";
const char argp_program_doc[] =
    "BPF mb_sockops loader.\n"
    "\n"
    "USAGE: ./mb_sockops [-v|--verbose] [-c|--cgroup <path>]\n"
    "        [-b|--bpffs <path>]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"cgroup", 'c', "/sys/fs/cgroup", 0, "cgroup path"},
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
    case 'c':
        env->cgroups_path = arg;
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
    printf("%-15s : %s\n", "cgroupspath", env.cgroups_path);
    printf("%-15s : %s\n", "bpffs", env.bpffs);
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

const char RELATIVE_PIN_PATH[] = "/sockops";

int main(int argc, char **argv)
{
    struct mb_sockops_bpf *skel;
    int err, cgroup_fd;

    env.cgroups_path = "/sys/fs/cgroup";
    env.bpffs = "/sys/fs/bpf";

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
    if (err) {
        fprintf(stderr, "parsing arguments failed with error: %d\n", err);
        return err;
    }

    size_t len = strlen(env.bpffs) + sizeof(RELATIVE_PIN_PATH) + 1;
    char *prog_pin_path = (char *)malloc(len);
    snprintf(prog_pin_path, len, "%s%s", env.bpffs, RELATIVE_PIN_PATH);

    print_env_maybe();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* If program is already pinned, skip as it's probably already attached */
    if (access(prog_pin_path, F_OK) == 0) {
        printf("found pinned program %s - skipping\n", prog_pin_path);
        free(prog_pin_path);
        return 0;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_sockops_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        fprintf(stderr, "opening mb_sockops program failed with error: %d\n",
                err);
        free(prog_pin_path);
        return err;
    }

    err = mb_sockops_bpf__load(skel);
    if (err) {
        fprintf(stderr,
                "loading mb_sockops program skeleton failed with error: %d\n",
                err);
        mb_sockops_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    err = bpf_program__pin(skel->progs.mb_sockops, prog_pin_path);
    if (err) {
        fprintf(stderr,
                "pinning mb_sockops program to %s failed with error: %d\n",
                prog_pin_path, err);
        mb_sockops_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    cgroup_fd = open(env.cgroups_path, O_RDONLY);
    if (cgroup_fd == -1) {
        fprintf(stderr, "opening cgroup %s failed\n", env.cgroups_path);
        mb_sockops_bpf__destroy(skel);
        free(prog_pin_path);
        return 1;
    }

    err = bpf_prog_attach(bpf_program__fd(skel->progs.mb_sockops), cgroup_fd,
                          BPF_CGROUP_SOCK_OPS, 0);
    if (err) {
        fprintf(stderr, "attaching mb_sockops program failed with error: %d\n",
                err);
        close(cgroup_fd);
        mb_sockops_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    free(prog_pin_path);

    return 0;
}
