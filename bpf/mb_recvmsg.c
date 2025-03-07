/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

#include "mb_recvmsg.skel.h"

#define ARG_SHORT_OUT_REDIRECT_PORT 0x80
#define ARG_SHORT_DNS_CAPTURE_PORT 0x82

static struct env {
    bool verbose;
    char *cgroups_path;
    char *bpffs;
    unsigned short int out_redirect_port;
    unsigned short int dns_capture_port;
} env;

const char *argp_program_version = "mb_recvmsg 0.1";
const char argp_program_doc[] =
    "BPF mb_recvmsg loader.\n"
    "\n"
    "USAGE: ./mb_recvmsg [-v|--verbose] [-c|--cgroup <path>]\n"
    "        [-b|--bpffs <path>]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"cgroup", 'c', "PATH", 0, "cgroup path"},
    {"bpffs", 'b', "PATH", 0, "BPF filesystem path"},
    {"out-redirect-port", ARG_SHORT_OUT_REDIRECT_PORT, "PORT", 0,
     "Outbound passthrough port, used to redirect outgoing traffic"},
    {"dns-capture-port", ARG_SHORT_DNS_CAPTURE_PORT, "PORT", 0,
     "Port where DNS traffic should be redirected to"},
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
    case ARG_SHORT_OUT_REDIRECT_PORT:
        errno = 0;
        env->out_redirect_port = (unsigned short int)strtoul(arg, NULL, 0);
        if (errno) {
            fprintf(stderr, "Invalid out-redirect-port: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARG_SHORT_DNS_CAPTURE_PORT:
        errno = 0;
        env->dns_capture_port = (unsigned short int)strtoul(arg, NULL, 0);
        if (errno) {
            fprintf(stderr, "Invalid dns-capture-port: %s\n", arg);
            argp_usage(state);
        }
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
    printf("%-17s : %s\n", "cgroup", env.cgroups_path);
    printf("%-17s : %s\n", "bpffs", env.bpffs);
    printf("%-17s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("%-17s : %u\n", "out-redirect-port", env.out_redirect_port);
    printf("%-17s : %u\n", "dns-capture-port", env.dns_capture_port);
    printf("####\n");
}

const char RELATIVE_PIN_PATH[] = "/recvmsg";

int main(int argc, char **argv)
{
    struct mb_recvmsg_bpf *skel;
    int err, cgroup_fd;

    // default values
    env.bpffs = "/sys/fs/bpf";
    env.cgroups_path = "/sys/fs/cgroup";
    env.out_redirect_port = 15001;
    env.dns_capture_port = 15053;

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

    skel = mb_recvmsg_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        fprintf(stderr, "opening mb_recvmsg objects failed with error: %d\n",
                err);
        free(prog_pin_path);
        return err;
    }

    /* Parameterize BPF code */
    skel->rodata->out_redirect_port = env.out_redirect_port;
    skel->rodata->dns_capture_port = env.dns_capture_port;

    err = mb_recvmsg_bpf__load(skel);
    if (err) {
        fprintf(stderr, "loading mb_recvmsg skeleton failed with error: %d\n",
                err);
        mb_recvmsg_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    err = bpf_program__pin(skel->progs.mb_recvmsg4, prog_pin_path);
    if (err) {
        fprintf(stderr,
                "pinning mb_recvmsg4 program to %s failed with error: %d\n",
                prog_pin_path, err);
        mb_recvmsg_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    cgroup_fd = open(env.cgroups_path, O_RDONLY);
    if (cgroup_fd == -1) {
        fprintf(stderr, "opening cgroup %s failed\n", env.cgroups_path);
        mb_recvmsg_bpf__destroy(skel);
        free(prog_pin_path);
        return 1;
    }

    err = bpf_prog_attach(bpf_program__fd(skel->progs.mb_recvmsg4), cgroup_fd,
                          BPF_CGROUP_UDP4_RECVMSG, 0);
    if (err) {
        fprintf(stderr, "attaching mb_recvmsg4 program failed with error: %d\n",
                err);
        close(cgroup_fd);
        mb_recvmsg_bpf__destroy(skel);
        free(prog_pin_path);
        return err;
    }

    free(prog_pin_path);

    return 0;
}
