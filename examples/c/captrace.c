#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "captrace.skel.h"

#define CAP_MAX 41 /* 0..40 inclusive */
static const char *cap_names[CAP_MAX] = {
    /*   0 */ "CAP_CHOWN",
    /*   1 */ "CAP_DAC_OVERRIDE",
    /*   2 */ "CAP_DAC_READ_SEARCH",
    /*   3 */ "CAP_FOWNER",
    /*   4 */ "CAP_FSETID",
    /*   5 */ "CAP_KILL",
    /*   6 */ "CAP_SETGID",
    /*   7 */ "CAP_SETUID",
    /*   8 */ "CAP_SETPCAP",
    /*   9 */ "CAP_LINUX_IMMUTABLE",
    /*  10 */ "CAP_NET_BIND_SERVICE",
    /*  11 */ "CAP_NET_BROADCAST",
    /*  12 */ "CAP_NET_ADMIN",
    /*  13 */ "CAP_NET_RAW",
    /*  14 */ "CAP_IPC_LOCK",
    /*  15 */ "CAP_IPC_OWNER",
    /*  16 */ "CAP_SYS_MODULE",
    /*  17 */ "CAP_SYS_RAWIO",
    /*  18 */ "CAP_SYS_CHROOT",
    /*  19 */ "CAP_SYS_PTRACE",
    /*  20 */ "CAP_SYS_PACCT",
    /*  21 */ "CAP_SYS_ADMIN",
    /*  22 */ "CAP_SYS_BOOT",
    /*  23 */ "CAP_SYS_NICE",
    /*  24 */ "CAP_SYS_RESOURCE",
    /*  25 */ "CAP_SYS_TIME",
    /*  26 */ "CAP_SYS_TTY_CONFIG",
    /*  27 */ "CAP_MKNOD",
    /*  28 */ "CAP_LEASE",
    /*  29 */ "CAP_AUDIT_WRITE",
    /*  30 */ "CAP_AUDIT_CONTROL",
    /*  31 */ "CAP_SETFCAP",
    /*  32 */ "CAP_MAC_OVERRIDE",
    /*  33 */ "CAP_MAC_ADMIN",
    /*  34 */ "CAP_SYSLOG",
    /*  35 */ "CAP_WAKE_ALARM",
    /*  36 */ "CAP_BLOCK_SUSPEND",
    /*  37 */ "CAP_AUDIT_READ",
    /*  38 */ "CAP_PERFMON",
    /*  39 */ "CAP_BPF",
    /*  40 */ "CAP_CHECKPOINT_RESTORE",
};

// Minimal event definition mirroring BPF side
struct event {
    __u32 pid;
    __u32 tid;
    __u32 cap;
    __u64 pid_ns_inum;
    char  comm[16];
};

static volatile bool exiting = false;
static void handle_signal(int sig) { (void)sig; exiting = true; }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const struct event *e = data;
    const char *name = (e->cap < CAP_MAX) ? cap_names[e->cap] : "UNKNOWN";
    printf("%-6u %-6u %-5u %-24s %-12llu %s\n",
           e->pid,
           e->tid,
           e->cap,
           name,
           (unsigned long long)e->pid_ns_inum,
           e->comm);
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0; // quiet
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct captrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    const char *btf_path = "/tmp/vmlinux.btf";

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    if (access(btf_path, R_OK) == 0) {
        printf("Found custom BTF at %s, using it.\n", btf_path);
        LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
        skel = captrace_bpf__open_opts(&opts);
    } else {
        printf("Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
        skel = captrace_bpf__open();
    }
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }
    err = captrace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skeleton: %d\n", err);
        goto cleanup;
    }
    err = captrace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1; goto cleanup;
    }

    printf("Listening for ns_capable kprobe events... Press Ctrl+C to stop.\n");
    printf("%-6s %-6s %-5s %-24s %-12s %s\n", "PID", "TID", "CAP", "CAP_NAME", "PID_NS_INUM", "COMM");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while (!exiting) {
        err = ring_buffer__poll(rb, 200);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    captrace_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
