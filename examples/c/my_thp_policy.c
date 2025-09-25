// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

typedef uint64_t u64;

#include "my_thp_policy.skel.h"

enum bpf_thp_vma_type {
    BPF_THP_VM_NONE = 0,
    BPF_THP_VM_HUGEPAGE,
    BPF_THP_VM_NOHUGEPAGE,
};

enum tva_type {
    TVA_SMAPS = 0,
    TVA_PAGEFAULT,
    TVA_KHUGEPAGED,
    TVA_FORCED_COLLAPSE,
    TVA_SWAP,
};

struct thp_event {
    u64 timestamp_ns;
    pid_t pid;
    char comm[16];
    unsigned long vma_start;
    unsigned long vma_end;
    enum bpf_thp_vma_type vma_type;
    enum tva_type tva_type;
    unsigned long original_orders;
    int suggested_order;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

const char *tva_type_to_str(enum tva_type type) {
    switch (type) {
    case TVA_SMAPS:          return "SMAPS";
    case TVA_PAGEFAULT:      return "PAGEFAULT";
    case TVA_KHUGEPAGED:     return "KHUGEPAGED";
    case TVA_FORCED_COLLAPSE:return "FORCED_COLLAPSE";
    case TVA_SWAP:           return "SWAP";
    default:                 return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct thp_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    t = e->timestamp_ns / 1000000000;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-16s %-7d VMA: %016lx-%016lx | Orig_Orders: %2lu | Sug_Order: %2d | VMA_Type: %d | TVA_Type: %s\n",
           ts, e->comm, e->pid,
           e->vma_start, e->vma_end,
           e->original_orders, e->suggested_order, e->vma_type,
           tva_type_to_str(e->tva_type));

    return 0;
}

int main(int argc, char **argv)
{
    struct my_thp_policy_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = my_thp_policy_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }

    err = my_thp_policy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    err = my_thp_policy_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to attach BPF skeleton: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("BPF struct_ops 'bpf_thp_ops' loaded and attached successfully.\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to create ring buffer: %s\n", strerror(-err));
        goto cleanup;
    }

    printf("BPF THP event polling started.\n");
    printf("%-8s %-16s %-7s %s\n", "TIME", "COMM", "PID", "VMA RANGE | ORIG_ORDERS | SUG_ORDER | VMA_TYPE | TVA_TYPE");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("ERROR: polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    my_thp_policy_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}