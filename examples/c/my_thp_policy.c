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
#include <stdint.h> // added for uint64_t

// define u64 for user space to match BPF side definition
typedef uint64_t u64;

// Include the generated BPF skeleton header
#include "my_thp_policy.skel.h"

// --- Event structure (must match BPF program's definition) ---
// Copy this from the .bpf.c file to ensure consistency
// And define enums that are part of the event structure
enum bpf_thp_vma_type {
	BPF_THP_VM_NONE = 0,
	BPF_THP_VM_HUGEPAGE,
	BPF_THP_VM_NOHUGEPAGE,
};

// Define tva_type enum for user-space
enum tva_type {
	TVA_SMAPS = 0,		/* Exposing "THPeligible:" in smaps. */
	TVA_PAGEFAULT,		/* Serving a non-swap page fault. */
	TVA_KHUGEPAGED,		/* Khugepaged collapse. */
	TVA_FORCED_COLLAPSE,	/* Forced collapse (e.g. MADV_COLLAPSE). */
	TVA_SWAP,		/* Serving a swap */
};

struct thp_event {
	u64 timestamp_ns;
	pid_t pid;
	char comm[16]; // TASK_COMM_LEN is 16
	unsigned long vma_start;
	unsigned long vma_end;
	enum bpf_thp_vma_type vma_type;
	enum tva_type tva_type; // ADDED: tva_type field
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

// --- Helper to convert tva_type enum to string ---
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

/*
 * Callback function for handling events from the BPF ring buffer.
 */
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
           tva_type_to_str(e->tva_type)); // ADDED: Print tva_type as string

    return 0;
}

int main(int argc, char **argv)
{
    struct my_thp_policy_bpf *skel;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link = NULL; // manage struct_ops link manually
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = my_thp_policy_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }

    err = my_thp_policy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // Attach struct_ops via its map (bpf_thp_ops) generated from .struct_ops section
    link = bpf_map__attach_struct_ops(skel->maps.bpf_thp_ops);
    if (!link) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to attach struct_ops (bpf_thp_ops): %s\n", strerror(errno));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "ERROR: Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("BPF THP policy program loaded and attached.\n");
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
    if (link)
        bpf_link__destroy(link);
    my_thp_policy_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}