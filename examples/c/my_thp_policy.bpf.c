// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h" // Essential for kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16 // Define TASK_COMM_LEN for comm buffer size

// Define bpf_thp_vma_type enum, as it's not always in vmlinux.h
enum bpf_thp_vma_type {
	BPF_THP_VM_NONE = 0,
	BPF_THP_VM_HUGEPAGE,	/* VM_HUGEPAGE */
	BPF_THP_VM_NOHUGEPAGE,	/* VM_NOHUGEPAGE */
};

// Define tva_type enum for BPF program
// This enum is from kernel source and must match exactly for BPF to correctly interpret it.
enum tva_type {
	TVA_SMAPS = 0,		/* Exposing "THPeligible:" in smaps. */
	TVA_PAGEFAULT,		/* Serving a non-swap page fault. */
	TVA_KHUGEPAGED,		/* Khugepaged collapse. */
	TVA_FORCED_COLLAPSE,	/* Forced collapse (e.g. MADV_COLLAPSE). */
	TVA_SWAP,		/* Serving a swap */
};


// Define the target THP order for 2MB (PMD-sized).
// This assumes PAGE_SIZE is 4KB.
// order = log2(2MB / 4KB) = log2(512) = 9.
// In the kernel, this is often represented by PMD_ORDER.
const int THP_2MB_ORDER = 9; // For 2MB THP (assuming 4KB base page size)


// --- Event structure to send to user-space ---
struct thp_event {
	u64 timestamp_ns;
	pid_t pid;
	char comm[TASK_COMM_LEN]; // TASK_COMM_LEN is 16
	unsigned long vma_start;
	unsigned long vma_end;
	enum bpf_thp_vma_type vma_type;
	enum tva_type tva_type;
	unsigned long original_orders;
	int suggested_order; // -1 if no change, or specific order (e.g., 9 for 2MB)
};

// --- BPF Ring Buffer Map ---
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

/* struct_ops thp_get_order implementation */
SEC("struct_ops/thp_get_order")
int my_thp_get_order(struct vm_area_struct *vma_ptr,
                     enum bpf_thp_vma_type vma_type_arg,
                     enum tva_type tva_type_arg,
                     unsigned long orders_arg)
{
    struct thp_event *e;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1; // fallback: no change

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->vma_start = BPF_CORE_READ(vma_ptr, vm_start);
    e->vma_end = BPF_CORE_READ(vma_ptr, vm_end);
    e->vma_type = vma_type_arg;
    e->tva_type = tva_type_arg;
    e->original_orders = orders_arg;

    e->suggested_order = -1; // default: no change
    int final_suggested_order = -1;

    /* Suggest 2MB (order 9) only if:
     * - VMA is explicitly hugepage preferred
     * - Caller requested that order (bit set in orders_arg)
     */
    if (vma_type_arg == BPF_THP_VM_HUGEPAGE && (orders_arg & (1UL << THP_2MB_ORDER))) {
        e->suggested_order = THP_2MB_ORDER;
        final_suggested_order = THP_2MB_ORDER;
    }

    bpf_ringbuf_submit(e, 0);
    return final_suggested_order; /* -1 keeps original orders */
}


char LICENSE[] SEC("license") = "GPL";