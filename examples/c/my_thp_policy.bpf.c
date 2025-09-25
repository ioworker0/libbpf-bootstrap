// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
const int THP_2MB_ORDER = 9; /* PMD-sized 2MB (assuming 4K base pages) */

struct thp_event {
    u64 timestamp_ns;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    unsigned long vma_start;
    unsigned long vma_end;
    enum bpf_thp_vma_type vma_type;
    enum tva_type tva_type;
    unsigned long original_orders;
    int suggested_order;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("struct_ops")
int BPF_PROG(thp_get_order, struct vm_area_struct *vma,
             enum bpf_thp_vma_type vma_type,
             enum tva_type tva_type,
             unsigned long orders)
{
    struct thp_event *e;
    pid_t pid;
    int ret_order;

    pid = bpf_get_current_pid_tgid() >> 32;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1;

    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->pid = pid;

    e->vma_start = BPF_CORE_READ(vma, vm_start);
    e->vma_end = BPF_CORE_READ(vma, vm_end);

    e->vma_type = vma_type;
    e->tva_type = tva_type;
    e->original_orders = orders;

    e->suggested_order = -1;
    if (vma_type == BPF_THP_VM_HUGEPAGE)
        e->suggested_order = THP_2MB_ORDER;

    ret_order = e->suggested_order;

    bpf_ringbuf_submit(e, 0);

    return ret_order >= 0 ? ret_order : -1;
}

SEC(".struct_ops.link")
struct bpf_thp_ops bpf_thp_ops = {
    .thp_get_order = (void *)thp_get_order,
};

char LICENSE[] SEC("license") = "GPL";