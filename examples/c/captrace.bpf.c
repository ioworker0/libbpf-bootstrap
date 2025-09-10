#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 最小依赖
#define TASK_COMM_LEN 16

struct event {
    __u32 pid;
    __u32 tid;
    __u32 cap;
    __u64 pid_ns_inum; // 当前进程 PID namespace inode
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/ns_capable")
int BPF_KPROBE(handle_ns_capable, void *ignored_ns, int cap)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->cap = (__u32)cap;

    // 读取当前 task 的 pid namespace inode (task->nsproxy->pid_ns_for_children->ns.inum)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    struct pid_namespace *pid_ns = BPF_CORE_READ(nsp, pid_ns_for_children);
    unsigned int inum = 0;
    if (pid_ns) {
        struct ns_common ns_common_val = {};
        BPF_CORE_READ_INTO(&ns_common_val, pid_ns, ns); // read embedded struct
        inum = ns_common_val.inum;
    }
    e->pid_ns_inum = inum;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
