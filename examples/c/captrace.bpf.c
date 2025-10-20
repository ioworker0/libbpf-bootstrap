#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

const volatile __u64 filter_net_ns_inum = 0; // 0: 不过滤

struct event {
    __u32 pid;
    __u32 tid;
    __u32 cap;
    __u64 pid_ns_inum;
    __u32 reaper_pid;
    __u64 net_ns_inum; // 网络命名空间 inode
    char  comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct last_key {
    __u32 pid;
    __u32 cap;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct last_key));
    __uint(max_entries, 1); // single slot per CPU
} last_seen SEC(".maps");

// 公共逻辑: 采集 task -> nsproxy -> {net_ns, pid_ns_for_children} , 做过滤并提交事件
static __always_inline int record_cap(int cap)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);

    u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    // Per-CPU last (pid,cap) suppression
    __u32 key0 = 0;
    struct last_key *lk = bpf_map_lookup_elem(&last_seen, &key0);
    if (lk) {
        if (lk->pid == pid && lk->cap == (unsigned)cap) {
            return 0; // suppress identical consecutive event on this CPU
        }
        // update (pid, cap)
        lk->pid = pid;
        lk->cap = cap;
    }

    struct net *net_ns = NULL;
    if (nsp)
        net_ns = BPF_CORE_READ(nsp, net_ns);

    unsigned int net_inum = 0;
    if (net_ns) {
        struct ns_common ns_net_common = {};
        BPF_CORE_READ_INTO(&ns_net_common, net_ns, ns);
        net_inum = ns_net_common.inum;
        if (filter_net_ns_inum && net_inum == filter_net_ns_inum)
            return 0; // 网络命名空间过滤
    }

    unsigned int pidns_inum = 0;
    __u32 reaper_pid = 0;
    struct pid_namespace *pid_ns = NULL;
    if (nsp)
        pid_ns = BPF_CORE_READ(nsp, pid_ns_for_children);
    if (pid_ns) {
        struct ns_common ns_common_val = {};
        BPF_CORE_READ_INTO(&ns_common_val, pid_ns, ns);
        pidns_inum = ns_common_val.inum;
        struct task_struct *reaper = BPF_CORE_READ(pid_ns, child_reaper);
        if (reaper) {
            if (bpf_core_field_exists(reaper->pid)) {
                reaper_pid = BPF_CORE_READ(reaper, pid);
            } else if (bpf_core_field_exists(reaper->tgid)) {
                reaper_pid = BPF_CORE_READ(reaper, tgid);
            }
        }
    }
    if (reaper_pid <= 1)
        return 0; // 过滤不合法的 namespace

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->tid = tid;
    e->cap = (__u32)cap;
    e->net_ns_inum = net_inum;
    e->pid_ns_inum = pidns_inum;
    e->reaper_pid = reaper_pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/ns_capable")
int BPF_KPROBE(handle_ns_capable, void *ignored_ns, int cap)
{
    return record_cap(cap);
}

SEC("kprobe/security_capable")
int BPF_KPROBE(handle_security_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
    return record_cap(cap);
}

char LICENSE[] SEC("license") = "GPL";
