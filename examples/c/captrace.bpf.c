#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 8
#define CMDLINE_LEN 32

#define CAP_OPT_NOAUDIT 2

const volatile __u64 filter_net_ns_inum = 0; // 0: 不过滤
const volatile bool capture_stack = false;   // 是否采集堆栈 (由用户态设置)

// Capability 过滤 bitmap: bit=1 表示**忽略**该 capability
// 默认忽略噪音较多的 capability（对应 Go 端的 defaultCapabilities）
const volatile __u64 ignored_caps_bitmap = 
    (1ULL << 0)  | // CAP_CHOWN
    (1ULL << 1)  | // CAP_DAC_OVERRIDE
    (1ULL << 2)  | // CAP_DAC_READ_SEARCH
    (1ULL << 3)  | // CAP_FOWNER
    (1ULL << 4)  | // CAP_FSETID
    (1ULL << 5)  | // CAP_KILL
    (1ULL << 6)  | // CAP_SETGID
    (1ULL << 7)  | // CAP_SETUID
    (1ULL << 8)  | // CAP_SETPCAP
    (1ULL << 10) | // CAP_NET_BIND_SERVICE
    (1ULL << 13) | // CAP_NET_RAW
    (1ULL << 18) | // CAP_SYS_CHROOT
    (1ULL << 23) | // CAP_SYS_NICE
    (1ULL << 27) | // CAP_MKNOD
    (1ULL << 29) | // CAP_AUDIT_WRITE
    (1ULL << 31);  // CAP_SETFCAP

struct event {
    __u32 pid;
    __u32 tid;
    __u32 cap;
    __u64 pid_ns_inum;
    __u32 reaper_pid;
    __u64 net_ns_inum; // 网络命名空间 inode
    char  comm[TASK_COMM_LEN];
    char  cmdline[CMDLINE_LEN];
    s32   stack_id; // -1 未采集
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB，可存储约 30万+ 事件
} events SEC(".maps");

// 栈跟踪 map (用于获取内核栈帧地址)
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * 32);  // 每个堆栈 32 个地址，约 256 字节
    __uint(max_entries, 32768);  // 最多 32768 个不同堆栈，约 8MB 内存
} stack_traces SEC(".maps");

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
static __always_inline int record_cap(int cap, int stack_id)
{
    // 过滤: 检查该 capability 是否在忽略列表中
//    if (cap >= 0 && cap < 64) {
//        __u64 mask = 1ULL << cap;
//        if (ignored_caps_bitmap & mask) {
//            return 0;  // 忽略该 capability
//        }
//    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);

    u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    // Per-CPU last (pid,cap) suppression
    __u32 key0 = 0;
    struct last_key *lk = bpf_map_lookup_elem(&last_seen, &key0);
    if (lk) {
// 不过滤，交给 plugin 处理
//        if (lk->pid == pid && lk->cap == (unsigned)cap) {
//            return 0; // suppress identical consecutive event on this CPU
//        }
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
    
    // 初始化 cmdline 为空字符串
    __builtin_memset(e->cmdline, 0, sizeof(e->cmdline));
    
    // 读取 cmdline (从进程的 mm 结构体)
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        unsigned long len = arg_end - arg_start;
        if (len > CMDLINE_LEN - 1)
            len = CMDLINE_LEN - 1;
        if (len > 0) {
            bpf_probe_read_user(&e->cmdline, len, (void *)arg_start);
            // 确保以 null 结尾
            e->cmdline[CMDLINE_LEN - 1] = '\0';
        }
    }
    
    e->stack_id = stack_id;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/ns_capable")
int BPF_KPROBE(handle_ns_capable, void *ignored_ns, int cap)
{
    return 0; // 暂时跳过，最终都会调用 security_capable
    int sid = -1;
    if (capture_stack)
        sid = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    return record_cap(cap, sid);
}

SEC("kprobe/security_capable")
int BPF_KPROBE(handle_security_capable, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
{
    if (opts & CAP_OPT_NOAUDIT)
        return 0;
    int sid = -1;
    if (capture_stack)
        sid = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    return record_cap(cap, sid);
}

SEC("kprobe/ns_capable_common")
int BPF_KPROBE(handle_ns_capable_common, struct user_namespace *ns, int cap, unsigned int opts)
{
    return 0; // 暂时跳过，最终都会调用 security_capable
    if (opts & CAP_OPT_NOAUDIT)
        return 0;
    int sid = -1;
    if (capture_stack)
        sid = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    return record_cap(cap, sid);
}

char LICENSE[] SEC("license") = "GPL";
