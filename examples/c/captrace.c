#include <errno.h>
#include <fcntl.h>
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
#include <time.h>

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
    __u32 reaper_pid; // 该 PID namespace 的 child_reaper PID
    __u64 net_ns_inum; // 新增: 网络命名空间 inode (与 BPF 端保持一致)
    char  comm[16];
};

static volatile bool exiting = false;
static void handle_signal(int sig) { (void)sig; exiting = true; }

// 优化：维护 20 个 bucket (pid % 20)，每个 bucket 绑定一个 pid 和其 0..40 cap 的最后打印时间（秒）。
// 若同一 pid 同一 cap 在 60 秒内再次出现则抑制；pid 变化时重置该 bucket。
#define PID_CACHE_BUCKETS 1024
#define SUPPRESS_WINDOW_SEC 60
struct pid_cache_bucket {
    __u32 pid;              // 0 表示空
    uint32_t window_start;  // 窗口起始时间 (秒)
    uint64_t cap_bitmap;    // 记录窗口内已打印过的 cap (bit 0..40)
};
static struct pid_cache_bucket pid_cache[PID_CACHE_BUCKETS];

static inline int suppress_by_pid_cache(__u32 pid, __u32 cap)
{
    if (cap >= 64) return 0; // 防御
    time_t now = time(NULL);
    if (now == (time_t)-1) return 0;
    unsigned idx = pid % PID_CACHE_BUCKETS;
    struct pid_cache_bucket *b = &pid_cache[idx];

    // 触发重置条件：
    // 1) bucket 绑定的 pid 不同
    // 2) 窗口已过期
    if (b->pid != pid || (b->window_start != 0 && (uint32_t)now - b->window_start >= SUPPRESS_WINDOW_SEC)) {
        b->pid = pid;
        b->window_start = (uint32_t)now;
        b->cap_bitmap = 0ULL; // 清空窗口
    }

    uint64_t mask = 1ULL << cap;
    if (b->cap_bitmap & mask)
        return 1; // 在当前窗口内已打印过
    b->cap_bitmap |= mask; // 记录
    return 0;
}

struct env_info {
    char daokeappuk[128];
    char daokeenv[64];
    char instanceid[128];
    char insip[64];
};

static void extract_env_info(pid_t pid, struct env_info *info)
{
    if (!info) return;
    snprintf(info->daokeappuk, sizeof(info->daokeappuk), "UNKNOWN");
    snprintf(info->daokeenv, sizeof(info->daokeenv), "UNKNOWN");
    snprintf(info->instanceid, sizeof(info->instanceid), "UNKNOWN");
    snprintf(info->insip, sizeof(info->insip), "UNKNOWN");
    char path[96];
    snprintf(path, sizeof(path), "/proc/%d/root/proc/1/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return; // silent
    unsigned char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0)
        return; // silent
    ssize_t pos = 0;
    while (pos < n) {
        unsigned char *nul = memchr(buf + pos, '\0', n - pos);
        if (!nul) break;
        ssize_t len = (nul - (buf + pos));
        pos += len + 1;
        if (len == 0) continue;
        char *entry = (char *)(buf + pos - (len + 1));
        if (len > 11 && !strncmp(entry, "DAOKEAPPUK=", 11)) {
            size_t vlen = len - 11; if (vlen >= sizeof(info->daokeappuk)) vlen = sizeof(info->daokeappuk) - 1;
            memcpy(info->daokeappuk, entry + 11, vlen); info->daokeappuk[vlen] = '\0';
        } else if (len > 9 && !strncmp(entry, "DAOKEENV=", 9)) {
            size_t vlen = len - 9; if (vlen >= sizeof(info->daokeenv)) vlen = sizeof(info->daokeenv) - 1;
            memcpy(info->daokeenv, entry + 9, vlen); info->daokeenv[vlen] = '\0';
        } else if (len > 11 && !strncmp(entry, "INSTANCEID=", 11)) {
            size_t vlen = len - 11; if (vlen >= sizeof(info->instanceid)) vlen = sizeof(info->instanceid) - 1;
            memcpy(info->instanceid, entry + 11, vlen); info->instanceid[vlen] = '\0';
        } else if (len > 6 && !strncmp(entry, "INSIP=", 6)) {
            size_t vlen = len - 6; if (vlen >= sizeof(info->insip)) vlen = sizeof(info->insip) - 1;
            memcpy(info->insip, entry + 6, vlen); info->insip[vlen] = '\0';
        }
    }
}

static unsigned long long get_self_netns_inum(void) {
    char buf[128];
    ssize_t n = readlink("/proc/self/ns/net", buf, sizeof(buf)-1);
    if (n < 0) return 0;
    buf[n] = '\0';
    char *l = strchr(buf, '['); if (!l) return 0;
    char *r = strchr(l, ']'); if (!r) return 0;
    *r = '\0';
    unsigned long long v = 0;
    if (sscanf(l+1, "%llu", &v) == 1) return v;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const struct event *e = data;
    const char *name = (e->cap < CAP_MAX) ? cap_names[e->cap] : "UNKNOWN";
    struct env_info envs;
    extract_env_info(e->reaper_pid, &envs); // 只使用 reaper_pid，不做 fallback

    // Skip if DAOKEAPPUK is empty or UNKNOWN
    if (!envs.daokeappuk[0] || strcmp(envs.daokeappuk, "UNKNOWN") == 0)
        return 0;

    // pid%1024 bucket + 窗口内 bitmap 去重
    if (suppress_by_pid_cache(e->pid, e->cap))
        return 0;

    printf("%-6u %-6u %-5u %-24s %-12llu %-8u %-12llu %-20s %-10s %-24s %-15s %s\n",
           e->pid,
           e->tid,
           e->cap,
           name,
           (unsigned long long)e->pid_ns_inum,
           e->reaper_pid,
           (unsigned long long)e->net_ns_inum,
           envs.daokeappuk,
           envs.daokeenv,
           envs.instanceid,
           envs.insip,
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

    // 获取当前进程网络命名空间 inode，并传给 BPF 端用于过滤
    unsigned long long self_netns = get_self_netns_inum();
    if (self_netns)
        printf("Setting filter_net_ns_inum to current netns inode: %llu\n", self_netns);
    else
        printf("Could not determine current netns inode, leaving filter_net_ns_inum=0 (no filtering).\n");
    if (skel->rodata && self_netns)
        skel->rodata->filter_net_ns_inum = self_netns;

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
    printf("%-6s %-6s %-5s %-24s %-12s %-8s %-12s %-20s %-10s %-24s %-15s %s\n",
           "PID", "TID", "CAP", "CAP_NAME", "PID_NS_INUM", "INITPID", "NETNS_INUM",
           "DAOKEAPPUK", "DAOKEENV", "INSTANCEID", "INSIP", "COMM");

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
