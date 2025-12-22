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
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "captrace.skel.h"
#include "config.h"
#include "socket.h"
#include "protocol.h"
#include <time.h>
#include <getopt.h>

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
    char  comm[8];
    char  cmdline[32]; // 新增: 完整命令行
    int   stack_id; // 新增: 栈 ID (-1 未采集)
};

// 选项: 是否打印堆栈
static bool opt_stack = false;
static int stack_fd = -1;

// Plux Agent 配置
static struct plugin_config g_config;
static struct socket_protocol g_socket;
static bool g_enable_plux_agent = false;

/* Function declarations */
int init_plux_agent(int argc, char **argv);

static volatile bool exiting = false;
static void handle_signal(int sig) { (void)sig; exiting = true; }

// 若同一 pid 同一 cap 在 60 秒内再次出现则抑制；pid 变化时重置该 bucket。
#define PID_CACHE_BUCKETS 2048
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
    char daokeip[64];
};

static void extract_env_info(pid_t pid, struct env_info *info)
{
    //https://wiki.17u.cn/wiki?fid=71ae923cfe664d5f8bb53a6c840ea506
    if (!info) return;
    snprintf(info->daokeappuk, sizeof(info->daokeappuk), "UNKNOWN");
    snprintf(info->daokeenv, sizeof(info->daokeenv), "UNKNOWN");
    snprintf(info->instanceid, sizeof(info->instanceid), "UNKNOWN");
    snprintf(info->daokeip, sizeof(info->daokeip), "UNKNOWN");
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
        } else if (len > 8 && !strncmp(entry, "DAOKEIP=", 8)) {
            size_t vlen = len - 8; if (vlen >= sizeof(info->daokeip)) vlen = sizeof(info->daokeip) - 1;
            memcpy(info->daokeip, entry + 8, vlen); info->daokeip[vlen] = '\0';
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

// ====== Kernel symbol resolution (for stack addresses) ======
#define MAX_SYMBOLS 250000
#define MAX_SYMBOL_NAME_LEN 128
struct kernel_symbol { uint64_t addr; char name[MAX_SYMBOL_NAME_LEN]; };
static struct kernel_symbol *kallsyms = NULL;
static int ksym_cnt = 0;

static int load_kernel_symbols(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f)
        return -1;
    kallsyms = malloc(sizeof(*kallsyms) * MAX_SYMBOLS);
    if (!kallsyms) { fclose(f); return -1; }
    char line[256];
    while (ksym_cnt < MAX_SYMBOLS && fgets(line, sizeof(line), f)) {
        uint64_t addr; char type; char name[MAX_SYMBOL_NAME_LEN];
        if (sscanf(line, "%" PRIx64 " %c %127s", &addr, &type, name) == 3) {
            kallsyms[ksym_cnt].addr = addr;
            strncpy(kallsyms[ksym_cnt].name, name, MAX_SYMBOL_NAME_LEN - 1);
            kallsyms[ksym_cnt].name[MAX_SYMBOL_NAME_LEN - 1] = '\0';
            ksym_cnt++;
        }
    }
    fclose(f);
    return 0;
}

static const char *resolve_kernel_symbol(uint64_t addr)
{
    static char buf[MAX_SYMBOL_NAME_LEN + 32];
    if (ksym_cnt == 0) return "[no_kallsyms]";
    int l = 0, r = ksym_cnt - 1, mi = -1;
    while (l <= r) {
        int m = l + (r - l) / 2;
        if (kallsyms[m].addr <= addr) { mi = m; l = m + 1; } else r = m - 1; }
    if (mi >= 0) {
        uint64_t off = addr - kallsyms[mi].addr;
        snprintf(buf, sizeof(buf), "%s+0x%lx", kallsyms[mi].name, (unsigned long)off);
        return buf;
    }
    return "[unresolved]";
}
// ====== End kernel symbol resolution ======

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const struct event *e = data;
    const char *name = (e->cap < CAP_MAX) ? cap_names[e->cap] : "UNKNOWN";
    struct env_info envs;

    // 处理 cmdline: 将 \0 替换为空格以便显示
    char cmdline_display[32];
    memcpy(cmdline_display, e->cmdline, sizeof(cmdline_display));
    for (int i = 0; i < (int)sizeof(cmdline_display) - 1; i++) {
        if (cmdline_display[i] == '\0') {
            // 如果遇到连续的 \0，说明已经到达字符串末尾
            if (i > 0 && cmdline_display[i-1] == '\0')
                break;
            cmdline_display[i] = ' ';  // 将参数分隔符 \0 替换为空格
        }
    }
    cmdline_display[sizeof(cmdline_display) - 1] = '\0';

    // pid%n bucket + 窗口内 bitmap 去重
    if (!g_enable_plux_agent && suppress_by_pid_cache(e->pid, e->cap))
        return 0;

    extract_env_info(e->reaper_pid, &envs); // 只使用 reaper_pid，不做 fallback

    // 只有在非 Plux Agent 模式下才检查 DAOKEAPPUK
    if (!g_enable_plux_agent) {
        // Skip if DAOKEAPPUK is empty or UNKNOWN
        if (!envs.daokeappuk[0] || strcmp(envs.daokeappuk, "UNKNOWN") == 0)
            return 0;
    }


    // 发送 event 给 plugin，g_enable_plux_agent = true
    if (g_enable_plux_agent) {
        struct captrace_event_data event_data = {
            .cap = e->cap,
            .reaper_pid = e->reaper_pid
        };

        // 复制字符串数据
        strncpy(event_data.comm, e->comm, sizeof(event_data.comm) - 1);
        strncpy(event_data.cmdline, cmdline_display, sizeof(event_data.cmdline) - 1);

        // 确保字符串以 null 结尾
        event_data.comm[sizeof(event_data.comm) - 1] = '\0';
        event_data.cmdline[sizeof(event_data.cmdline) - 1] = '\0';

        // 创建 JSON 数据
        char json_buf[1024];
        int ret = create_captrace_event_json(&event_data, json_buf, sizeof(json_buf));
        if (ret > 0) {
            // 发送事件给 Agent
            socket_send_event(&g_socket, json_buf, ret);
        }

        // 如果配置了 stack 且有堆栈数据，发送堆栈信息
        if (g_config.stack && e->stack_id >= 0 && stack_fd >= 0) {
            unsigned long addrs[127] = {0};
            int key = e->stack_id;
            if (bpf_map_lookup_elem(stack_fd, &key, addrs) == 0) {
                // 统计实际深度
                uint32_t depth = 0;
                for (int i = 0; i < 127; i++) {
                    if (!addrs[i]) break;
                    depth++;
                }

                // 填充 stacktrace_data
                struct stacktrace_data stacktrace;
                stacktrace.depth = depth;
                for (uint32_t i = 0; i < depth; i++) {
                    stacktrace.addresses[i] = addrs[i];
                }

                // 复制其他字段
                strncpy(stacktrace.comm, e->comm, sizeof(stacktrace.comm) - 1);
                strncpy(stacktrace.cmdline, cmdline_display, sizeof(stacktrace.cmdline) - 1);
                stacktrace.cap = e->cap;
                stacktrace.reaper_pid = e->reaper_pid;

                // 确保字符串以 null 结尾
                stacktrace.comm[sizeof(stacktrace.comm) - 1] = '\0';
                stacktrace.cmdline[sizeof(stacktrace.cmdline) - 1] = '\0';

                // 发送堆栈给 Agent
                if (socket_send_stacktrace(&g_socket, &stacktrace) < 0) {
                    fprintf(stderr, "Failed to send stacktrace\n");
                }
            }
        }
    } else {
        // 原有的打印逻辑
        printf("%-6u %-6u %-5u %-24s %-12llu %-8u %-12llu %-20s %-10s %-24s %-15s %-8s %-32s\n",
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
               envs.daokeip,
               e->comm,
               cmdline_display);

        if (opt_stack && e->stack_id >= 0 && stack_fd >= 0) {
            unsigned long addrs[127] = {0};
            int key = e->stack_id;
            if (bpf_map_lookup_elem(stack_fd, &key, addrs) == 0) {
                printf("  stack_id=%d\n", e->stack_id);
                for (int i = 0; i < 127; i++) {
                    if (!addrs[i]) break;
                    printf("    [%02d] [<%016lx>] %s\n", i, addrs[i], resolve_kernel_symbol(addrs[i]));
                }
            }
        }
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0; // quiet
    return vfprintf(stderr, fmt, args);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  -s, --stack          Capture & print kernel stack for each event\n"
        "  -c, --config CONFIG  JSON configuration for Plux Agent\n"
        "  -h, --help           Show this help\n", prog);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct captrace_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    const char *btf_path = "/plux/btf/kernel.btf";

    // 提升内存锁定限制，BPF maps 需要锁定内存
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Warning: failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        // 继续执行，libbpf 会自动处理
    }

    static const struct option long_opts[] = {
        {"stack", no_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {"config", required_argument, NULL, 'c'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "shc:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': opt_stack = true; break;
        case 'h': usage(argv[0]); return 0;
        case 'c': /* config option will be handled in init_plux_agent */ break;
        default: usage(argv[0]); return 1;
        }
    }

    // 初始化 Plux Agent
    err = init_plux_agent(argc, argv);

    // g_config.stack 不直接打印 stack，而是发送给 agent
//    if (g_enable_plux_agent && g_config.stack) {
//        opt_stack = true;
//    }

    // 如果开启堆栈且未启用 Plux Agent, 才加载内核符号
    if (opt_stack && !g_enable_plux_agent) {
        if (load_kernel_symbols() != 0) {
            fprintf(stderr, "Warning: failed to load /proc/kallsyms, will show raw addresses.\n");
        } else {
            fprintf(stderr, "Loaded %d kernel symbols.\n", ksym_cnt);
        }
    }
    if (err < 0) {
        fprintf(stderr, "Failed to initialize Plux Agent (continuing without Agent): %d\n", err);
        printf("Running in standalone mode - no Plux Agent connection\n");
        // 注意：这里不退出，即使 Agent 初始化失败也继续运行
    } else {
        printf("Plux Agent connection established successfully!\n");
        printf("Listening for capability events and sending to Agent...\n");
    }

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

    // 设置是否采集堆栈
    // - 命令行 -s 参数：standalone 模式打印堆栈
    // - 配置 stack: true：Agent 模式发送堆栈
    bool should_capture_stack = opt_stack || (g_enable_plux_agent && g_config.stack);
    if (skel->rodata)
        skel->rodata->capture_stack = should_capture_stack;

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

    // 记录栈 map fd
    // - Standalone 模式 + opt_stack：需要用于打印和符号解析
    // - Agent 模式 + g_config.stack：需要用于发送堆栈给 Agent
    if (should_capture_stack)
        stack_fd = bpf_map__fd(skel->maps.stack_traces);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1; goto cleanup;
    }

    printf("Listening for ns_capable kprobe events... Press Ctrl+C to stop.\n");
    printf("%-6s %-6s %-5s %-24s %-12s %-8s %-12s %-20s %-10s %-24s %-15s %-8s %-32s\n",
           "PID", "TID", "CAP", "CAP_NAME", "PID_NS_INUM", "INITPID", "NETNS_INUM",
           "DAOKEAPPUK", "DAOKEENV", "INSTANCEID", "DAOKEIP", "COMM", "CMDLINE");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100); // 100ms
        if (err < 0) {
            fprintf(stderr, "Polling error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    captrace_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}

// 配置解析相关函数

// 初始化 Plux Agent 连接
int init_plux_agent(int argc, char **argv)
{
    int err;

    printf("=== Initializing Plux Agent connection ===\n");

    // 初始化配置
    init_plugin_config(&g_config);
    strncpy(g_config.plugin_name, "plux-ebpf-captrace", sizeof(g_config.plugin_name) - 1);
    printf("Plugin name: %s\n", g_config.plugin_name);

    // 解析命令行配置
    err = parse_config_args(argc, argv, &g_config);
    if (err < 0) {
        fprintf(stderr, "Failed to parse config: %d\n", err);
        return err;
    }

    // 检查是否提供了 socket_path
    if (strlen(g_config.socket_path) == 0) {
        printf("No socket_path provided in config, running without Plux Agent\n");
        printf("Use: --config '{\"socket_path\":\"/path/to/socket\"}' to enable Agent\n");
        g_enable_plux_agent = false;
        return 0;
    }

    printf("Target socket path: %s\n", g_config.socket_path);
    printf("Debug mode: %s\n", g_config.debug_mode ? "enabled" : "disabled");
    printf("Heartbeat interval: %d seconds\n", g_config.heartbeat_interval);
    printf("Stack capture: %s\n", g_config.stack ? "enabled" : "disabled");

    // 检查 socket 文件是否存在
    err = check_socket_file(g_config.socket_path);
    if (err < 0) {
        fprintf(stderr, "Socket file not accessible: %s (error: %d)\n", g_config.socket_path, err);
        return err;
    }
    printf("Socket file exists and is accessible\n");

    // 初始化 socket 协议
    err = init_socket_protocol(&g_socket, &g_config);
    if (err < 0) {
        fprintf(stderr, "Failed to init socket protocol: %d\n", err);
        return err;
    }
    printf("Socket protocol initialized\n");

    // 连接到 Agent
    err = socket_connect(&g_socket);
    if (err < 0) {
        fprintf(stderr, "Failed to connect to Plux Agent: %d\n", err);
        return err;
    }
    printf("Connected to Plux Agent\n");

    // 发送握手
    err = socket_send_handshake(&g_socket);
    if (err < 0) {
        fprintf(stderr, "Failed to send handshake: %d\n", err);
        return err;
    }
    printf("Handshake sent successfully\n");

    // 启动心跳
    err = socket_start_heartbeat(&g_socket);
    if (err < 0) {
        fprintf(stderr, "Failed to start heartbeat: %d\n", err);
        return err;
    }
    printf("Heartbeat thread started (%d second interval)\n", g_config.heartbeat_interval);

    // 发送 info 日志：socket_path 已获取
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "[plux-ebpf-captrace] Socket path configured: %s", g_config.socket_path);
    err = socket_send_log_info(&g_socket, log_msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send info log: %d\n", err);
        // 不返回错误，继续执行
    } else {
        printf("Info log sent: %s\n", log_msg);
    }

    // 发送 info 日志：stack 配置
    snprintf(log_msg, sizeof(log_msg), "[plux-ebpf-captrace] Stack capture %s", 
             g_config.stack ? "enabled" : "disabled");
    err = socket_send_log_info(&g_socket, log_msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send stack config log: %d\n", err);
        // 不返回错误，继续执行
    } else {
        printf("Info log sent: %s\n", log_msg);
    }

    printf("=== Plux Agent connection established ===\n");
    g_enable_plux_agent = true;
    return 0;
}
