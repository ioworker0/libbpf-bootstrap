// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpdrop_tracer.skel.h"
#include "config.h"
#include "socket.h"
#include "protocol.h"

/* Event structure matching BPF side */
struct event {
    __u64 timestamp;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 drop_reason;
    __u8  tcp_state;
    __u8  tcp_flags;
    __s32 stack_id;
};

/* TCP state names */
static const char *tcp_state_names[] = {
    [1] = "ESTABLISHED",
    [2] = "SYN_SENT",
    [3] = "SYN_RECV",
    [4] = "FIN_WAIT1",
    [5] = "FIN_WAIT2",
    [6] = "TIME_WAIT",
    [7] = "CLOSE",
    [8] = "CLOSE_WAIT",
    [9] = "LAST_ACK",
    [10] = "LISTEN",
    [11] = "CLOSING",
    [12] = "NEW_SYN_RECV",
};

#define TCP_STATE_MAX 12

/* Drop reason names (从内核获取) */
#define REASON_MAX_LEN 64
#define MAX_DROP_REASONS 128
static char drop_reasons[MAX_DROP_REASONS][REASON_MAX_LEN];
static int drop_reason_max = 0;
static bool drop_reason_inited = false;

/* Plux Agent 配置 */
static struct plugin_config g_config;
static struct socket_protocol g_socket;
static bool g_enable_plux_agent = false;
static int stack_fd = -1;

static volatile bool exiting = false;

/* Signal handler */
static void handle_signal(int sig)
{
    fprintf(stderr, "[SIGNAL] Received signal %d, exiting...\n", sig);
    exiting = true;
}

/* Helper to search for a string in a file stream */
static bool fsearch(FILE *f, char *target)
{
    char tmp[128];
    while (fscanf(f, "%s", tmp) == 1) {
        if (strstr(tmp, target))
            return true;
    }
    return false;
}

/* Parse drop reason enum from tracefs */
static int parse_reason_enum(void)
{
    char name[REASON_MAX_LEN];
    int index = 0;
    FILE *f;

    f = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format", "r");
    if (!f || !fsearch(f, "__print_symbolic")) {
        if (f)
            fclose(f);
        return -1;
    }

    while (true) {
        if (!fsearch(f, "{") ||
            fscanf(f, "%d, \"%63[A-Z_0-9]\"", &index, name) != 2)
            break;
        if (index < MAX_DROP_REASONS)
            strcpy(drop_reasons[index], name);
    }
    drop_reason_max = index;
    drop_reason_inited = true;

    fclose(f);
    return 0;
}

/* Get drop reason name */
static const char *get_drop_reason_name(int reason)
{
    if (!drop_reason_inited || reason < 0 || reason > drop_reason_max)
        return "UNKNOWN";
    return drop_reasons[reason];
}

/* Get TCP state name */
static const char *get_tcp_state_name(__u8 state)
{
    if (state > 0 && state <= TCP_STATE_MAX && tcp_state_names[state])
        return tcp_state_names[state];
    return "UNKNOWN";
}

/* Format TCP flags */
static void format_tcp_flags(__u8 flags, char *buf, size_t size)
{
    int pos = 0;
    if (flags & 0x01) pos += snprintf(buf + pos, size - pos, "FIN ");
    if (flags & 0x02) pos += snprintf(buf + pos, size - pos, "SYN ");
    if (flags & 0x04) pos += snprintf(buf + pos, size - pos, "RST ");
    if (flags & 0x08) pos += snprintf(buf + pos, size - pos, "PSH ");
    if (flags & 0x10) pos += snprintf(buf + pos, size - pos, "ACK ");
    if (flags & 0x20) pos += snprintf(buf + pos, size - pos, "URG ");
    if (pos > 0 && buf[pos - 1] == ' ')
        buf[pos - 1] = '\0';  // 移除末尾空格
    else
        buf[0] = '\0';
}

/* Event handler */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    const struct event *e = data;

    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    char flags_str[32];

    /* 转换 IP 地址 */
    struct in_addr saddr = { .s_addr = e->saddr };
    struct in_addr daddr = { .s_addr = e->daddr };
    inet_ntop(AF_INET, &saddr, saddr_str, sizeof(saddr_str));
    inet_ntop(AF_INET, &daddr, daddr_str, sizeof(daddr_str));

    /* 格式化 TCP flags */
    format_tcp_flags(e->tcp_flags, flags_str, sizeof(flags_str));

    /* Agent 模式: 只发送堆栈 */
    if (g_enable_plux_agent) {
        if (e->stack_id >= 0 && stack_fd >= 0) {
            unsigned long addrs[MAX_STACK_DEPTH];
            int key = e->stack_id;
            
            if (bpf_map_lookup_elem(stack_fd, &key, addrs) == 0) {
                /* 统计实际深度 */
                uint32_t depth = 0;
                for (int i = 0; i < MAX_STACK_DEPTH; i++) {
                    if (!addrs[i])
                        break;
                    depth++;
                }

                /* 填充 tcp_drop_stacktrace_data */
                struct tcp_drop_stacktrace_data stacktrace = {0};
                stacktrace.timestamp = e->timestamp;
                stacktrace.saddr = e->saddr;
                stacktrace.daddr = e->daddr;
                stacktrace.sport = e->sport;
                stacktrace.dport = e->dport;
                stacktrace.drop_reason = e->drop_reason;
                stacktrace.tcp_state = e->tcp_state;
                stacktrace.tcp_flags = e->tcp_flags;
                stacktrace.depth = depth;

                /* 复制堆栈地址 */
                for (uint32_t i = 0; i < depth && i < MAX_STACK_DEPTH; i++) {
                    stacktrace.addresses[i] = addrs[i];
                }
                
                /* 设置终止标记 */
                if (depth < MAX_STACK_DEPTH) {
                    stacktrace.addresses[depth] = 0;
                }

                /* 创建 JSON 并发送 */
                char json_buf[8192];  // 大 buffer 用于堆栈数据
                int ret = create_tcp_drop_stacktrace_json(&stacktrace, json_buf, sizeof(json_buf));
                if (ret > 0) {
                    /* 使用 MSG_TYPE_STACKTRACE (0x0008) */
                    if (socket_send_raw_message(&g_socket, MSG_TYPE_STACKTRACE, json_buf, ret) < 0) {
                        fprintf(stderr, "[ERROR] Failed to send stacktrace (errno: %d, %s)\n",
                                errno, strerror(errno));
                    }
                } else {
                    fprintf(stderr, "[ERROR] Failed to create stacktrace JSON, ret=%d\n", ret);
                }
            }
        }
    } else {
        /* Standalone 模式: 打印到控制台 */
        fprintf(stdout, "[%llu] TCP DROP: %s:%u -> %s:%u state=%s flags=[%s] reason=%s(%u)\n",
                e->timestamp,
                saddr_str, e->sport,
                daddr_str, e->dport,
                get_tcp_state_name(e->tcp_state),
                flags_str,
                get_drop_reason_name(e->drop_reason),
                e->drop_reason);
    }

    return 0;
}

/* libbpf print callback */
static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

/* Usage */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n\n"
        "Options:\n"
        "  -c, --config CONFIG  JSON configuration for Plux Agent\n"
        "  -h, --help           Show this help\n\n"
        "Example:\n"
        "  %s                                    # Standalone mode\n"
        "  %s --config '{\"socket_path\":\"/tmp/agent.sock\",\"plugin_name\":\"tcpdrop\",\"stack\":true}'\n",
        prog, prog, prog);
}

/* Initialize Plux Agent */
static int init_plux_agent(int argc, char **argv)
{
    /* 初始化配置 */
    init_plugin_config(&g_config);
    
    /* 设置默认 plugin name */
    snprintf(g_config.plugin_name, sizeof(g_config.plugin_name), "tcpdrop_tracer");
    
    /* 默认开启堆栈采集 */
    g_config.stack = true;

    /* 解析命令行参数 */
    if (parse_config_args(argc, argv, &g_config) < 0) {
        return -1;
    }

    /* 检查是否配置了 socket_path */
    if (g_config.socket_path[0] == '\0') {
        return 0;  // 未配置 Agent，使用 standalone 模式
    }

    /* 初始化 socket protocol */
    if (init_socket_protocol(&g_socket, &g_config) < 0) {
        fprintf(stderr, "[ERROR] Failed to initialize socket protocol\n");
        return -1;
    }

    /* 连接到 Agent */
    if (socket_connect(&g_socket) < 0) {
        fprintf(stderr, "[ERROR] Failed to connect to Agent socket: %s\n", g_config.socket_path);
        return -1;
    }

    fprintf(stderr, "[INFO] Connected to Agent: %s\n", g_config.socket_path);

    /* 发送握手 */
    if (socket_send_handshake(&g_socket) < 0) {
        fprintf(stderr, "[ERROR] Failed to send handshake\n");
        socket_disconnect(&g_socket);
        return -1;
    }

    fprintf(stderr, "[INFO] Handshake sent, plugin_name=%s\n", g_config.plugin_name);

    /* 启动心跳线程 */
    if (socket_start_heartbeat(&g_socket) < 0) {
        fprintf(stderr, "[ERROR] Failed to start heartbeat\n");
        socket_disconnect(&g_socket);
        return -1;
    }

    g_enable_plux_agent = true;
    return 0;
}

int main(int argc, char **argv)
{
    struct tcpdrop_tracer_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* 设置 libbpf 错误和调试信息回调 */
    libbpf_set_print(libbpf_print_fn);

    /* 初始化 Plux Agent（如果配置了） */
    if (init_plux_agent(argc, argv) < 0) {
        fprintf(stderr, "[ERROR] Failed to initialize Plux Agent\n");
        return 1;
    }

    /* 解析 drop reasons */
    if (parse_reason_enum() < 0) {
        fprintf(stderr, "[WARN] Failed to parse drop reasons from tracefs\n");
    } else {
        fprintf(stderr, "[INFO] Parsed %d drop reasons\n", drop_reason_max);
    }

    /* 打开并加载 BPF 应用 */
    skel = tcpdrop_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "[ERROR] Failed to open BPF skeleton\n");
        return 1;
    }

    /* 加载 & 验证 BPF 程序 */
    err = tcpdrop_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint */
    err = tcpdrop_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* 获取 stack_traces map fd */
    stack_fd = bpf_map__fd(skel->maps.stack_traces);
    if (stack_fd < 0) {
        fprintf(stderr, "[ERROR] Failed to get stack_traces map fd\n");
        goto cleanup;
    }

    fprintf(stderr, "[INFO] Successfully started! Monitoring TCP drops...\n");
    if (!g_enable_plux_agent) {
        fprintf(stderr, "[INFO] Running in standalone mode (use --config to enable Agent)\n");
    }

    /* 设置信号处理 */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* 创建 ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "[ERROR] Failed to create ring buffer\n");
        goto cleanup;
    }

    /* 主循环：处理事件 */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "[ERROR] Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    fprintf(stderr, "[INFO] Cleaning up...\n");
    
    /* 清理 ring buffer */
    if (rb)
        ring_buffer__free(rb);
    
    /* 清理 BPF skeleton */
    if (skel)
        tcpdrop_tracer_bpf__destroy(skel);
    
    /* 断开 Agent 连接 */
    if (g_enable_plux_agent) {
        socket_stop_heartbeat(&g_socket);
        socket_disconnect(&g_socket);
    }

    fprintf(stderr, "[INFO] Exited\n");
    return err < 0 ? -err : 0;
}
