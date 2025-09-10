#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "skb_kfree_skb_no_reason.skel.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
    __u64 timestamp;
    __u32 pid;
    __u32 drop_reason;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 state;
    __u8 tcpflags;
    char comm[TASK_COMM_LEN];
    __u32 stack_id;
};

#define REASON_MAX_LEN 64
#define MAX_DROP_REASONS 128

char drop_reasons[MAX_DROP_REASONS][REASON_MAX_LEN];
int drop_reason_max = 0;
bool drop_reason_inited = false;
struct skb_kfree_skb_no_reason_bpf *skel;

bool fsearch(FILE *f, char *target) {
    char tmp[128];

    while (fscanf(f, "%s", tmp) == 1) {
        if (strstr(tmp, target)) {
            return true;
        }
    }
    return false;
}

static int parse_reason_enum() {
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
            fscanf(f, "%d, \"%31[A-Z_0-9]\"", &index, name) != 2)
            break;
        strcpy(drop_reasons[index], name);
    }
    drop_reason_max = index;
    drop_reason_inited = true;

    fclose(f);
    return 0;
}

void print_drop_reasons() {
    if (!drop_reason_inited) {
        printf("Drop reasons not initialized. Please parse first.\n");
        return;
    }

    printf("Parsed drop reasons:\n");
    for (int i = 0; i <= drop_reason_max; i++) {
        printf("  ID: %d, Name: %s\n", i, drop_reasons[i]);
    }
}

static const char *get_drop_reason_name(int reason) {
    if (reason >= 0 && reason <= drop_reason_max) {
        return drop_reasons[reason];
    }
    return "UNKNOWN";
}

const char *tcp_states[] = {
    [0] = "CLOSED",
    [1] = "LISTEN",
    [2] = "SYN_SENT",
    [3] = "SYN_RECV",
    [4] = "ESTABLISHED",
    [5] = "FIN_WAIT1",
    [6] = "FIN_WAIT2",
    [7] = "CLOSE_WAIT",
    [8] = "CLOSING",
    [9] = "LAST_ACK",
    [10] = "TIME_WAIT",
    [11] = "DELETE_TCB",
};


static char *tcp_flags_to_str(__u8 flags, char *buf, size_t buf_size) {
    size_t pos = 0;

    if (flags & 0x01) pos += snprintf(buf + pos, buf_size - pos, "FIN|");
    if (flags & 0x02) pos += snprintf(buf + pos, buf_size - pos, "SYN|");
    if (flags & 0x04) pos += snprintf(buf + pos, buf_size - pos, "RST|");
    if (flags & 0x08) pos += snprintf(buf + pos, buf_size - pos, "PSH|");
    if (flags & 0x10) pos += snprintf(buf + pos, buf_size - pos, "ACK|");
    if (flags & 0x20) pos += snprintf(buf + pos, buf_size - pos, "URG|");
    if (flags & 0x40) pos += snprintf(buf + pos, buf_size - pos, "ECE|");
    if (flags & 0x80) pos += snprintf(buf + pos, buf_size - pos, "CWR|");

    if (pos > 0) buf[pos - 1] = '\0';
    else snprintf(buf, buf_size, "NONE");

    return buf;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define NANOSECONDS_IN_SECOND 1000000000

time_t get_boot_time() {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) {
        perror("Failed to open /proc/stat");
        return 0;
    }

    char line[256];
    time_t boot_time = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "btime %ld", &boot_time) == 1) {
            fclose(fp);
            return boot_time;
        }
    }

    fclose(fp);
    fprintf(stderr, "Failed to find btime in /proc/stat\n");
    return 0;
}

#define MAX_SYMBOLS 200000
#define MAX_SYMBOL_NAME_LEN 128

struct kernel_symbol {
    uint64_t addr;
    char name[MAX_SYMBOL_NAME_LEN];
};

static struct kernel_symbol symbols[MAX_SYMBOLS];
static int symbol_count = 0;

static int load_kernel_symbols() {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        perror("Failed to open /proc/kallsyms");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uint64_t addr;
        char type;
        char name[MAX_SYMBOL_NAME_LEN];

        if (sscanf(line, "%lx %c %s", &addr, &type, name) == 3) {
            if (symbol_count < MAX_SYMBOLS) {
                symbols[symbol_count].addr = addr;
                strncpy(symbols[symbol_count].name, name, MAX_SYMBOL_NAME_LEN - 1);
                symbols[symbol_count].name[MAX_SYMBOL_NAME_LEN - 1] = '\0';
                symbol_count++;
            } else {
                fprintf(stderr, "Symbol table exceeds maximum size (%d)\n", MAX_SYMBOLS);
                break;
            }
        }
    }

    fclose(f);
    printf("Loaded %d kernel symbols\n", symbol_count);

    for (int i = 0; i < 10 && i < symbol_count; i++) {
    printf("Symbol %d: addr=0x%lx, name=%s\n", i, symbols[i].addr, symbols[i].name);
		}


    return 0;
}

const char *resolve_kernel_symbol(uint64_t addr) {
    static char symbol[MAX_SYMBOL_NAME_LEN + 32];

    int left = 0, right = symbol_count - 1;
    int match_index = -1;

    while (left <= right) {
        int mid = (left + right) / 2;

        if (symbols[mid].addr <= addr) {
            match_index = mid;
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    if (match_index != -1) {
        uint64_t offset = addr - symbols[match_index].addr;
        snprintf(symbol, sizeof(symbol), "%s+0x%lx", symbols[match_index].name, offset);
        return symbol;
    }

    return "UNKNOWN";
}

#define MAX_STACK_DEPTH 15

static void print_stack_trace(int stack_map_fd, uint32_t stack_id) {
    uint64_t ips[MAX_STACK_DEPTH] = {0};
    int ret;

    if (stack_id == 0) {
        printf("  [Invalid stack ID 0]\n");
        return;
    }

//    ret = bpf_map__lookup_elem(stack_map_fd, &stack_id, ips);
    ret = bpf_map_lookup_elem_flags(stack_map_fd, &stack_id, ips, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to lookup stack trace (id: %u), error: %d\n", stack_id, ret);
        return;
    }

    printf("Stack trace (id: %u):\n", stack_id);
    for (int i = 0; i < MAX_STACK_DEPTH && ips[i]; i++) {
        const char *symbol = resolve_kernel_symbol(ips[i]);
        printf("  #%-2d 0x%016lx [%s]\n", i, ips[i], symbol);
    }
}


static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;

    time_t boot_time = get_boot_time();
    if (boot_time == 0) {
        fprintf(stderr, "Could not retrieve boot time\n");
        return 0;
    }

    uint64_t elapsed_seconds = e->timestamp / NANOSECONDS_IN_SECOND;

    time_t event_time = boot_time + elapsed_seconds;

    struct tm tm;
    localtime_r(&event_time, &tm);

    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &e->daddr, dst_ip, sizeof(dst_ip));

    const char *tcp_state = e->state < ARRAY_SIZE(tcp_states) ? tcp_states[e->state] : "UNKNOWN";
    char tcp_flags_buf[64];
    tcp_flags_to_str(e->tcpflags, tcp_flags_buf, sizeof(tcp_flags_buf));

    const char *drop_reason = get_drop_reason_name(e->drop_reason);

    printf("\nTime: %s | PID: %u | Comm: %s | Reason: %d %s\n",
           time_buf,
           e->pid,
           e->comm,
           e->drop_reason,
           drop_reason);

    printf("Src: %s:%u -> Dst: %s:%u | State: %s | Flags: %s\n",
           src_ip, e->sport,
           dst_ip, e->dport,
           tcp_state, tcp_flags_buf);

    int stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
    if (stack_map_fd >= 0 && e->stack_id != 0) {
        print_stack_trace(stack_map_fd, e->stack_id);
    }


    return 0;
}


int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    const char *btf_path = "/tmp/vmlinux.btf";
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    if (load_kernel_symbols() < 0) {
        fprintf(stderr, "Failed to load kernel symbols\n");
        return -1;
    }

    if (access(btf_path, R_OK) == 0) {
        printf("Found custom BTF at %s, using it.\n", btf_path);
        LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
        skel = skb_kfree_skb_no_reason_bpf__open_opts(&opts);
    } else {
        printf("Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
        skel = skb_kfree_skb_no_reason_bpf__open();
    }

    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = skb_kfree_skb_no_reason_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = skb_kfree_skb_no_reason_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

//    if (parse_reason_enum() < 0) {
//	    fprintf(stderr, "Failed to parse drop reasons\n");
//	    goto cleanup;
//    }
	print_drop_reasons();

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Successfully started! Monitoring skb:free_skb events...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            printf("Polling interrupted, exiting...\n");
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    skb_kfree_skb_no_reason_bpf__destroy(skel);
    return -err;
}