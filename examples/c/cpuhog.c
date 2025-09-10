// 这个采集有问题
//
//监控 CPU 4 (持续时间 > 5 ms)...
//TIME     COMM            PID     EVENT
//812:16:43 进程 'skynet-log-agen' (PID 4305  ) 在 CPU 上被连续中断超过 921.146 ms
//    #0  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #1  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #2  [<ffffffff8b671bcf>] handle_irq_event+0xaf
//    #3  [<ffffffff8b680ab0>] handle_edge_irq+0x2e0
//    #4  [<ffffffff8b3a12c0>] __common_interrupt+0x60
//    #5  [<ffffffff8da7e2a7>] common_interrupt+0x47
//    #6  [<ffffffff8b0015eb>] asm_common_interrupt+0x2b
//
//12:16:43 进程 'skynet-log-agen' (PID 4305  ) 在 CPU 上被连续中断超过 922.677 ms
//    #0  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #1  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #2  [<ffffffff8b671bcf>] handle_irq_event+0xaf
//    #3  [<ffffffff8b680ab0>] handle_edge_irq+0x2e0
//    #4  [<ffffffff8b3a12c0>] __common_interrupt+0x60
//    #5  [<ffffffff8da7e2ec>] common_interrupt+0x8c
//    #6  [<ffffffff8b0015eb>] asm_common_interrupt+0x2b
//    #7  [<ffffffff8d168fc0>] sk_stream_wait_close+0x0
//    #8  [<ffffffff8d4adc78>] tcp_close+0x28
//    #9  [<ffffffff8d5b30ab>] inet_release+0x10b
//    #10 [<ffffffff8d0fb30f>] __sock_release+0xaf
//    #11 [<ffffffff8d0fb4d9>] sock_close+0x19
//    #12 [<ffffffff8bf0c07b>] __fput+0x36b
//    #13 [<ffffffff8bf0d2eb>] fput_close_sync+0xdb
//    #14 [<ffffffff8bef2854>] __x64_sys_close+0x84
//    #15 [<ffffffff8b2e0e82>] x64_sys_call+0x14c2
//    #16 [<ffffffff8da7c276>] do_syscall_64+0x66
//    #17 [<ffffffff8b00012f>] entry_SYSCALL_64_after_hwframe+0x76
//
//12:16:59 进程 'skynet-log-agen' (PID 4305  ) 在 CPU 上被连续中断超过 5.050 ms
//    #0  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #1  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #2  [<ffffffff8b671bcf>] handle_irq_event+0xaf
//    #3  [<ffffffff8b680ab0>] handle_edge_irq+0x2e0
//    #4  [<ffffffff8b3a12c0>] __common_interrupt+0x60
//    #5  [<ffffffff8da7e2a7>] common_interrupt+0x47
//    #6  [<ffffffff8b0015eb>] asm_common_interrupt+0x2b
//
//12:17:03 进程 'skynet-log-agen' (PID 4305  ) 在 CPU 上被连续中断超过 4302.497 ms
//    #0  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #1  [<ffffffff8b671926>] __handle_irq_event_percpu+0x256
//    #2  [<ffffffff8b671bcf>] handle_irq_event+0xaf
//    #3  [<ffffffff8b680ab0>] handle_edge_irq+0x2e0
//    #4  [<ffffffff8b3a12c0>] __common_interrupt+0x60
//    #5  [<ffffffff8da7e2ec>] common_interrupt+0x8c
//    #6  [<ffffffff8b0015eb>] asm_common_interrupt+0x2b
//    #7  [<ffffffff8b714760>] __usecs_to_jiffies+0x0
//    #8  [<ffffffff8d509702>] tcp_write_xmit+0x1532
//    #9  [<ffffffff8d50bf8b>] __tcp_push_pending_frames+0x9b
//    #10 [<ffffffff8d50fde9>] tcp_send_fin+0x119
//    #11 [<ffffffff8d4ad6de>] __tcp_close+0x7ee
//    #12 [<ffffffff8d4adc78>] tcp_close+0x28
//    #13 [<ffffffff8d5b30ab>] inet_release+0x10b
//    #14 [<ffffffff8d0fb30f>] __sock_release+0xaf
//    #15 [<ffffffff8d0fb4d9>] sock_close+0x19
//    #16 [<ffffffff8bf0c07b>] __fput+0x36b
//    #17 [<ffffffff8bf0d2eb>] fput_close_sync+0xdb
//    #18 [<ffffffff8bef2854>] __x64_sys_close+0x84
//    #19 [<ffffffff8b2e0e82>] x64_sys_call+0x14c2
//    #20 [<ffffffff8da7c276>] do_syscall_64+0x66
//    #21 [<ffffffff8b00012f>] entry_SYSCALL_64_after_hwframe+0x76
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <inttypes.h>
#include "cpuhog.skel.h"

#define MAX_STACK_DEPTH 127

/* --- 数据结构定义 --- */
#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
	int kernel_stack_id;
};

/* --- 内核符号解析 --- */
#define MAX_SYMBOLS	    250000
#define MAX_SYMBOL_NAME_LEN 64
struct kernel_symbol {
	uint64_t addr;
	char name[MAX_SYMBOL_NAME_LEN];
};
static struct kernel_symbol *symbols = NULL;
static int symbol_count = 0;

static int load_kernel_symbols()
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) {
		perror("错误: 无法打开 /proc/kallsyms");
		return -1;
	}
	symbols = malloc(MAX_SYMBOLS * sizeof(struct kernel_symbol));
	if (!symbols) {
		fprintf(stderr, "错误: 无法为符号分配内存\n");
		fclose(f);
		return -1;
	}

	while (fscanf(f, "%" PRIx64 " %*c %s\n", &symbols[symbol_count].addr, symbols[symbol_count].name) == 2) {
		symbol_count++;
		if (symbol_count >= MAX_SYMBOLS) break;
	}
	fclose(f);
	printf("信息: 已加载 %d 个内核符号。\n", symbol_count);
	return 0;
}

static const char *resolve_kernel_symbol(uint64_t addr)
{
	static char symbol_str[MAX_SYMBOL_NAME_LEN + 32];
	if (symbol_count == 0) return "[kallsyms not loaded]";
	int left = 0, right = symbol_count - 1, match_index = -1;

	while (left <= right) {
		int mid = left + (right - left) / 2;
		if (symbols[mid].addr <= addr) {
			match_index = mid;
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	if (match_index != -1) {
		snprintf(symbol_str, sizeof(symbol_str), "%s+0x%lx", symbols[match_index].name, (unsigned long)(addr - symbols[match_index].addr));
		return symbol_str;
	}
	return "[unresolved]";
}

/* --- 命令行参数定义 --- */
static struct env {
	int cpu;
	long duration_ms;
	bool verbose;
} env = {
	.cpu = -1,
	.duration_ms = 5,
};

static const char doc[] = "监控指定 CPU，当同一个进程持续被中断超过一定时长时触发，可能表明其'霸占'了CPU。\n";
static const struct argp_option opts[] = {
	{ "cpu", 'c', "CPU", 0, "要监控的特定 CPU ID", 0 },
	{ "duration", 'd', "DURATION_MS", 0, "触发警报所需的最短持续时间 (毫秒)", 0 },
	{ "verbose", 'v', NULL, 0, "详细调试输出", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'c': env.cpu = strtol(arg, NULL, 10); break;
	case 'd': env.duration_ms = strtol(arg, NULL, 10); break;
	case ARGP_KEY_ARG: argp_usage(state); break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* --- libbpf & 信号处理 --- */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

/* --- 堆栈打印函数 --- */
static void print_stack(struct cpuhog_bpf *skel, int stack_id)
{
	if (stack_id < 0) return;

	const int stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
	uint64_t ips[MAX_STACK_DEPTH] = {};
	int i;

	if (bpf_map_lookup_elem(stack_map_fd, &stack_id, ips) != 0) {
		fprintf(stderr, "    错误: 未找到堆栈 ID %d\n", stack_id);
		return;
	}

	for (i = 0; i < MAX_STACK_DEPTH && ips[i]; i++) {
		printf("    #%-2d [<%016" PRIx64 ">] %s\n", i, ips[i], resolve_kernel_symbol(ips[i]));
	}
}

/* --- Ring Buffer 事件处理 --- */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct cpuhog_bpf *skel = ctx;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s 进程 '%-15s' (PID %-6d) 在 CPU 上被连续中断超过 %.3f ms\n",
		   ts, e->comm, e->pid, (double)e->total_ns / 1000000);

	print_stack(skel, e->kernel_stack_id);
	printf("\n");
	return 0;
}

/* --- 主函数 --- */
int main(int argc, char **argv)
{
	const char *btf_path = "/tmp/vmlinux.btf";
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	struct ring_buffer *rb = NULL;
	struct cpuhog_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	libbpf_set_print(libbpf_print_fn);

	if (load_kernel_symbols() != 0) {
		fprintf(stderr, "警告: 无法加载内核符号。堆栈将只显示地址。\n");
	}

	if (access(btf_path, R_OK) == 0) {
		printf("信息: 找到自定义 BTF 文件 %s, 将使用它。\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = cpuhog_bpf__open_opts(&opts);
	} else {
		skel = cpuhog_bpf__open();
	}
	if (!skel) {
		fprintf(stderr, "错误: 打开 BPF 骨架失败\n");
		goto cleanup;
	}

	skel->rodata->min_duration_ns = env.duration_ms * 1000000;
	skel->rodata->target_cpu = env.cpu;

	err = cpuhog_bpf__load(skel);
	if (err) {
		fprintf(stderr, "错误: 加载 BPF 骨架失败: %s\n", strerror(errno));
		goto cleanup;
	}

	err = cpuhog_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "错误: 附加 BPF 骨架失败\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "错误: 创建 Ring Buffer 失败\n");
		goto cleanup;
	}

	if (env.cpu != -1) {
		printf("监控 CPU %d (持续时间 > %ld ms)...\n", env.cpu, env.duration_ms);
	} else {
		printf("监控所有 CPU (持续时间 > %ld ms)...\n", env.duration_ms);
	}
	printf("%-8s %-15s %-7s %s\n", "TIME", "COMM", "PID", "EVENT");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("错误: 轮询 Ring Buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	cpuhog_bpf__destroy(skel);
	free(symbols);
	return err < 0 ? -err : 0;
}