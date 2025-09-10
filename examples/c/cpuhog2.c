//
// docker run -it --rm --network=host --privileged -v $(pwd):$(pwd) --hostname libbpf-bootstrap --pid=host -v /lib/modules/:/lib/modules/ -v /usr/src/:/usr/src/ -v /sys/kernel/debug:/sys/kernel/debug hub.17usoft.com/mingzhe.yang/imagedong/nettrace-build:build-25-07-26 sh -c  "cd /tmp1/libbpf-bootstrap/examples/c && ls && rm -rf .output/cpuhog* && rm -rf cpuhog && make cpuhog && ./cpuhog -s -c 4 -d 10 -F 1000"
// 效果不佳
//11:27:14 进程 'pstree         ' (PID 3233365) 在 CPU 上持续运行超过 10.000 ms (采样 10 次)
//    #0  [<ffffffff8b4550f9>] __unwind_start+0x29
//    #1  [<ffffffff8b3d52cb>] arch_stack_walk+0x6b
//    #2  [<ffffffff8b713bf6>] stack_trace_save+0x96
//    #3  [<ffffffff8be3b17f>] kasan_save_stack+0x2f
//    #4  [<ffffffff8be3b1f8>] kasan_save_track+0x18
//    #5  [<ffffffff8be3e4bb>] kasan_save_alloc_info+0x3b
//    #6  [<ffffffff8be3b686>] __kasan_slab_alloc+0x76
//    #7  [<ffffffff8bda7fb0>] kmem_cache_alloc_noprof+0x120
//    #8  [<ffffffff8bf3258f>] getname_flags.part.0+0x4f
//    #9  [<ffffffff8bf49fe1>] getname_flags+0x81
//    #10 [<ffffffff8bf1da5e>] __do_sys_newstat+0x7e
//    #11 [<ffffffff8bf1db48>] __x64_sys_newstat+0x58
//    #12 [<ffffffff8b2e0a37>] x64_sys_call+0x1077
//    #13 [<ffffffff8da7c276>] do_syscall_64+0x66
//    #14 [<ffffffff8b00012f>] entry_SYSCALL_64_after_hwframe+0x76
//
//11:27:14 进程 'pstree         ' (PID 3233365) 在 CPU 上持续运行超过 10.000 ms (采样 10 次)
//    #0  [<ffffffff8be3de60>] kasan_check_range+0x40
//    #1  [<ffffffff8be3ecb8>] __kasan_check_write+0x18
//    #2  [<ffffffff8da27b59>] mt_validate+0x449
//    #3  [<ffffffff8bd5f8f9>] validate_mm+0xb9
//    #4  [<ffffffff8bd624a0>] vms_complete_munmap_vmas+0x540
//    #5  [<ffffffff8bd64720>] do_vmi_align_munmap+0x390
//    #6  [<ffffffff8bd64a1d>] do_vmi_munmap+0x15d
//    #7  [<ffffffff8bd6de0e>] __vm_munmap+0x17e
//    #8  [<ffffffff8bcfc2bd>] __x64_sys_munmap+0x5d
//    #9  [<ffffffff8b2e1019>] x64_sys_call+0x1659
//    #10 [<ffffffff8da7c276>] do_syscall_64+0x66
//    #11 [<ffffffff8b00012f>] entry_SYSCALL_64_after_hwframe+0x76
//
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
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "cpuhog.skel.h"

#define MAX_STACK_DEPTH 127

/* --- 数据结构定义 --- */
#define TASK_COMM_LEN 16

struct event {
	__u32 pid;
	__u32 count;
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
	int freq;
	bool strict;
	bool verbose;
} env = {
	.cpu = -1,
	.duration_ms = 5,
	.freq = 999,
	.strict = false,
};

static const char doc[] = "以固定频率在 CPU 上采样，当同一个进程持续运行时长超过阈值则触发。\n";
static const struct argp_option opts[] = {
	{ "cpu", 'c', "CPU", 0, "要监控的特定 CPU ID", 0 },
	{ "duration", 'd', "DURATION_MS", 0, "触发警报所需的最短持续时间 (毫秒)", 0 },
	{ "frequency", 'F', "HZ", 0, "采样频率 (Hz)", 0 },
	{ "strict", 's', NULL, 0, "启用严格模式 (通过 sched_switch 检查连续性)", 0 },
	{ "verbose", 'v', NULL, 0, "详细调试输出", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'c': env.cpu = strtol(arg, NULL, 10); break;
	case 'd': env.duration_ms = strtol(arg, NULL, 10); break;
	case 'F': env.freq = strtol(arg, NULL, 10); break;
	case 's': env.strict = true; break;
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

/* --- 全局变量和 perf_event 打开函数 --- */
static int *pmu_fds = NULL;
static int num_cpus = 0;

static long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int open_and_attach_perf_event(int freq, struct cpuhog_bpf *skel)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_freq = freq,
		.freq = 1,
	};
	int i;

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus < 0) {
		fprintf(stderr, "错误: 获取 CPU 数量失败: %s\n", strerror(-num_cpus));
		return -1;
	}

	pmu_fds = malloc(num_cpus * sizeof(int));
	if (!pmu_fds) {
		fprintf(stderr, "错误: 无法为 PMU fds 分配内存\n");
		return -1;
	}
	for (i = 0; i < num_cpus; i++) {
		pmu_fds[i] = -1;
	}

	for (i = 0; i < num_cpus; i++) {
		if (skel->rodata->target_cpu != -1 && i != skel->rodata->target_cpu) {
			continue;
		}

		pmu_fds[i] = perf_event_open(&attr, -1, i, -1, PERF_FLAG_FD_CLOEXEC);
		if (pmu_fds[i] < 0) {
			fprintf(stderr, "错误: CPU %d 的 perf_event_open 失败: %s\n", i, strerror(errno));
			return -1;
		}
		skel->links.on_cpu_sample = bpf_program__attach_perf_event(skel->progs.on_cpu_sample, pmu_fds[i]);
		if (!skel->links.on_cpu_sample) {
			fprintf(stderr, "错误: CPU %d 的 bpf_program__attach_perf_event 失败: %s\n", i, strerror(errno));
			return -1;
		}
	}

	return 0;
}

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

	double duration_ms = (double)e->count * 1000.0 / env.freq;

	printf("%-8s 进程 '%-15s' (PID %-6d) 在 CPU 上持续运行超过 %.3f ms (采样 %u 次)\n",
		   ts, e->comm, e->pid, duration_ms, e->count);

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
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	if (env.freq <= 0) {
		fprintf(stderr, "错误: 无效的频率: %d\n", env.freq);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	if (load_kernel_symbols() != 0) {
		fprintf(stderr, "警告: 无法加载内核符号. 堆栈将只显示地址。\n");
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

	if (env.duration_ms > 0) {
		skel->rodata->min_count = (unsigned long long)env.duration_ms * env.freq / 1000;
		if (skel->rodata->min_count == 0) skel->rodata->min_count = 1;
	}
	skel->rodata->target_cpu = env.cpu;
	skel->rodata->strict_mode = env.strict;

	// 如果不处于严格模式，则不加载 sched_switch 探针以节省资源
	if (!env.strict) {
		bpf_program__set_autoload(skel->progs.handle_sched_switch, false);
	}

	err = cpuhog_bpf__load(skel);
	if (err) {
		fprintf(stderr, "错误: 加载 BPF 骨架失败: %s\n", strerror(errno));
		goto cleanup;
	}

	// 只有在严格模式下才需要附加 sched_switch
	if (env.strict) {
		err = cpuhog_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "错误: 附加 sched_switch 探针失败\n");
			goto cleanup;
		}
	}

	err = open_and_attach_perf_event(env.freq, skel);
	if (err) {
		fprintf(stderr, "错误: 附加 perf event 失败\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "错误: 创建 Ring Buffer 失败\n");
		goto cleanup;
	}

	printf("监控模式: %s\n", env.strict ? "严格 (检查上下文切换)" : "常规 (仅采样)");
	if (env.cpu != -1) {
		printf("在 CPU %d 上以 %dHz 频率采样 (持续时间 > %ld ms)...\n", env.cpu, env.freq, env.duration_ms);
	} else {
		printf("在所有 CPU 上以 %dHz 频率采样 (持续时间 > %ld ms)...\n", env.freq, env.duration_ms);
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
	if (pmu_fds) {
		for (i = 0; i < num_cpus; i++) {
			if (pmu_fds[i] >= 0)
				close(pmu_fds[i]);
		}
		free(pmu_fds);
	}
	ring_buffer__free(rb);
	cpuhog_bpf__destroy(skel);
	free(symbols);
	return err < 0 ? -err : 0;
}