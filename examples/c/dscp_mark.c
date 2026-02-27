// SPDX-License-Identifier: GPL-2.0
// 搞不定，暂时放弃
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "dscp_mark.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

// DSCP 值定义
#define DSCP_CS0  0x00
#define DSCP_CS1  0x08
#define DSCP_CS2  0x10
#define DSCP_CS3  0x18
#define DSCP_CS4  0x20
#define DSCP_CS5  0x28
#define DSCP_CS6  0x30
#define DSCP_CS7  0x38
#define DSCP_EF   0x2e
#define DSCP_AF11 0x0a

static void print_usage(const char *prog)
{
	printf("Usage: %s <interface> [dscp_value]\n", prog);
	printf("\nArguments:\n");
	printf("  interface        Network interface (e.g., eth0)\n");
	printf("  dscp_value       DSCP value in hex (default: 0x2e for EF)\n");
	printf("\nCommon DSCP values:\n");
	printf("  0x00 (CS0)  - Default\n");
	printf("  0x08 (CS1)  - Priority 1\n");
	printf("  0x10 (CS2)  - Priority 2\n");
	printf("  0x18 (CS3)  - Priority 3\n");
	printf("  0x20 (CS4)  - Priority 4\n");
	printf("  0x28 (CS5)  - Priority 5\n");
	printf("  0x30 (CS6)  - Priority 6\n");
	printf("  0x2e (EF)   - Expedited Forwarding (highest)\n");
	printf("\nExamples:\n");
	printf("  %s eth0           # Use default DSCP (0x2e - EF)\n", prog);
	printf("  %s eth0 0x20      # Use DSCP CS4 (0x20)\n", prog);
	printf("  %s eth0 0x2e      # Use DSCP EF (0x2e - highest priority)\n", prog);
}

int main(int argc, char **argv)
{
	struct dscp_mark_bpf *skel;
	int err;
	int ifindex;
	char *ifname;
	__u8 dscp_value = DSCP_EF;  // 默认 EF (最高优先级)
	int watchdog_fd;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	ifname = argv[1];
	
	// 解析 DSCP 值（如果提供）
	if (argc >= 3) {
		if (strcmp(argv[2], "--help") == 0 || strcmp(argv[2], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		}
		dscp_value = strtol(argv[2], NULL, 0);
	}
	
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
		return 1;
	}

	printf("Interface: %s (ifindex: %d)\n", ifname, ifindex);
	printf("DSCP value: 0x%02x\n", dscp_value);

	libbpf_set_print(libbpf_print_fn);

	// 尝试使用自定义 BTF 路径
	const char *btf_path = "/plux/btf/kernel.btf";
	
	if (access(btf_path, R_OK) == 0) {
		printf("Found custom BTF at %s, using it.\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = dscp_mark_bpf__open_opts(&opts);
	} else {
		printf("Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
		skel = dscp_mark_bpf__open();
	}
	
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 设置 DSCP 值
	skel->rodata->target_dscp = dscp_value;

	// 加载 BPF 程序
	err = dscp_mark_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("BPF program loaded successfully\n");

	// 获取 watchdog map fd
	watchdog_fd = bpf_map__fd(skel->maps.plux_watchdog);
	if (watchdog_fd < 0) {
		fprintf(stderr, "Failed to get watchdog map fd\n");
		goto cleanup;
	}

	// 设置 TC hook (ingress) - veth 上 ingress 才是容器发出的包
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
			    .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS);

	// 创建 qdisc (如果不存在)
	err = bpf_tc_hook_create(&tc_hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	if (err == -EEXIST) {
		printf("TC qdisc already exists\n");
	}

	// Attach 前清理：删除旧的 plux_dscp_marker 程序（priority 3）
	printf("Cleaning up old filter at priority 3...\n");
	
	// 我们 attach 时固定用了 handle 1，所以这里也直接清理 handle 1
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, old_opts,
			    .handle = 1,
			    .priority = 3,
			    .prog_fd = 0,
			    .prog_id = 0,
			    .flags = 0);
	
	// 先 query 确认一下（可选，但这能拿到 prog_id 打印出来）
	err = bpf_tc_query(&tc_hook, &old_opts);
	if (err == 0) {
		printf("  -> Found old filter (handle=%u, prog_id=%u)\n", 
		       old_opts.handle, old_opts.prog_id);
		
		old_opts.prog_fd = 0;
		old_opts.prog_id = 0;
		old_opts.flags = 0;
		
		err = bpf_tc_detach(&tc_hook, &old_opts);
		if (err == 0) {
			printf("  -> Removed successfully\n");
		} else {
			printf("  -> Failed to remove: %d (continuing anyway)\n", err);
		}
	} else {
		// 如果 query 不到 handle 1，说明可能没有，或者用了其他 handle
		// 无论如何，尝试 detach 一下 handle 1 兜底
		printf("  -> No old filter with handle 1 found (err=%d)\n", err);
		err = bpf_tc_detach(&tc_hook, &old_opts);
		if (err == 0) {
			printf("  -> Detached handle 1 successfully (blind detach)\n");
		} else if (err != -ENOENT) {
			printf("  -> Failed to detach handle 1: %d\n", err);
		}
	}

	// 设置 TC opts，优先级设为 3（在 Calico 49152 之前执行）
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
			    .handle = 1,
			    .priority = 3,
			    .prog_fd = bpf_program__fd(skel->progs.plux_dscp_marker));

	// Attach 程序到 TC ingress
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC program: %d\n", err);
		goto cleanup_detach;
	}

	printf("Successfully attached DSCP marker to %s (priority: 3, before Calico)\n", ifname);
	printf("Marking ALL container egress traffic (veth ingress) with DSCP: 0x%02x\n", dscp_value);
	printf("Press Ctrl+C to detach and exit...\n");
	printf("\nYou can verify with: tc filter show dev %s ingress\n", ifname);
	printf("To see logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

	// 注册信号处理
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup_detach;
	}
	signal(SIGTERM, sig_int);
	signal(SIGHUP, sig_int);

	// 初始化心跳
	__u32 key = 0;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	__u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	if (bpf_map_update_elem(watchdog_fd, &key, &now, BPF_ANY) < 0) {
		fprintf(stderr, "Failed to initialize watchdog: %s\n", strerror(errno));
		goto cleanup_detach;
	}
	printf("Watchdog initialized (timeout: 30s, update interval: 1s)\n");

	// 主循环：每 1 秒更新一次心跳
	while (!exiting) {
		sleep(1);
		
		if (!exiting) {
			// 更新心跳时间戳
			clock_gettime(CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
			if (bpf_map_update_elem(watchdog_fd, &key, &now, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to update watchdog: %s\n", strerror(errno));
				exiting = 1;
				goto cleanup_detach;
			}
		}
	}

	printf("\nDetaching program...\n");

cleanup_detach:
	// Detach 程序
	tc_opts.flags = 0;
	tc_opts.prog_fd = 0;
	tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC program: %d\n", err);
	}

cleanup:
	printf("Cleaning up...\n");
	dscp_mark_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
