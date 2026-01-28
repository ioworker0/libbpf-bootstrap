// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
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

	// 设置 TC hook (egress)
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
			    .ifindex = ifindex,
			    .attach_point = BPF_TC_EGRESS);

	// 创建 qdisc (如果不存在)
	err = bpf_tc_hook_create(&tc_hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	if (err == -EEXIST) {
		printf("TC qdisc already exists\n");
	}

	// 设置 TC opts，优先级设为 3（在 pktcap 之后，在其他规则之前）
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
			    .handle = 1,
			    .priority = 3,
			    .prog_fd = bpf_program__fd(skel->progs.dscp_marker));

	// Attach 程序到 TC egress
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC program: %d\n", err);
		goto cleanup;
	}

	printf("Successfully attached DSCP marker to %s (priority: 3)\n", ifname);
	printf("Marking ALL egress traffic with DSCP: 0x%02x\n", dscp_value);
	printf("Press Ctrl+C to detach and exit...\n");
	printf("\nYou can verify with: tc filter show dev %s egress\n", ifname);
	printf("To see logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

	// 注册信号处理
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	// 主循环
	while (!exiting) {
		sleep(1);
	}

	printf("\nDetaching program...\n");

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
