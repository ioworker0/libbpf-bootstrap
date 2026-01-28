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
#include "egress_filter.skel.h"

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

int main(int argc, char **argv)
{
	struct egress_filter_bpf *skel;
	int err;
	int ifindex;
	char *ifname;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
		fprintf(stderr, "Example: %s calife61cb86319\n", argv[0]);
		return 1;
	}

	ifname = argv[1];
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
		return 1;
	}

	printf("Interface: %s (ifindex: %d)\n", ifname, ifindex);

	libbpf_set_print(libbpf_print_fn);

	// 尝试使用自定义 BTF 路径（参考 captrace）
	const char *btf_path = "/plux/btf/kernel.btf";
	
	if (access(btf_path, R_OK) == 0) {
		printf("Found custom BTF at %s, using it.\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = egress_filter_bpf__open_opts(&opts);
	} else {
		printf("Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
		skel = egress_filter_bpf__open();
	}
	
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// 加载 BPF 程序
	err = egress_filter_bpf__load(skel);
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

	// 设置 TC opts，优先级设为 1（确保在 Calico 之前执行）
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
			    .handle = 1,
			    .priority = 1,  // 优先级 1，小于 Calico 的 49151
			    .prog_fd = bpf_program__fd(skel->progs.egress_firewall));

	// Attach 程序到 TC egress
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC program: %d\n", err);
		goto cleanup;
	}

	printf("Successfully attached egress filter to %s (priority: %d)\n", ifname, tc_opts.priority);
	printf("Blocking egress traffic from IP: 111.63.65.103\n");
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
	egress_filter_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
