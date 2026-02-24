// SPDX-License-Identifier: GPL-2.0
/*
 * pktfwd.c - 包转发插件用户态程序 (DNAT)
 *
 * 功能：在 egress 方向匹配目的 IP，并转发到目标 IP
 *
 * 用法：pktfwd <interface> <original_ip> <target_ip>
 *   - interface: 网卡名称（veth 宿主机侧）
 *   - original_ip: 需要转发的原始目的 IP
 *   - target_ip: 转发到哪里的目标 IP
 *
 * 例如：pktfwd calixxx 10.96.0.1 10.244.1.5
 *
 * 注意：
 *   - egress 是容器的出口方向
 *   - 对于 veth，宿主机侧的 egress 就是容器发出的包
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pktfwd.skel.h"
#include "plux/init.h"
#include "plux/btf.h"
#include "plux/user_watchdog.h"
#include "plux/tc.h"

// 转发配置结构（与 BPF 端对应）
struct fwd_config {
	__u32 original_ip;  // 需要转发的原始目的 IP (网络字节序)
	__u32 target_ip;    // 转发到哪里的目标 IP (网络字节序)
	__u8  enabled;      // 是否启用
	__u8  _padding[3];
};

// 统计结构（与 BPF 端对应）
struct fwd_stats {
	__u64 total_packets;
	__u64 forwarded_packets;
	__u64 non_ipv4;
	__u64 no_match;
};

static void print_stats(struct fwd_stats *stats)
{
	printf("\r");
	printf("Total: %-8llu Forwarded: %-8llu NoMatch: %-8llu NonIPv4: %-llu    ",
	       stats->total_packets,
	       stats->forwarded_packets,
	       stats->no_match,
	       stats->non_ipv4);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	struct pktfwd_bpf *skel;
	int ifindex, err;
	struct in_addr orig_addr, target_addr;
	struct fwd_config cfg = {0};
	struct fwd_stats stats = {0};
	__u32 key = 0;
	int cfg_fd, stats_fd;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <interface> <original_ip> <target_ip>\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "  interface   - 网卡名称（veth 宿主机侧）\n");
		fprintf(stderr, "  original_ip - 需要转发的原始目的 IP\n");
		fprintf(stderr, "  target_ip   - 转发到哪里的目标 IP\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "Example:\n");
		fprintf(stderr, "  %s calixxx 10.96.0.1 10.244.1.5\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "Note: egress is the container's outbound direction.\n");
		fprintf(stderr, "For veth, the host side egress is packets from the container.\n");
		return 1;
	}

	// 解析网卡
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Invalid interface: %s\n", argv[1]);
		return 1;
	}

	// 解析原始 IP（需要转发的 IP）
	if (inet_pton(AF_INET, argv[2], &orig_addr) != 1) {
		fprintf(stderr, "Invalid original IP: %s\n", argv[2]);
		return 1;
	}

	// 解析目标 IP（转发到哪里的 IP）
	if (inet_pton(AF_INET, argv[3], &target_addr) != 1) {
		fprintf(stderr, "Invalid target IP: %s\n", argv[3]);
		return 1;
	}

	// 设置配置
	cfg.original_ip = orig_addr.s_addr;
	cfg.target_ip = target_addr.s_addr;
	cfg.enabled = 1;

	printf("=======================================================\n");
	printf("Packet Forwarder (DNAT)\n");
	printf("=======================================================\n");
	printf("Interface:    %s (ifindex: %d)\n", argv[1], ifindex);
	printf("Original IP:  %s (will be matched)\n", argv[2]);
	printf("Target IP:    %s (will be forwarded to)\n", argv[3]);
	printf("Direction:    Egress (container outbound)\n");
	printf("=======================================================\n\n");

	// ------------------------------------------------
	// STEP 1: 初始化
	plux_init();

	// STEP 2: 打开 skeleton
	skel = PLUX_BTF_TRY_OPEN_BEFORE_LOAD(skel, pktfwd);
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// STEP 3: 加载 BPF 程序
	err = pktfwd_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "BPF program loaded\n");

	// STEP 4: 获取 map fd
	cfg_fd = bpf_map__fd(skel->maps.fwd_cfg);
	stats_fd = bpf_map__fd(skel->maps.stats);

	if (cfg_fd < 0 || stats_fd < 0) {
		fprintf(stderr, "Failed to get map fd\n");
		goto cleanup;
	}

	// STEP 5: 设置转发配置
	if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY) < 0) {
		fprintf(stderr, "Failed to set forward config\n");
		goto cleanup;
	}

	fprintf(stderr, "Forward config set: %s -> %s\n", argv[2], argv[3]);

	// STEP 6: 启动 watchdog
	err = plux_watchdog_start(bpf_map__fd(skel->maps.__plux_watchdog), 1);
	if (err) {
		fprintf(stderr, "Failed to start watchdog thread\n");
		goto cleanup;
	}

	// ================================================================
	// STEP 7: TC Egress
	// ================================================================
	// 对于 veth，宿主机侧的 egress 就是容器发出的包
	err = plux_tc_hook_create(ifindex, BPF_TC_EGRESS);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC egress hook: %d\n", err);
		goto cleanup;
	}

	// 清理旧的 filter
	fprintf(stderr, "Cleaning up old egress filter at priority %d...\n", PLUX_PKTFWD_PRIORITY);
	plux_tc_cleanup(ifindex, BPF_TC_EGRESS, PLUX_PKTFWD_PRIORITY, PLUX_PKTFWD_HANDLE);

	// 挂载 BPF 程序
	err = plux_tc_attach_prog(ifindex, BPF_TC_EGRESS,
				  bpf_program__fd(skel->progs.plux_packet_forward),
				  PLUX_PKTFWD_PRIORITY, PLUX_PKTFWD_HANDLE);
	if (err) {
		goto cleanup_detach;
	}

	printf("\n");
	printf("Packet forwarding started on %s (egress)\n", argv[1]);
	printf("DNAT: %s -> %s\n", argv[2], argv[3]);
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n\n");

	// 主循环：显示统计信息
	while (!plux_signal_should_exit()) {
		// 读取统计信息
		if (bpf_map_lookup_elem(stats_fd, &key, &stats) == 0) {
			print_stats(&stats);
		}

		sleep(1);
	}

	printf("\n\nDetaching...\n");

cleanup_detach:
	// Detach TC filter
	plux_tc_detach(ifindex, BPF_TC_EGRESS, PLUX_PKTFWD_PRIORITY, PLUX_PKTFWD_HANDLE);

cleanup:
	// 显示最终统计
	if (bpf_map_lookup_elem(stats_fd, &key, &stats) == 0) {
		printf("\nFinal Statistics:\n");
		printf("  Total packets:     %llu\n", stats.total_packets);
		printf("  Forwarded packets: %llu\n", stats.forwarded_packets);
		printf("  No match packets:  %llu\n", stats.no_match);
		printf("  Non-IPv4 packets:  %llu\n", stats.non_ipv4);
	}

	pktfwd_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
