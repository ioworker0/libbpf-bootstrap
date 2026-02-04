// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include "tcpktcap.skel.h"
#include "plux/init.h"
#include "plux/btf.h"
#include "plux/user_watchdog.h"
#include "plux/tc.h"

#define CAPTURE_LEN 1600   // veth MTU 默认 1500 + 以太网头 14 + VLAN 8 = 1522，1600 有余量
#define MAX_PRINT_LEN 1600  // 最多打印 1600 字节

struct packet_event {
	__u16 data_len;
	__u8  data[CAPTURE_LEN];
};

static int handle_packet(void *ctx, void *data, size_t len);
static void print_hex_dump(const __u8 *data, __u16 len);

int main(int argc, char **argv)
{
	struct tcpktcap_bpf *skel;
	struct ring_buffer *rb;
	int ifindex, err;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
		fprintf(stderr, "Example: %s eth0\n", argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Invalid interface: %s\n", argv[1]);
		return 1;
	}

	// STEP 1: 初始化 BPF 运行环境（设置 RLIMIT_MEMLOCK + 信号处理）
	plux_init();

	// STEP 2: 打开 BPF skeleton（加载前获取 CO-RE reloc info）
	skel = PLUX_BTF_TRY_OPEN_BEFORE_LOAD(skel, tcpktcap);
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// STEP 3: 配置过滤参数（必须在 load 之前设置）
	skel->rodata->filter_ip = 0;         // 0 = 不过滤 IP
	skel->rodata->filter_port = 0;       // 0 = 不过滤端口
	skel->rodata->filter_mode = 0;       // 0=AND, 1=OR

	// STEP 4: 配置 RateLimit（必须在 load 之前设置）
	skel->rodata->__bpf_ratelimit_interval = 1;
	skel->rodata->__bpf_ratelimit_burst = 100;
	fprintf(stderr, "RateLimit configured: interval=1 s, burst=100 pkts/s\n");

	// STEP 5: 加载 BPF 程序到内核
	err = tcpktcap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	fprintf(stderr, "BPF program loaded\n");

	// STEP 6: 启动 watchdog 线程（用户态挂掉时自动放行流量）
	err = plux_watchdog_start(bpf_map__fd(skel->maps.__plux_watchdog), 1);
	if (err) {
		fprintf(stderr, "Failed to start watchdog thread\n");
		goto cleanup;
	}

	// STEP 7: 创建 TC Ingress qdisc
	err = plux_tc_hook_create(ifindex, BPF_TC_INGRESS);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC ingress hook: %d\n", err);
		goto cleanup;
	}

	// STEP 8: 清理旧的 ingress filter
	fprintf(stderr, "Cleaning up old ingress filter at priority %d...\n", PLUX_PKTCAP_PRIORITY);
	plux_tc_cleanup(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

	// STEP 9: Attach BPF 程序到 TC Ingress
	err = plux_tc_attach_prog(ifindex, BPF_TC_INGRESS,
				  bpf_program__fd(skel->progs.plux_tcp_packet_capture),
				  PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	if (err)
		goto cleanup_detach;

	// STEP 10: 创建 TC Egress qdisc
	err = plux_tc_hook_create(ifindex, BPF_TC_EGRESS);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC egress hook: %d\n", err);
		goto cleanup_detach;
	}

	// STEP 11: 清理旧的 egress filter
	fprintf(stderr, "Cleaning up old egress filter at priority %d...\n", PLUX_PKTCAP_PRIORITY);
	plux_tc_cleanup(ifindex, BPF_TC_EGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

	// STEP 12: Attach BPF 程序到 TC Egress
	err = plux_tc_attach_prog(ifindex, BPF_TC_EGRESS,
				  bpf_program__fd(skel->progs.plux_tcp_packet_capture),
				  PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	if (err)
		goto cleanup_detach;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.packets), handle_packet, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_detach;
	}

	printf("\n");
	printf("=======================================================\n");
	printf("Capturing packets on %s (up to %d bytes per packet)\n", argv[1], CAPTURE_LEN);
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n");

	while (!plux_signal_should_exit()) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	printf("\n\nDetaching...\n");

cleanup_detach:
	// Detach TC filters
	plux_tc_detach(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	plux_tc_detach(ifindex, BPF_TC_EGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

cleanup:
	ring_buffer__free(rb);
	tcpktcap_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}

static void print_hex_dump(const __u8 *data, __u16 len)
{
	for (int i = 0; i < len; i += 16) {
		printf("  0x%04x:  ", i);

		for (int j = 0; j < 16; j++) {
			if (i + j < len)
				printf("%02x ", data[i + j]);
			else
				printf("   ");
			if (j == 7)
				printf(" ");
		}

		printf(" |");

		for (int j = 0; j < 16 && i + j < len; j++) {
			char c = data[i + j];
			printf("%c", isprint(c) ? c : '.');
		}

		printf("|\n");
	}
}

static int handle_packet(void *ctx, void *data, size_t len)
{
	struct packet_event *pkt = data;

	printf("\nlen=%u\n", pkt->data_len);
	print_hex_dump(pkt->data, pkt->data_len > MAX_PRINT_LEN ? MAX_PRINT_LEN : pkt->data_len);

	return 0;
}
