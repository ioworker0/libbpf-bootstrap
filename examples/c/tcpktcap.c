// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include "tcpktcap.skel.h"
#include "plux/init.h"
#include "plux/btf.h"
#include "plux/user_watchdog.h"
#include "plux/tc.h"
#include "socket.h"
#include "config.h"
#include "cJSON.h"

#define CAPTURE_LEN 1600   // veth MTU 默认 1500 + 以太网头 14 + VLAN 8 = 1522，1600 有余量
#define MAX_PRINT_LEN 1600  // 最多打印 1600 字节
#define MAX_SOCKET_PATH 256
#define MAX_INTERFACE_LEN 128

// 配置结构
struct tcpktcap_config {
	char socket_path[MAX_SOCKET_PATH];
	char interface[MAX_INTERFACE_LEN];
	bool ingress;
	bool egress;
	__u32 ratelimit_interval;
	__u32 ratelimit_burst;
	__u32 filter_ip;      // 0 = 不过滤 IP
	__u16 filter_port;    // 0 = 不过滤端口
	__u8 filter_mode;     // 0=AND(全部匹配), 1=OR(任一匹配)
};

// 全局配置
static struct tcpktcap_config g_config = {
	.ingress = true,
	.egress = true,
	.ratelimit_interval = 1,
	.ratelimit_burst = 100,
	.filter_ip = 0,
	.filter_port = 0,
	.filter_mode = 0,
};

struct packet_event {
	__u32 data_len;
	// 5元组信息（固定位置）
	__u32 src_ip;             // 源IP地址（网络字节序）
	__u32 dst_ip;             // 目标IP地址（网络字节序）
	__u16 src_port;           // 源端口（主机字节序）
	__u16 dst_port;           // 目标端口（主机字节序）
	__u8  protocol;           // 协议（IPPROTO_TCP = 6）
	__u8  reserved[3];        // 对齐保留字段
	__u8  data[CAPTURE_LEN];
};

static int handle_packet_print(void *ctx, void *data, size_t len);
static int handle_packet_socket(void *ctx, void *data, size_t len);
static void print_hex_dump(const __u8 *data, __u16 len);
static int parse_tcpktcap_config_args(int argc, char *argv[], struct tcpktcap_config *config);

static ring_buffer_sample_fn g_handle_packet;

// Socket 连接（Agent 模式）
static struct socket_protocol g_socket;

int main(int argc, char **argv)
{
	struct tcpktcap_bpf *skel;
	struct ring_buffer *rb;
	int ifindex, err;

	// 解析配置参数
	err = parse_tcpktcap_config_args(argc, argv, &g_config);
	if (err) {
		return 1;
	}

	// 根据 socket_path 设置 packet 处理函数
	if (g_config.socket_path[0] != '\0') {
		g_handle_packet = handle_packet_socket;

		err = plux_agent_socket_init(&g_socket, g_config.socket_path, "plux-tcpktcap");
		if (err) {
			return 1;
		}

		fprintf(stderr, "Agent mode: sending packets to socket\n");
	} else {
		g_handle_packet = handle_packet_print;
		fprintf(stderr, "Standalone mode: printing packets\n");
	}

	// 确定要使用的 interface（必须从 config 中获取）
	if (g_config.interface[0] == '\0') {
		fprintf(stderr, "Error: interface must be specified in config\n");
		return 1;
	}

	ifindex = if_nametoindex(g_config.interface);
	if (!ifindex) {
		fprintf(stderr, "Invalid interface: %s\n", g_config.interface);
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
	skel->rodata->filter_ip = g_config.filter_ip;         // 0 = 不过滤 IP
	skel->rodata->filter_port = g_config.filter_port;     // 0 = 不过滤端口
	skel->rodata->filter_mode = g_config.filter_mode;     // 0=AND, 1=OR

	// STEP 4: 配置 RateLimit（必须在 load 之前设置）
	skel->rodata->__bpf_ratelimit_interval = g_config.ratelimit_interval;
	skel->rodata->__bpf_ratelimit_burst = g_config.ratelimit_burst;
	fprintf(stderr, "RateLimit configured: interval=%u s, burst=%u pkts/s\n",
		g_config.ratelimit_interval, g_config.ratelimit_burst);

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
	if (g_config.ingress) {
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
	}

	// STEP 10: 创建 TC Egress qdisc
	if (g_config.egress) {
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
	}

	// 检查是否至少有一个方向启用
	if (!g_config.ingress && !g_config.egress) {
		fprintf(stderr, "Error: Neither ingress nor egress is enabled\n");
		goto cleanup_detach;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.packets), g_handle_packet, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_detach;
	}

	printf("\n");
	printf("=======================================================\n");
	printf("Capturing packets on %s (up to %d bytes per packet)\n", g_config.interface, CAPTURE_LEN);
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
	// Detach TC filters (only detach what we attached)
	if (g_config.ingress)
		plux_tc_detach(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	if (g_config.egress)
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

static int handle_packet_print(void *ctx, void *data, size_t len)
{
	struct packet_event *pkt = data;
	struct in_addr src_addr = { .s_addr = pkt->src_ip };
	struct in_addr dst_addr = { .s_addr = pkt->dst_ip };

	printf("\n5-tuple: %s:%u -> %s:%u [proto=%u] len=%u\n",
	       inet_ntoa(src_addr), pkt->src_port,
	       inet_ntoa(dst_addr), pkt->dst_port,
	       pkt->protocol, pkt->data_len);
	print_hex_dump(pkt->data, pkt->data_len > MAX_PRINT_LEN ? MAX_PRINT_LEN : pkt->data_len);

	return 0;
}

static int handle_packet_socket(void *ctx, void *data, size_t len)
{
	struct packet_event *pkt = data;

	// 发送带5元组信息的 packet_event 到 socket
	// 注意：packet_event 和 packet_data 结构不再相同，需要适配
	if (socket_send_packet(&g_socket, (struct packet_data *)pkt) < 0) {
		fprintf(stderr, "Failed to send packet to socket\n");
		return -1;
	}

	return 0;
}

// 解析命令行参数 --config "json_string"
static int parse_tcpktcap_config_args(int argc, char *argv[], struct tcpktcap_config *config)
{
	const char *config_str = NULL;
	cJSON *json = NULL;
	cJSON *item = NULL;

	if (argc > 1)
		fprintf(stderr, "%s: Parsing config arguments...\n", argv[1]);

	if (argc > 2)
		fprintf(stderr, "%s: Parsing config arguments...\n", argv[2]);

	if (!config)
		return -1;

	// 查找 --config 参数
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
			config_str = argv[i + 1];
			break;
		}
	}

	if (!config_str) {
		fprintf(stderr, "Error: --config argument is required\n");
		fprintf(stderr, "Usage: %s --config '{\"interface\":\"eth0\"}'\n", argv[0]);
		return -1;
	}

	// 解析 JSON
	json = cJSON_Parse(config_str);
	if (!json) {
		const char *error_ptr = cJSON_GetErrorPtr();
		fprintf(stderr, "Failed to parse JSON config: %s\n", config_str);
		if (error_ptr)
			fprintf(stderr, "JSON error before: %s\n", error_ptr);
		return -1;
	}

	// 解析 socket_path
	item = cJSON_GetObjectItem(json, "socket_path");
	if (item && cJSON_IsString(item) && item->valuestring) {
		strncpy(config->socket_path, item->valuestring, sizeof(config->socket_path) - 1);
		config->socket_path[sizeof(config->socket_path) - 1] = '\0';
	}

	// 解析 interface
	item = cJSON_GetObjectItem(json, "interface");
	if (item && cJSON_IsString(item) && item->valuestring) {
		strncpy(config->interface, item->valuestring, sizeof(config->interface) - 1);
		config->interface[sizeof(config->interface) - 1] = '\0';
	}

	// 解析 ingress
	item = cJSON_GetObjectItem(json, "ingress");
	if (item && cJSON_IsTrue(item)) {
		config->ingress = true;
	} else if (item && cJSON_IsFalse(item)) {
		config->ingress = false;
	}

	// 解析 egress
	item = cJSON_GetObjectItem(json, "egress");
	if (item && cJSON_IsTrue(item)) {
		config->egress = true;
	} else if (item && cJSON_IsFalse(item)) {
		config->egress = false;
	}

	// 解析 ratelimit_interval
	item = cJSON_GetObjectItem(json, "ratelimit_interval");
	if (item && cJSON_IsNumber(item)) {
		config->ratelimit_interval = (__u32)item->valuedouble;
	}

	// 解析 ratelimit_burst
	item = cJSON_GetObjectItem(json, "ratelimit_burst");
	if (item && cJSON_IsNumber(item)) {
		config->ratelimit_burst = (__u32)item->valuedouble;
	}

	// 解析 filter_ip
	item = cJSON_GetObjectItem(json, "filter_ip");
	if (item && cJSON_IsNumber(item)) {
		config->filter_ip = (__u32)item->valuedouble;
	}

	// 解析 filter_port
	item = cJSON_GetObjectItem(json, "filter_port");
	if (item && cJSON_IsNumber(item)) {
		config->filter_port = (__u16)item->valuedouble;
	}

	// 解析 filter_mode
	item = cJSON_GetObjectItem(json, "filter_mode");
	if (item && cJSON_IsNumber(item)) {
		config->filter_mode = (__u8)item->valuedouble;
	}

	cJSON_Delete(json);

	// 打印解析后的配置
	fprintf(stderr, "Config parsed:\n");
	fprintf(stderr, "  interface: %s\n", config->interface);
	fprintf(stderr, "  socket_path: %s\n", config->socket_path);
	fprintf(stderr, "  ingress: %s\n", config->ingress ? "true" : "false");
	fprintf(stderr, "  egress: %s\n", config->egress ? "true" : "false");
	fprintf(stderr, "  ratelimit_interval: %u\n", config->ratelimit_interval);
	fprintf(stderr, "  ratelimit_burst: %u\n", config->ratelimit_burst);
	fprintf(stderr, "  filter_ip: 0x%x\n", config->filter_ip);
	fprintf(stderr, "  filter_port: %u\n", config->filter_port);
	fprintf(stderr, "  filter_mode: %u (0=AND, 1=OR)\n", config->filter_mode);

	return 0;
}
