// SPDX-License-Identifier: GPL-2.0
/*
 * TCP Packet Capture - libpcap version (不依赖 eBPF)
 * 
 * 使用 libpcap 捕获 TCP 数据包，支持:
 * - IP/端口过滤
 * - 打印模式和 Socket Agent 模式
 * - 用户态速率限制
 * - 5元组提取
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include "socket.h"
#include "protocol.h"
#include "cJSON.h"
#include "plux/signal.h"

// 使用标准类型定义
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;

#define CAPTURE_LEN 1600   // 捕获长度
#define MAX_PRINT_LEN 1600
#define MAX_SOCKET_PATH 256
#define MAX_INTERFACE_LEN 128
#define MAX_FILTER_LEN 512

// 配置结构
struct tcpktcap_pcap_config {
	char socket_path[MAX_SOCKET_PATH];
	char interface[MAX_INTERFACE_LEN];
	bool ingress;                      // 是否捕获入口流量
	bool egress;                       // 是否捕获出口流量
	__u32 ratelimit_interval;      // 速率限制窗口（秒）
	__u32 ratelimit_burst;          // 每窗口允许的包数
	__u32 filter_ip;                // 过滤IP（网络字节序，0=不过滤）
	__u16 filter_port;              // 过滤端口（主机字节序，0=不过滤）
	__u8 filter_mode;               // 0=AND, 1=OR, 2=tuple
};

// 全局配置
static struct tcpktcap_pcap_config g_config = {
	.ingress = true,
	.egress = true,
	.ratelimit_interval = 1,
	.ratelimit_burst = 100,
	.filter_ip = 0,
	.filter_port = 0,
	.filter_mode = 0,
};

// 速率限制状态
static struct {
	time_t window_start;
	__u32 packet_count;
} g_ratelimit = {0};

// Socket 连接（Agent 模式）
static struct socket_protocol g_socket;
static int g_agent_mode = 0;  // 0=打印模式，1=Agent模式

// 函数声明
static int ratelimit_check(void);
static void print_hex_dump(const __u8 *data, __u16 len);
static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void build_bpf_filter(char *filter_buf, size_t buf_size);
static int parse_tcpktcap_pcap_config(int argc, char *argv[]);
static int init_agent_socket(void);

// ============================================================================
// main 函数
// ============================================================================
int main(int argc, char **argv)
{
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[MAX_FILTER_LEN];
	bpf_u_int32 net = 0;
	int err;
	
	// 解析配置
	err = parse_tcpktcap_pcap_config(argc, argv);
	if (err) {
		return 1;
	}
	
	// 设置信号处理
	plux_signal_init();
	
	// 判断工作模式
	if (g_config.socket_path[0] != '\0') {
		g_agent_mode = 1;
		fprintf(stderr, "Agent mode: sending packets to socket\n");
		
		err = init_agent_socket();
		if (err) {
			return 1;
		}
	} else {
		g_agent_mode = 0;
		fprintf(stderr, "Standalone mode: printing packets\n");
	}
	
	// 打开网络接口
	handle = pcap_open_live(g_config.interface, CAPTURE_LEN, 1, 1000, errbuf);
	if (!handle) {
		fprintf(stderr, "Couldn't open device %s: %s\n", g_config.interface, errbuf);
		goto cleanup;
	}

	// 按配置区分 ingress / egress
	if (!g_config.ingress && !g_config.egress) {
		fprintf(stderr, "Error: Neither ingress nor egress is enabled\n");
		goto cleanup;
	}
	if (g_config.ingress && g_config.egress) {
		if (pcap_setdirection(handle, PCAP_D_INOUT) != 0)
			fprintf(stderr, "Warning: pcap_setdirection(INOUT) failed: %s\n", pcap_geterr(handle));
	} else if (g_config.ingress) {
		if (pcap_setdirection(handle, PCAP_D_IN) != 0)
			fprintf(stderr, "Warning: pcap_setdirection(IN) failed: %s\n", pcap_geterr(handle));
	} else {
		if (pcap_setdirection(handle, PCAP_D_OUT) != 0)
			fprintf(stderr, "Warning: pcap_setdirection(OUT) failed: %s\n", pcap_geterr(handle));
	}
	
	// 构建 BPF 过滤表达式
	build_bpf_filter(filter_exp, sizeof(filter_exp));
	fprintf(stderr, "BPF filter: %s\n", filter_exp);
	
	// 编译并应用 BPF 过滤器
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		goto cleanup;
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_freecode(&fp);
		goto cleanup;
	}
	
	pcap_freecode(&fp);
	
	printf("\n");
	printf("=======================================================\n");
	printf("Capturing TCP packets on %s (libpcap mode)\n", g_config.interface);
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n");
	
	// 初始化速率限制
	g_ratelimit.window_start = time(NULL);
	g_ratelimit.packet_count = 0;
	
	// 开始捕获（循环）
	while (!plux_signal_should_exit()) {
		// 使用 pcap_dispatch 而不是 pcap_loop，便于检查退出信号
		int ret = pcap_dispatch(handle, 10, packet_handler, NULL);
		if (ret < 0) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
			break;
		}
	}
	
	printf("\n\nStopping capture...\n");
	
cleanup:
	if (handle) {
		pcap_close(handle);
	}
	
	if (g_agent_mode) {
		socket_stop_heartbeat(&g_socket);
		socket_disconnect(&g_socket);
	}
	
	printf("Done.\n");
	return 0;
}

// ============================================================================
// 函数定义
// ============================================================================

// 速率限制检查（用户态实现）
static int ratelimit_check(void)
{
	// 如果 ratelimit_burst 或 ratelimit_interval 为 0，视为关闭限速
	if (g_config.ratelimit_burst == 0 || g_config.ratelimit_interval == 0)
		return 1;

	time_t now = time(NULL);
	
	// 检查是否需要重置窗口
	if (now >= g_ratelimit.window_start + g_config.ratelimit_interval) {
		g_ratelimit.window_start = now;
		g_ratelimit.packet_count = 0;
	}
	
	// 检查是否超过限制
	if (g_ratelimit.packet_count >= g_config.ratelimit_burst) {
		return 0;  // 超过限制
	}
	
	g_ratelimit.packet_count++;
	return 1;  // 通过
}

// 打印16进制 dump
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

// libpcap 回调函数
static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)user;
	
	// 速率限制检查
	if (!ratelimit_check()) {
		return;  // 超过速率限制，丢弃
	}
	
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	
	// 只处理 IP 包
	if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
		return;
	}
	
	struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
	
	// 只处理 TCP 包
	if (ip_hdr->ip_p != IPPROTO_TCP) {
		return;
	}
	
	// 检查 IP 头部长度
	int ip_hdr_len = ip_hdr->ip_hl * 4;
	if (ip_hdr_len < 20) {
		return;  // 无效的 IP 头部
	}
	
	struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);
	
	// 提取5元组
	__u32 src_ip = ip_hdr->ip_src.s_addr;  // 已经是网络字节序
	__u32 dst_ip = ip_hdr->ip_dst.s_addr;  // 已经是网络字节序
	__u16 src_port = ntohs(tcp_hdr->th_sport);
	__u16 dst_port = ntohs(tcp_hdr->th_dport);
	
	// 应用过滤规则（如果 BPF filter 没有完全覆盖）
	if (g_config.filter_ip != 0 || g_config.filter_port != 0) {
		int ip_match = (g_config.filter_ip == 0) || 
		               (src_ip == g_config.filter_ip || dst_ip == g_config.filter_ip);
		int port_match = (g_config.filter_port == 0) || 
		                 (src_port == g_config.filter_port || dst_port == g_config.filter_port);
		
		// 根据 filter_mode 决定
		switch (g_config.filter_mode) {
		case 0:  // AND: IP 和端口都要匹配
			if (!ip_match || !port_match)
				return;
			break;
		case 1:  // OR: IP 或端口匹配即可
			if (!ip_match && !port_match)
				return;
			break;
		case 2:  // tuple: 源或目的整体匹配
			if (g_config.filter_ip != 0 && g_config.filter_port != 0) {
				int src_tuple_match = (src_ip == g_config.filter_ip && src_port == g_config.filter_port);
				int dst_tuple_match = (dst_ip == g_config.filter_ip && dst_port == g_config.filter_port);
				if (!src_tuple_match && !dst_tuple_match)
					return;
			}
			break;
		}
	}
	
	__u32 data_len = pkthdr->caplen;
	if (data_len > PACKET_CAPTURE_LEN)
		data_len = PACKET_CAPTURE_LEN;
	
	// 根据模式处理
	if (g_agent_mode) {
		// Agent 模式：使用零拷贝版本，直接发送原始 packet 指针
		if (socket_send_packet_zerocopy(&g_socket, src_ip, dst_ip, src_port, dst_port,
		                                 IPPROTO_TCP, packet, data_len) < 0) {
			fprintf(stderr, "Failed to send packet to socket\n");
		}
	} else {
		// 打印模式：直接用原始 packet 指针，避免 memcpy
		struct in_addr src_addr = { .s_addr = src_ip };
		struct in_addr dst_addr = { .s_addr = dst_ip };
		
		printf("\n5-tuple: %s:%u -> %s:%u [proto=%u] len=%u\n",
		       inet_ntoa(src_addr), src_port,
		       inet_ntoa(dst_addr), dst_port,
		       IPPROTO_TCP, data_len);
		
		// 直接打印原始 packet，无需拷贝
		__u32 print_len = data_len > MAX_PRINT_LEN ? MAX_PRINT_LEN : data_len;
		print_hex_dump(packet, print_len);
	}
}

// 构建 BPF 过滤表达式
static void build_bpf_filter(char *filter_buf, size_t buf_size)
{
	int offset = 0;
	
	// 基础过滤：只捕获 TCP
	offset += snprintf(filter_buf + offset, buf_size - offset, "tcp");
	
	// 如果指定了 IP 或端口，添加到 BPF filter（提高效率）
	if (g_config.filter_ip != 0) {
		struct in_addr addr = { .s_addr = g_config.filter_ip };
		offset += snprintf(filter_buf + offset, buf_size - offset, 
		                   " and host %s", inet_ntoa(addr));
	}
	
	if (g_config.filter_port != 0) {
		offset += snprintf(filter_buf + offset, buf_size - offset,
		                   " and port %u", g_config.filter_port);
	}
}

// 解析配置参数
static int parse_tcpktcap_pcap_config(int argc, char *argv[])
{
	const char *config_str = NULL;
	cJSON *json = NULL;
	cJSON *item = NULL;
	
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
		fprintf(stderr, "Failed to parse JSON config: %s\n", config_str);
		return -1;
	}
	
	// 解析 socket_path
	item = cJSON_GetObjectItem(json, "socket_path");
	if (item && cJSON_IsString(item) && item->valuestring) {
		strncpy(g_config.socket_path, item->valuestring, sizeof(g_config.socket_path) - 1);
	}
	
	// 解析 interface
	item = cJSON_GetObjectItem(json, "interface");
	if (item && cJSON_IsString(item) && item->valuestring) {
		strncpy(g_config.interface, item->valuestring, sizeof(g_config.interface) - 1);
	}
	
	// 解析 ratelimit_interval
	item = cJSON_GetObjectItem(json, "ratelimit_interval");
	if (item && cJSON_IsNumber(item)) {
		g_config.ratelimit_interval = (__u32)item->valuedouble;
	}

	// 解析 ingress
	item = cJSON_GetObjectItem(json, "ingress");
	if (item && cJSON_IsBool(item))
		g_config.egress = cJSON_IsTrue(item);

	// 解析 egress
	item = cJSON_GetObjectItem(json, "egress");
	if (item && cJSON_IsBool(item))
		g_config.ingress = cJSON_IsTrue(item);
	
	// 解析 ratelimit_burst
	item = cJSON_GetObjectItem(json, "ratelimit_burst");
	if (item && cJSON_IsNumber(item)) {
		g_config.ratelimit_burst = (__u32)item->valuedouble;
	}
	
	// 解析 filter_ip
	item = cJSON_GetObjectItem(json, "filter_ip");
	if (item && cJSON_IsNumber(item)) {
		g_config.filter_ip = (__u32)item->valuedouble;
	}
	
	// 解析 filter_port
	item = cJSON_GetObjectItem(json, "filter_port");
	if (item && cJSON_IsNumber(item)) {
		g_config.filter_port = (__u16)item->valuedouble;
	}
	
	// 解析 filter_mode
	item = cJSON_GetObjectItem(json, "filter_mode");
	if (item && cJSON_IsNumber(item)) {
		g_config.filter_mode = (__u8)item->valuedouble;
	}
	
	cJSON_Delete(json);
	
	// 验证 interface
	if (g_config.interface[0] == '\0') {
		fprintf(stderr, "Error: interface must be specified\n");
		return -1;
	}
	
	// 打印配置
	fprintf(stderr, "Config parsed:\n");
	fprintf(stderr, "  interface: %s\n", g_config.interface);
	fprintf(stderr, "  socket_path: %s\n", g_config.socket_path);
	fprintf(stderr, "  ingress: %s\n", g_config.ingress ? "true" : "false");
	fprintf(stderr, "  egress: %s\n", g_config.egress ? "true" : "false");
	fprintf(stderr, "  ratelimit: %u pkts/%u sec\n", 
	        g_config.ratelimit_burst, g_config.ratelimit_interval);
	if (g_config.filter_ip != 0) {
		struct in_addr addr = { .s_addr = g_config.filter_ip };
		fprintf(stderr, "  filter_ip: %s (0x%08x)\n", inet_ntoa(addr), g_config.filter_ip);
	}
	if (g_config.filter_port != 0) {
		fprintf(stderr, "  filter_port: %u\n", g_config.filter_port);
	}
	fprintf(stderr, "  filter_mode: %u (0=AND, 1=OR, 2=tuple)\n", g_config.filter_mode);
	
	return 0;
}

// 初始化 Agent socket 连接
static int init_agent_socket(void)
{
	struct plugin_config plugin_cfg = {0};
	int err;
	
	strncpy(plugin_cfg.socket_path, g_config.socket_path, sizeof(plugin_cfg.socket_path) - 1);
	strncpy(plugin_cfg.plugin_name, "plux-tcpktcap-pcap", sizeof(plugin_cfg.plugin_name) - 1);
	plugin_cfg.heartbeat_interval = 5;
	
	err = init_socket_protocol(&g_socket, &plugin_cfg);
	if (err) {
		fprintf(stderr, "Failed to init socket protocol: %d\n", err);
		return -1;
	}
	
	err = socket_connect(&g_socket);
	if (err) {
		fprintf(stderr, "Failed to connect to socket: %d\n", err);
		return -1;
	}
	
	err = socket_send_handshake(&g_socket);
	if (err) {
		fprintf(stderr, "Failed to send handshake: %d\n", err);
		socket_disconnect(&g_socket);
		return -1;
	}
	
	err = socket_start_heartbeat(&g_socket);
	if (err) {
		fprintf(stderr, "Failed to start heartbeat: %d\n", err);
		socket_disconnect(&g_socket);
		return -1;
	}
	
	return 0;
}
