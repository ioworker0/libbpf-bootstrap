// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "plux/bpf_ratelimit.h"
#include "plux/bpf_watchdog.h"

#define ETH_P_IP 0x0800
#define TC_ACT_UNSPEC (-1)
#define CAPTURE_LEN 1600
#define IPPROTO_TCP 6

// 传递到用户态的数据包事件
struct packet_event {
	__u16 data_len;           // 实际捕获长度
	__u8  data[CAPTURE_LEN];  // 原始以太网帧数据
};

// Ringbuf: 内核态 -> 用户态 传递数据包
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 48 * 1024 * 1024);  // 48MB ≈ 30711 个包
} packets SEC(".maps");

// 过滤配置（const，加载前通过 rodata 设置）
// 0 表示不过滤该字段
const volatile __u32 filter_ip = 0;
const volatile __u16 filter_port = 0;
const volatile __u8 filter_mode = 0;  // 0=AND(全部匹配), 1=OR(任一匹配)

// 过滤匹配函数
// 返回 1 表示匹配，0 表示不匹配
static __always_inline int match_filter(__u32 src_ip, __u32 dst_ip,
					__u16 src_port, __u16 dst_port)
{
	// IP 匹配: 检查源或目标 IP
	bool ip_match = (filter_ip == 0 || filter_ip == src_ip || filter_ip == dst_ip);
	// Port 匹配: 检查源或目标端口
	bool port_match = (filter_port == 0 || filter_port == src_port || filter_port == dst_port);

	if (filter_mode == 0)  // AND 模式: 设置的条件全部匹配
		return (filter_ip == 0 || ip_match) && (filter_port == 0 || port_match);
	else  // OR 模式: 设置的条件任一匹配即可
		return (filter_ip && ip_match) || (filter_port && port_match);
}

SEC("tc")
int plux_tcp_packet_capture(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct packet_event *evt;
	__u16 capture_len;

	// 安全检查 1: Watchdog - 用户态挂了自动放行
	if (bpf_watchdog_timed_out())
		return TC_ACT_UNSPEC;

	// 安全检查 2: 以太网头边界检查
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 只处理 IPv4
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	// 解析 IP 头
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 只处理 TCP
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	// 解析 TCP 头
	tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 应用过滤规则
	if (!match_filter(ip->saddr, ip->daddr, bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest)))
		return TC_ACT_UNSPEC;

	// 计算捕获长度（整个以太网帧）
	capture_len = data_end - data;
	if (capture_len > CAPTURE_LEN)
		capture_len = CAPTURE_LEN;

	// RateLimit: 限制抓包速率，防止 ringbuf 溢出和用户态过载
	if (bpf_ratelimit_check())
		return TC_ACT_UNSPEC;

	// 分配 ringbuf 空间
	evt = bpf_ringbuf_reserve(&packets, sizeof(*evt), 0);
	if (!evt)
		return TC_ACT_UNSPEC;

	// 填充数据并提交
	evt->data_len = capture_len;
	for (int i = 0; i < CAPTURE_LEN && i < capture_len; i++) {
		if ((void *)(((__u8 *)data) + i) >= data_end)
			break;
		evt->data[i] = *(((__u8 *)data) + i);
	}
	bpf_ringbuf_submit(evt, 0);

	return TC_ACT_UNSPEC;  // 放行流量
}

char __license[] SEC("license") = "GPL";
