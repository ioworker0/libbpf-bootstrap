// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "plux/bpf_ratelimit.h"
#include "plux/bpf_watchdog.h"

#define ETH_P_IP 0x0800
#define TC_ACT_UNSPEC (-1)
#define IPPROTO_TCP 6
#define CAPTURE_LEN 1600

// 传递到用户态的数据包事件
struct packet_event {
	__u32 data_len;           // 实际捕获长度
	// 5元组信息（固定位置）
	__u32 src_ip;             // 源IP地址（网络字节序）
	__u32 dst_ip;             // 目标IP地址（网络字节序）
	__u16 src_port;           // 源端口（主机字节序）
	__u16 dst_port;           // 目标端口（主机字节序）
	__u8  protocol;           // 协议（IPPROTO_TCP = 6）
	__u8  reserved[3];        // 对齐保留字段
	__u8  data[CAPTURE_LEN];  // 原始以太网帧数据
};

// Ringbuf: 内核态 -> 用户态 传递数据包
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 96 * 1024 * 1024);  // 96MB ≈ 60000 个包
} packets SEC(".maps");

// 过滤配置（const，加载前通过 rodata 设置）
// 0 表示不过滤该字段
const volatile __u32 filter_ip = 0;
const volatile __u16 filter_port = 0;
const volatile __u8 filter_mode = 0;  // 0=AND(全部匹配), 1=OR(任一匹配), 2=元组匹配(源或目的整体匹配)

// 过滤匹配函数
// 返回 1 表示匹配，0 表示不匹配
static __always_inline int match_filter(__u32 src_ip, __u32 dst_ip,
					__u16 src_port, __u16 dst_port)
{
	if (filter_mode == 2) {
		// mode 2: 必须 (src_ip, src_port) 或 (dst_ip, dst_port) 整体满足
		bool src_ok = (filter_ip == 0 || filter_ip == src_ip) &&
			      (filter_port == 0 || filter_port == src_port);
		bool dst_ok = (filter_ip == 0 || filter_ip == dst_ip) &&
			      (filter_port == 0 || filter_port == dst_port);
		return src_ok || dst_ok;
	}

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
	__u32 src_ip, dst_ip;
	__u16 src_port, dst_port;
	__u8 protocol;

	// 安全检查 1: Watchdog - 用户态挂了自动放行
	if (bpf_watchdog_timed_out())
		return TC_ACT_UNSPEC;

	/* 微调: 先解析/过滤，命中后再 pull_data，减少每包开销 */

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

	/* 保存元组，后续 pull_data 后指针会失效 */
	src_ip = ip->saddr;
	dst_ip = ip->daddr;
	src_port = bpf_ntohs(tcp->source);
	dst_port = bpf_ntohs(tcp->dest);
	protocol = ip->protocol;

	// 应用过滤规则
	if (!match_filter(src_ip, dst_ip, src_port, dst_port))
		return TC_ACT_UNSPEC;

	// RateLimit: 限制抓包速率，防止 ringbuf 溢出和用户态过载
	if (bpf_ratelimit_check())
		return TC_ACT_UNSPEC;

	/* 命中过滤后再拉线性区，降低总体开销 */
	// https://docs.ebpf.io/linux/helper-function/bpf_skb_pull_data/
	__u32 pull_len = skb->len;
	if (pull_len > CAPTURE_LEN)
		pull_len = CAPTURE_LEN;
	if (pull_len > 0 && bpf_skb_pull_data(skb, pull_len) < 0)
		return TC_ACT_UNSPEC;

	/* pull_data 后 data/data_end 可能变化，必须重取 */
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;

	/* 线性区可读长度 */
	__u32 payload_len = (__u32)((__u8 *)data_end - (__u8 *)data);
	if (payload_len > CAPTURE_LEN)
		payload_len = CAPTURE_LEN;

	/* 兼容当前内核 verifier：ringbuf_reserve 的 size 需为编译期常量 */
	evt = bpf_ringbuf_reserve(&packets, sizeof(*evt), 0);
	if (!evt)
		return TC_ACT_UNSPEC;

	// 填充元数据（包括长度）
	evt->data_len = payload_len;
	evt->src_ip = src_ip;
	evt->dst_ip = dst_ip;
	evt->src_port = src_port;
	evt->dst_port = dst_port;
	evt->protocol = protocol;
	evt->reserved[0] = 0;
	evt->reserved[1] = 0;
	evt->reserved[2] = 0;

	/* 
	 * 尝试使用 helper 一次性拷贝 
	 * 注意：payload_len 是变量，在某些旧内核 verifier 可能无法推导安全性。
	 * 但因为 reserve 是常量大小，且我们对 payload_len 做了 CAPTURE_LEN 截断，
	 * 这里期望 verifier 能通过。
	 */
	if (payload_len > 0) {
		// 再次确保 payload_len 不超限（verifier 提示）
		if (payload_len > CAPTURE_LEN)
			payload_len = CAPTURE_LEN;
			
		bpf_skb_load_bytes(skb, 0, evt->data, payload_len);
	}

	bpf_ringbuf_submit(evt, 0);

	return TC_ACT_UNSPEC;  // 放行流量
}

char __license[] SEC("license") = "GPL";
