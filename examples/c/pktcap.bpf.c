// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "plux/bpf_ratelimit.h"

#define ETH_P_IP 0x0800
#define TC_ACT_UNSPEC (-1) // 默认行为，让后续程序继续处理
#define CAPTURE_LEN 1500  // 增加到 1500 字节（标准 MTU）

struct packet_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _padding[3]; // 调整填充
	__u32 total_len;   // 使用 u32
	__u16 data_len;    // 实际捕获长度
	__u8  data[CAPTURE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} packets SEC(".maps");

// Watchdog map: 用于检测用户态程序是否存活
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);  // 最后更新时间戳（纳秒）
} plux_watchdog SEC(".maps");

#define WATCHDOG_TIMEOUT_NS (10ULL * 1000000000ULL)  // 10 秒超时

SEC("tc")
int plux_packet_capture(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct packet_event *evt;
	__u16 capture_len;

	// RateLimit: 限制抓包速率，防止 ringbuf 溢出和用户态过载
	if (bpf_ratelimit_check())
		return TC_ACT_UNSPEC;

	// Watchdog 检查：如果用户态程序挂了，自动放行所有流量
	__u32 key = 0;
	__u64 *last_heartbeat = bpf_map_lookup_elem(&plux_watchdog, &key);
	if (last_heartbeat) {
		__u64 now = bpf_ktime_get_ns();
		if (now - *last_heartbeat > WATCHDOG_TIMEOUT_NS) {
			bpf_printk("plux_packet_capture: watchdog timeout, bypassing");
			return TC_ACT_UNSPEC;  // 超时，放行
		}
	}
	
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;  // 放行，让后续程序继续处理
	
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;  // 非 IPv4，放行
	
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_UNSPEC;  // 放行
	
	evt = bpf_ringbuf_reserve(&packets, sizeof(*evt), 0);
	if (!evt)
		return TC_ACT_UNSPEC;  // 内存不足，直接放行
	
	evt->src_ip = ip->saddr;
	evt->dst_ip = ip->daddr;
	evt->protocol = ip->protocol;
	evt->src_port = 0;
	evt->dst_port = 0;
	
	// 使用 skb->len 获取完整的包长度（包括以太网头）作为原始长度
	// ip->tot_len 只是 IP 包长度
	evt->total_len = skb->len;
	
	// 解析端口
	if (ip->protocol == 6 || ip->protocol == 17) {  // TCP or UDP
		struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
		if ((void *)(tcp + 1) <= data_end) {
			evt->src_port = bpf_ntohs(tcp->source);
			evt->dst_port = bpf_ntohs(tcp->dest);
		}
	}
	
	// 复制完整的以太网帧（从 eth 开始）
	capture_len = data_end - data;  // 完整数据包长度
	if (capture_len > CAPTURE_LEN)
		capture_len = CAPTURE_LEN;
	
	evt->data_len = capture_len;
	
	// 复制数据（从以太网头开始）
	for (int i = 0; i < CAPTURE_LEN && i < capture_len; i++) {
		if ((void *)(((__u8 *)data) + i) >= data_end)
			break;
		evt->data[i] = *(((__u8 *)data) + i);
	}
	
	bpf_ringbuf_submit(evt, 0);
	return TC_ACT_UNSPEC;  // 抓包完成，放行给 Calico
}

char __license[] SEC("license") = "GPL";
