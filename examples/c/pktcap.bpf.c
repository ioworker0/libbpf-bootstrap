// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define CAPTURE_LEN 128  // 抓取前128字节

struct packet_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u16 total_len;
	__u16 data_len;  // 实际抓取的数据长度
	__u8  data[CAPTURE_LEN];  // 包内容
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} packets SEC(".maps");

SEC("tc")
int packet_capture(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct packet_event *evt;
	__u16 capture_len;
	
	if ((void *)(eth + 1) > data_end)
		return 0;
	
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;
	
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;
	
	evt = bpf_ringbuf_reserve(&packets, sizeof(*evt), 0);
	if (!evt)
		return 0;
	
	evt->src_ip = ip->saddr;
	evt->dst_ip = ip->daddr;
	evt->protocol = ip->protocol;
	evt->total_len = bpf_ntohs(ip->tot_len);
	evt->src_port = 0;
	evt->dst_port = 0;
	
	// 解析端口
	if (ip->protocol == 6 || ip->protocol == 17) {  // TCP or UDP
		struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
		if ((void *)(tcp + 1) <= data_end) {
			evt->src_port = bpf_ntohs(tcp->source);
			evt->dst_port = bpf_ntohs(tcp->dest);
		}
	}
	
	// 复制包数据（从 IP 头开始）
	capture_len = evt->total_len;
	if (capture_len > CAPTURE_LEN)
		capture_len = CAPTURE_LEN;
	
	// 边界检查
	if ((void *)ip + capture_len > data_end)
		capture_len = data_end - (void *)ip;
	
	evt->data_len = capture_len;
	
	// 复制数据
	for (int i = 0; i < CAPTURE_LEN && i < capture_len; i++) {
		if ((void *)ip + i + 1 > data_end)
			break;
		evt->data[i] = *(((__u8 *)ip) + i);
	}
	
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char __license[] SEC("license") = "GPL";
