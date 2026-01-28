// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_UNSPEC (-1) // 默认行为，继续处理
#define TC_ACT_SHOT   2    // 丢弃数据包

#define ETH_P_IP 0x0800

// 写死要阻断的 IP: 111.63.65.103
// 网络字节序(大端): 6f 3f 41 67
// 小端: 67 41 3f 6f
#define BLOCKED_IP 0x67413F6F  // 111.63.65.103 in little-endian

SEC("tc")
int egress_firewall(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth;
	struct iphdr *ip;

	// 检查以太网头
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 只处理 IPv4
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	// 检查 IP 头
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_UNSPEC;

	__u32 src_ip = ip->saddr;

	// 检查源 IP 是否是要阻断的容器 IP
	// 在 veth ingress 上，src_ip 就是容器的 IP
	if (src_ip == BLOCKED_IP) {
		bpf_printk("Blocked container egress from IP: 111.63.65.103");
		return TC_ACT_SHOT;  // 丢弃数据包
	}

	// 允许其他流量，使用 TC_ACT_UNSPEC 让 Calico 继续处理
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
