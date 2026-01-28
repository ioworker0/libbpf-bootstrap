// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_UNSPEC (-1)
#define ETH_P_IP 0x0800

// DSCP 值定义（常用的）
#define DSCP_CS0  0x00  // 默认
#define DSCP_CS1  0x08  // 优先级 1
#define DSCP_CS2  0x10  // 优先级 2
#define DSCP_CS3  0x18  // 优先级 3
#define DSCP_CS4  0x20  // 优先级 4
#define DSCP_CS5  0x28  // 优先级 5
#define DSCP_CS6  0x30  // 优先级 6
#define DSCP_CS7  0x38  // 优先级 7
#define DSCP_EF   0x2e  // Expedited Forwarding (最高优先级)
#define DSCP_AF11 0x0a  // Assured Forwarding

// 配置：要设置的 DSCP 值（从用户态配置）
const volatile __u8 target_dscp = DSCP_EF;  // 默认设置为 EF (最高优先级)

// Calico style: 手动更新 IP 校验和（RFC-1141 增量更新）
// 修正版：TOS 是 IP 头的低位字节，不需要左移！
static __always_inline void ip_update_csum_for_tos(struct iphdr *ip, __u8 old_tos, __u8 new_tos)
{
	__u32 sum = ip->check;
	// TOS 在 [Ver/IHL][TOS] 这个 16-bit 字的低位
	// 所以直接加上差值，不需要 << 8
	// 使用 bpf_htons 确保字节序正确处理
	sum += bpf_htons((__u16)(new_tos - old_tos));
	
	// 处理进位 (Standard RFC 1071/1141 checksum arithmetic)
	sum = (sum & 0xffff) + (sum >> 16);
	// 再次处理可能的进位
	sum = (sum & 0xffff) + (sum >> 16);
	
	ip->check = (__u16)sum;
}

SEC("tc")
int dscp_marker(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth;
	struct iphdr *ip;
	__u8 old_tos, new_tos;
	__u8 ecn_bits;

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

	// 读取当前 TOS 字段
	old_tos = ip->tos;
	
	// 保留 ECN 位（低 2 位），只修改 DSCP（高 6 位）
	ecn_bits = old_tos & 0x03;
	new_tos = (target_dscp << 2) | ecn_bits;
	
	// 如果 TOS 没变，不需要修改
	if (old_tos == new_tos)
		return TC_ACT_UNSPEC;
	
	// Calico style: 直接修改指针
	ip->tos = new_tos;
	
	// Calico style: 手动更新校验和（修正公式）
	ip_update_csum_for_tos(ip, old_tos, new_tos);
	
	bpf_printk("DSCP marked: 0x%x (TOS: 0x%x -> 0x%x)", 
		   target_dscp, old_tos, new_tos);
	
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
