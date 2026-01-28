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

// Cilium style: IPv4 checksum update helper
static __always_inline int
ipv4_csum_update_by_value(struct __sk_buff *ctx, int l3_off, __u32 old_val,
			  __u32 new_val, __u32 len)
{
	return bpf_l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
				   old_val, new_val, len);
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
	int l3_off = sizeof(struct ethhdr);

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
	
	// Cilium style: 直接修改指针
	ip->tos = new_tos;
	
	// Cilium style: 更新校验和
	// l3_csum_replace() takes at min 2 bytes, zero extended.
	if (ipv4_csum_update_by_value(skb, l3_off, old_tos, new_tos, 2) < 0) {
		bpf_printk("Failed to update IP checksum");
		return TC_ACT_UNSPEC;
	}
	
	bpf_printk("DSCP marked: 0x%x (TOS: 0x%x -> 0x%x)", 
		   target_dscp, old_tos, new_tos);
	
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
