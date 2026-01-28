// SPDX-License-Identifier: GPL-2.0
// 搞不定，暂时放弃
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2
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


// Cilium style: 使用 bpf_l3_csum_replace 增量更新校验和
// 之前的实现尝试手动计算校验和（RFC-1141），但在反码运算和字节序处理上容易出错。
// Cilium 和标准做法是使用 bpf_l3_csum_replace 辅助函数。
// 
// 注意：TOS (offset 1) 和 Version/IHL (offset 0) 组成一个 16-bit 字。
// 我们传入 size=2，并使用 bpf_htons 确保差异值被应用到正确的字节位置。
// 例如在 Little Endian 机器上，TOS 位于高字节 (0xXX00)，bpf_htons 会正确处理位移。
static __always_inline int ip_update_csum_safe(struct __sk_buff *skb, __u8 old_tos, __u8 new_tos)
{
	// 24 = sizeof(struct ethhdr) + offsetof(struct iphdr, check)
	// 假设是标准以太网帧（无 VLAN）
	return bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
				   bpf_htons(old_tos), bpf_htons(new_tos), 2);
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
	
	// Cilium style: 使用 helper 更新校验和
	// 如果更新失败，丢弃包以避免发送坏包
	if (ip_update_csum_safe(skb, old_tos, new_tos) < 0)
		return TC_ACT_SHOT;
	
	bpf_printk("DSCP marked: 0x%x (TOS: 0x%x -> 0x%x)", 
		   target_dscp, old_tos, new_tos);
	
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
