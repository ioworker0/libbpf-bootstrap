// SPDX-License-Identifier: GPL-2.0
/*
 * pktfwd.bpf.c - 包转发插件 (DNAT)
 *
 * 功能：在 egress 方向匹配目的 IP，并转发到目标 IP
 *
 * 用法：pktfwd <interface> <original_ip> <target_ip>
 *   - interface: 网卡名称
 *   - original_ip: 需要转发的原始目的 IP
 *   - target_ip: 转发到哪里的目标 IP
 *
 * 例如：pktfwd eth0 10.96.0.1 10.244.1.5
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "plux/bpf_watchdog.h"

#define ETH_P_IP 0x0800
#define TC_ACT_UNSPEC (-1)  // 默认行为，让后续程序继续处理
#define TC_ACT_OK 0         // 继续处理

// 转发配置（从用户空间设置）
struct fwd_config {
	__u32 original_ip;  // 需要转发的原始目的 IP (网络字节序)
	__u32 target_ip;    // 转发到哪里的目标 IP (网络字节序)
	__u8  enabled;      // 是否启用
	__u8  _padding[3];
};

// 配置 map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fwd_config);
} fwd_cfg SEC(".maps");

// 统计 map
struct fwd_stats {
	__u64 total_packets;    // 总包数
	__u64 forwarded_packets; // 转发的包数
	__u64 non_ipv4;         // 非 IPv4 包
	__u64 no_match;         // 不匹配的包
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fwd_stats);
} stats SEC(".maps");

// 更新 IP 校验和（使用 BPF helper，与 Calico 一致）
static __always_inline void update_ip_checksum(struct __sk_buff *skb,
						__u32 ip_cksum_off,  // IP check 字段相对于 skb->data 的偏移
						__u32 old_addr, __u32 new_addr)
{
	// bpf_l3_csum_replace: 增量更新 L3 校验和
	// 参数: skb, offset, old_value, new_value, size (2=half word, 4=word)
	bpf_l3_csum_replace(skb, ip_cksum_off, old_addr, new_addr, 4);
}

// 更新 L4 校验和（使用 BPF helper，与 Calico 一致）
static __always_inline void update_l4_checksum(struct __sk_buff *skb,
						__u32 l4_cksum_off,  // L4 check 字段相对于 skb->data 的偏移
						__u32 old_addr, __u32 new_addr,
						__u16 old_port, __u16 new_port)
{
	// 更新 IP 地址变化对校验和的影响
	bpf_l4_csum_replace(skb, l4_cksum_off, old_addr, new_addr, 4);
	// 更新端口变化对校验和的影响（如果需要）
	if (old_port != new_port) {
		bpf_l4_csum_replace(skb, l4_cksum_off, old_port, new_port, 2);
	}
}

SEC("tc")
int plux_packet_forward(struct __sk_buff *skb)
{
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct fwd_config *cfg;
	struct fwd_stats *stat;
	__u32 key = 0;

	// 统计：增加总包数
	stat = bpf_map_lookup_elem(&stats, &key);
	if (stat) {
		__sync_fetch_and_add(&stat->total_packets, 1);
	}

	// Watchdog: 如果用户态程序挂了，自动放行所有流量
	if (bpf_watchdog_timed_out())
		return TC_ACT_UNSPEC;

	// 获取配置
	cfg = bpf_map_lookup_elem(&fwd_cfg, &key);
	if (!cfg || !cfg->enabled)
		return TC_ACT_UNSPEC;

	// 检查以太网头
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 只处理 IPv4
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		if (stat) {
			__sync_fetch_and_add(&stat->non_ipv4, 1);
		}
		return TC_ACT_UNSPEC;
	}

	// 检查 IP 头
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_UNSPEC;

	// 检查目的 IP 是否匹配
	if (ip->daddr != cfg->original_ip) {
		if (stat) {
			__sync_fetch_and_add(&stat->no_match, 1);
		}
		return TC_ACT_UNSPEC;
	}

	// 执行 DNAT：修改目的 IP
	__u32 old_ip = ip->daddr;
	__u32 new_ip = cfg->target_ip;

	bpf_printk("pktfwd: DNAT %pI4 -> %pI4", &old_ip, &new_ip);

	// 计算 IP check 字段相对于 skb->data 的偏移
	// = 以太网头(14) + IP头内check偏移(10)
	__u32 ip_cksum_off = sizeof(struct ethhdr) + offsetof(struct iphdr, check);

	// 更新 IP 校验和
	update_ip_checksum(skb, ip_cksum_off, old_ip, new_ip);

	// 更新目的 IP
	ip->daddr = new_ip;

	// 更新 L4 校验和（TCP/UDP）
	if (ip->protocol == 6 || ip->protocol == 17) {
		struct tcphdr *l4 = (void *)ip + (ip->ihl * 4);
		if ((void *)(l4 + 1) <= data_end) {
			// 计算 L4 check 字段相对于 skb->data 的偏移
			// = 以太网头(14) + IP头(ihl*4) + L4头内check偏移
			__u32 l4_cksum_off;
			if (ip->protocol == 6) {  // TCP
				l4_cksum_off = sizeof(struct ethhdr) + (ip->ihl * 4) + offsetof(struct tcphdr, check);
			} else {  // UDP
				l4_cksum_off = sizeof(struct ethhdr) + (ip->ihl * 4) + offsetof(struct udphdr, check);
			}
			update_l4_checksum(skb, l4_cksum_off, old_ip, new_ip, 0, 0);
		}
	}

	// 统计：增加转发包数
	if (stat) {
		__sync_fetch_and_add(&stat->forwarded_packets, 1);
	}

	// 继续处理，让后续的 Calico 等程序继续
	return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
