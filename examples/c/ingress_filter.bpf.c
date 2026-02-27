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

// Watchdog: 心跳超时时间（纳秒），默认 10 秒
#define WATCHDOG_TIMEOUT_NS (10ULL * 1000000000ULL)

// Watchdog map: 存储最后一次心跳时间
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);  // 最后心跳时间戳（纳秒）
} plux_watchdog SEC(".maps");

SEC("tc")
int plux_ingress_firewall(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    __u32 key = 0;
    __u64 *last_heartbeat;
    __u64 now;

    // Watchdog: 检查心跳超时
    last_heartbeat = bpf_map_lookup_elem(&plux_watchdog, &key);
    if (last_heartbeat) {
        now = bpf_ktime_get_ns();
        if (now - *last_heartbeat > WATCHDOG_TIMEOUT_NS) {
            // 超时，自动放行所有流量（安全失效策略）
            bpf_printk("plux_ingress_firewall: watchdog timeout, bypassing");
            return TC_ACT_UNSPEC;
        }
    } else {
        // 没有心跳记录，放行（安全失效策略）
        return TC_ACT_UNSPEC;
    }

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

    // 检查源 IP 是否是要阻断的 IP（ingress 看谁发进来的）
    // 拦截所有来自 111.63.65.103 的入向流量
    if (src_ip == BLOCKED_IP) {
        bpf_printk("Blocked ingress from IP: 111.63.65.103");
        return TC_ACT_SHOT;  // 丢弃数据包
    }

    // 允许其他流量
    return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
