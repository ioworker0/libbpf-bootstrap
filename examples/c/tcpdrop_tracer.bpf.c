// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

/* Event structure sent to userspace */
struct event {
    __u64 timestamp;       // 时间戳 (ns)
    __u32 saddr;           // 源 IP (IPv4)
    __u32 daddr;           // 目标 IP (IPv4)
    __u16 sport;           // 源端口
    __u16 dport;           // 目标端口
    __u32 drop_reason;     // 丢包原因
    __u8  tcp_state;       // TCP 状态
    __u8  tcp_flags;       // TCP flags
    __s32 stack_id;        // 堆栈 ID (-1 表示未采集)
};

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 * 1024);  // 32MB
} events SEC(".maps");

/* Stack trace map */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64) * 32);  // 32 层堆栈
    __uint(max_entries, 32768);
} stack_traces SEC(".maps");

/* Extract TCP header from skb */
static __always_inline int extract_tcp_info(struct sk_buff *skb, 
                                            __u32 *saddr, __u32 *daddr,
                                            __u16 *sport, __u16 *dport,
                                            __u8 *tcp_flags)
{
    void *head = NULL;
    void *data = NULL;
    __u16 network_header = 0;
    __u16 transport_header = 0;
    
    // 读取 skb 头指针和偏移
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);
    
    if (!head || !data)
        return -1;
    
    // 读取 IP 头
    struct iphdr iph = {};
    void *ip_header = head + network_header;
    bpf_probe_read_kernel(&iph, sizeof(iph), ip_header);
    
    *saddr = iph.saddr;
    *daddr = iph.daddr;
    
    // 检查是否是 TCP
    if (iph.protocol != IPPROTO_TCP)
        return -1;
    
    // 读取 TCP 头
    struct tcphdr tcph = {};
    void *tcp_header = head + transport_header;
    bpf_probe_read_kernel(&tcph, sizeof(tcph), tcp_header);
    
    *sport = bpf_ntohs(tcph.source);
    *dport = bpf_ntohs(tcph.dest);
    
    // 提取 TCP flags
    __u8 flags = 0;
    if (tcph.fin) flags |= 0x01;
    if (tcph.syn) flags |= 0x02;
    if (tcph.rst) flags |= 0x04;
    if (tcph.psh) flags |= 0x08;
    if (tcph.ack) flags |= 0x10;
    if (tcph.urg) flags |= 0x20;
    *tcp_flags = flags;
    
    return 0;
}

SEC("tracepoint/skb/kfree_skb")
int tp__skb_kfree_skb(struct trace_event_raw_kfree_skb *args)
{
    struct event *e;
    struct sk_buff *skb;
    struct sock *sk;
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    __u8 tcp_flags = 0;
    __u8 tcp_state = 0;
    __u32 drop_reason = 0;
    
    // 动态检查内核是否有 reason 字段（兼容老内核）
    if (bpf_core_field_exists(args->reason)) {
        drop_reason = args->reason;
    } else {
        drop_reason = 0;  // 老内核没有 reason 字段
    }
    
    // 注释掉 reason 过滤，因为很多场景 reason 都是 0
    // if (drop_reason <= SKB_DROP_REASON_NOT_SPECIFIED)
    //     return 0;
    
    // 过滤: 排除 IPv6
    if (args->protocol == bpf_htons(ETH_P_IPV6))
        return 0;
    
    skb = args->skbaddr;
    if (!skb)
        return 0;
    
    // 提取 TCP 信息
    if (extract_tcp_info(skb, &saddr, &daddr, &sport, &dport, &tcp_flags) < 0)
        return 0;  // 不是 TCP，忽略

    // IP + PORT 过滤 TODO

    // 获取 TCP state (从 sock 结构体)
    bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
    if (sk) {
        // 读取 socket state
        bpf_probe_read_kernel(&tcp_state, sizeof(tcp_state), &sk->__sk_common.skc_state);
    }
    
    // 只在 reason=0 时过滤正常关闭的连接（噪音过滤）
    // TCP_CLOSE = 7, FIN flag = 0x01
//    if (drop_reason == 0 && tcp_state == 7 && (tcp_flags & 0x01)) {
//        return 0;  // 正常 FIN 包，不是真正的丢包
//    }
    
    // 采集内核堆栈
    __s32 stack_id = bpf_get_stackid(args, &stack_traces, BPF_F_REUSE_STACKID);
    
    // 分配 ringbuf 空间
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    // 填充事件
    e->timestamp = bpf_ktime_get_ns();
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    e->drop_reason = drop_reason;  // 使用之前判断的 drop_reason（可能为 0）
    e->tcp_state = tcp_state;
    e->tcp_flags = tcp_flags;
    e->stack_id = stack_id;
    
    // 提交事件
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
