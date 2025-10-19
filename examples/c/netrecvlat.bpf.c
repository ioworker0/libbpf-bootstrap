// SPDX-License-Identifier: Dual MIT/GPL
// Measure RX latency of TCP IPv4 packets at several receive path stages.
// Stages:
//   1) tracepoint/net/netif_receive_skb          (TO_NETIF_RCV)
//   2) kprobe/tcp_v4_rcv                         (TO_TCPV4_RCV)
//   3) tracepoint/skb/skb_copy_datagram_iovec    (TO_USER_COPY)
//
// Latency is computed as: now (ktime_get_ns + mono_wall_offset) - skb->tstamp
// Only packets whose cumulative latency exceeds per-stage thresholds are emitted.
//
// This is a simplified version (no ratelimit helper) suitable for libbpf-bootstrap.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bpf_ratelimit.h"

// Add missing protocol constant (avoid including if_ether.h which may clash)
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// Helper functions to compute header pointers (kernel macros not available in BPF C here)
static __always_inline void *skb_network_header(const struct sk_buff *skb)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh_off = BPF_CORE_READ(skb, network_header);
	return head + nh_off;
}

static __always_inline void *skb_transport_header(const struct sk_buff *skb)
{
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 th_off = BPF_CORE_READ(skb, transport_header);
	return head + th_off;
}

// Global rate limiter: 1 second interval, allow 100 events per interval (shared across CPUs)
BPF_RATELIMIT(rate, 1, 100);

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/* User configurable (via .rodata rewrite) */
volatile const __u64 to_netif     = 10ULL  * 1000 * 1000;   // 10 ms in ns
volatile const __u64 to_tcpv4     = 20ULL * 1000 * 1000;    // 20 ms
volatile const __u64 to_user_copy = 50ULL * 1000 * 1000;    // 50 ms

struct perf_event_t {
	char comm[TASK_COMM_LEN];
	__u64 latency;        // delta in ns
	__u64 tgid_pid;       // (tgid << 32) | pid for user copy stage; 0 otherwise
	__u64 pkt_len;        // skb->len
	__u16 sport;
	__u16 dport;
	__u32 saddr;          // IPv4 src
	__u32 daddr;          // IPv4 dst
	__u32 seq;
	__u32 ack_seq;
	__u8  state;          // TCP state if available
	__u8  where;          // stage identifier
};

enum skb_rcv_where {
	TO_NETIF_RCV = 0,
	TO_TCPV4_RCV = 1,
	TO_USER_COPY = 2,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
} netrecvlat_events SEC(".maps");

/* mono_wall_offset is updated periodically from user space via this ARRAY map (key=0). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} mono_wall_offset_map SEC(".maps");

static __always_inline __u64 skb_latency(struct sk_buff *skb)
{
	__u64 tstamp = BPF_CORE_READ(skb, tstamp);
	if (!tstamp)
		return 0; // no software timestamp available
	__u32 k = 0;
	__u64 *offset_ptr = bpf_map_lookup_elem(&mono_wall_offset_map, &k);
	__u64 offs = 0;
	if (offset_ptr)
		offs = *offset_ptr;
	return bpf_ktime_get_ns() + offs - tstamp;
}

static __always_inline void submit_event(void *ctx, struct sk_buff *skb, struct iphdr *ip, struct tcphdr *tcp,
		__u64 lat, __u8 state, __u8 where)
{
 	// Rate limit before doing work (cheap path)
	if (bpf_ratelimited(&rate))
		return;
 	struct perf_event_t evt = {};
 	if (where == TO_USER_COPY) {
 		evt.tgid_pid = bpf_get_current_pid_tgid();
 		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
 	}

	evt.latency = lat;
	evt.saddr = ip->saddr;
	evt.daddr = ip->daddr;
	evt.sport = tcp->source;
	evt.dport = tcp->dest;
	evt.seq = tcp->seq;
	evt.ack_seq = tcp->ack_seq;
	evt.pkt_len = BPF_CORE_READ(skb, len);
	evt.state = state;
	evt.where = where;
	bpf_perf_event_output(ctx, &netrecvlat_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

SEC("tracepoint/net/netif_receive_skb")
int netif_receive_skb_prog(struct trace_event_raw_net_dev_template *args)
{
	struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
	struct iphdr ip;
	struct tcphdr tcp;
	__u64 lat;

	if (BPF_CORE_READ(skb, protocol) != bpf_htons(ETH_P_IP))
		return 0;
	bpf_probe_read(&ip, sizeof(ip), skb_network_header(skb));
	if (ip.protocol != IPPROTO_TCP)
		return 0;
	bpf_probe_read(&tcp, sizeof(tcp), skb_transport_header(skb));
	lat = skb_latency(skb);
	if (lat < to_netif)
		return 0;
	submit_event(args, skb, &ip, &tcp, lat, 0 /* state unknown here */, TO_NETIF_RCV);
	return 0;
}

SEC("kprobe/tcp_v4_rcv")
int tcp_v4_rcv_prog(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	struct iphdr ip;
	struct tcphdr tcp;
	__u64 lat;
	__u8 state;
	struct sock *sk;

	lat = skb_latency(skb);
	if (lat < to_tcpv4)
		return 0;

	if (BPF_CORE_READ(skb, protocol) != bpf_htons(ETH_P_IP))
		return 0;
	bpf_probe_read(&ip, sizeof(ip), skb_network_header(skb));
	if (ip.protocol != IPPROTO_TCP)
		return 0;
	bpf_probe_read(&tcp, sizeof(tcp), skb_transport_header(skb));

	/* Skip if skb->sk is NULL (no TCP socket context) */
	sk = BPF_CORE_READ(skb, sk);
	if (!sk)
		return 0;
	state = BPF_CORE_READ(sk, __sk_common.skc_state);

	submit_event(ctx, skb, &ip, &tcp, lat, state, TO_TCPV4_RCV);
	return 0;
}

SEC("tracepoint/skb/skb_copy_datagram_iovec")
int skb_copy_datagram_iovec_prog(struct trace_event_raw_skb_copy_datagram_iovec *args)
{
	struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
	struct iphdr ip;
	struct tcphdr tcp;
	__u64 lat;
	__u8 state;
	struct sock *sk;

	if (BPF_CORE_READ(skb, protocol) != bpf_htons(ETH_P_IP))
		return 0;
	bpf_probe_read(&ip, sizeof(ip), skb_network_header(skb));
	if (ip.protocol != IPPROTO_TCP)
		return 0;
	bpf_probe_read(&tcp, sizeof(tcp), skb_transport_header(skb));
	lat = skb_latency(skb);
	if (lat < to_user_copy)
		return 0;

	/* Skip if skb->sk is NULL */
	sk = BPF_CORE_READ(skb, sk);
	if (!sk)
		return 0;
	state = BPF_CORE_READ(sk, __sk_common.skc_state);

	submit_event(args, skb, &ip, &tcp, lat, state, TO_USER_COPY);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
