#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct event {
	u64 timestamp;
	u32 pid;
	u32 drop_reason;
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 state;
	u8 tcpflags;
	char comm[TASK_COMM_LEN];
	u32 stack_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512);
} events SEC(".maps");

#define MAX_STACK_DEPTH 15
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

SEC("tracepoint/skb/kfree_skb")
int tp__skb_free_skb(struct trace_event_raw_kfree_skb *args)
{
	struct event *event;

	// if (args->reason <= SKB_DROP_REASON_NOT_SPECIFIED)
	// 	return 0;

	if (args->protocol == bpf_htons(0x86dd))
		return 0;

	if (bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= 511) {
		bpf_printk("Ring buffer is almost full\n");
		return 0;
	}

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	struct sk_buff *skb = args->skbaddr;

	if (!skb) {
		return 0;
	}

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);

	// if (!sk) {
	//     return 0;
	// }

	// u16 skc_family = 0;
	// bpf_probe_read_kernel(&skc_family, sizeof(skc_family), &sk->__sk_common.skc_family);
	// if (skc_family != AF_INET) {
	//     return 0;
	// }

	void *head;
	if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head)) {
		bpf_printk("Read head failed\n");
		return 0;
	}

	u16 network_header;
	if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header)) {
		bpf_printk("Read head or network_header failed\n");
		return 0;
	}

	void *ip_header_ptr = (char *)head + network_header;

	struct iphdr ip;
	if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_header_ptr)) {
		bpf_printk("Read IP header failed\n");
		return 0;
	}

	if (ip.protocol != IPPROTO_TCP) {
		return 0;
	}

	u16 transport_header;
	if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
				  &skb->transport_header)) {
		bpf_printk("Read head or transport_header failed\n");
		return 0;
	}

	struct tcphdr tcp;
	void *tcp_ptr = head + transport_header;
	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), tcp_ptr)) {
		bpf_printk("Read TCP failed\n");
		return 0;
	}

	u8 tcpflags = 0;
	if (bpf_probe_read_kernel(&tcpflags, sizeof(tcpflags), (void *)&tcp + 13)) {
		bpf_printk("Read tcpflags failed\n");
		return 0;
	}

	char skc_state = 0;
	if (sk) {
		bpf_probe_read_kernel(&skc_state, sizeof(skc_state),
				      (const void *)&sk->__sk_common.skc_state);
	} else {
		skc_state = 127;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	event->saddr = ip.saddr;
	event->daddr = ip.daddr;
	event->sport = bpf_ntohs(tcp.source);
	event->dport = bpf_ntohs(tcp.dest);
	event->state = skc_state;
	event->tcpflags = tcpflags;
	// event->drop_reason = args->reason;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	event->stack_id = bpf_get_stackid(args, &stack_traces, 0);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";