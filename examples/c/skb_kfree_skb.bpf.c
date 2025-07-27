#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2 // Define Address Family for IPv4 if not already defined
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16 // Standard length for process command names
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800 // EtherType for IP packets
#endif

/*
 * The event structure sent from the kernel to user-space via the ring buffer.
 * It contains all the relevant information about the dropped skb.
 */
struct event {
	u64 timestamp;     // Event timestamp in nanoseconds
	u32 pid;           // PID of the process that owned the socket (if any)
	u32 drop_reason;   // The reason code for why the skb was dropped
	u32 saddr;         // Source IPv4 address
	u32 daddr;         // Destination IPv4 address
	u16 sport;         // Source port
	u16 dport;         // Destination port
	u8 state;          // TCP socket state
	u8 tcpflags;       // TCP flags (SYN, ACK, FIN, etc.)
	char comm[TASK_COMM_LEN]; // Command name of the process
	u32 stack_id;      // ID for the kernel stack trace
};

/*
 * BPF ring buffer to send events to user-space.
 * It's a memory-efficient way to transfer data.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512);
} events SEC(".maps");

#define MAX_STACK_DEPTH 15 // Define the max depth for stack traces

/*
 * BPF map to store kernel stack traces.
 * The key is a stack_id (u32) and the value is an array of instruction pointers.
 * The key and value sizes are explicitly defined for this special map type.
 */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 512);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

/*
 * BPF program attached to the skb:kfree_skb tracepoint.
 * This program is executed every time a socket buffer (skb) is freed.
 */
SEC("tracepoint/skb/kfree_skb")
int tp__skb_free_skb(struct trace_event_raw_kfree_skb *args)
{
	struct event *event;

	// Filter out events that are not actual drops (e.g., normal freeing)
	if (args->reason <= SKB_DROP_REASON_NOT_SPECIFIED)
		return 0;

	// Filter out IPv6 packets for simplicity
	if (args->protocol == bpf_htons(0x86dd))
		return 0;

	if (bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) >= 511) {
        bpf_printk("Ring buffer is almost full\n");
		return 0;
	}

	// Get the PID of the current process
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	struct sk_buff *skb = args->skbaddr;

	if (!skb) {
		return 0;
	}

	// Safely read the socket pointer from the skb
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

	// Safely read the offset to the network (L3) header
	u16 network_header;
	if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header)) {
		bpf_printk("Read head or network_header failed\n");
		return 0;
	}

	// Calculate the pointer to the IP header
	void *ip_header_ptr = (char *)head + network_header;

	// Read the IP header from the calculated pointer
	struct iphdr ip;
	if (bpf_probe_read_kernel(&ip, sizeof(ip), ip_header_ptr)) {
		bpf_printk("Read IP header failed\n");
		return 0;
	}

	// We are only interested in TCP packets
	if (ip.protocol != IPPROTO_TCP) {
		return 0;
	}

	// Safely read the offset to the transport (L4) header
	u16 transport_header;
	if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
				  &skb->transport_header)) {
		bpf_printk("Read head or transport_header failed\n");
		return 0;
	}

	// Read the TCP header
	struct tcphdr tcp;
	void *tcp_ptr = head + transport_header;
	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), tcp_ptr)) {
		bpf_printk("Read TCP failed\n");
		return 0;
	}

	// The TCP flags are located at offset 13 within the TCP header
	u8 tcpflags = 0;
	if (bpf_probe_read_kernel(&tcpflags, sizeof(tcpflags), (void *)&tcp + 13)) {
		bpf_printk("Read tcpflags failed\n");
		return 0;
	}

	// Read the TCP state from the socket structure, if it exists
	char skc_state = 0;
	if (sk) {
		bpf_probe_read_kernel(&skc_state, sizeof(skc_state),
				      (const void *)&sk->__sk_common.skc_state);
	} else {
		skc_state = 127; // Use a custom value to indicate no socket was found
	}

	// Reserve space in the ring buffer for our event
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Populate the event structure with the collected data
	event->timestamp = bpf_ktime_get_ns();
	event->pid = pid;
	event->saddr = ip.saddr;
	event->daddr = ip.daddr;
	event->sport = bpf_ntohs(tcp.source);
	event->dport = bpf_ntohs(tcp.dest);
	event->state = skc_state;
	event->tcpflags = tcpflags;
	event->drop_reason = args->reason;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Get the kernel stack trace and store its ID in the event
	event->stack_id = bpf_get_stackid(args, &stack_traces, 0);

	// Submit the event to the ring buffer for user-space to consume
	bpf_ringbuf_submit(event, 0);
	return 0;
}

// Define the license for the BPF program
char _license[] SEC("license") = "Dual BSD/GPL";