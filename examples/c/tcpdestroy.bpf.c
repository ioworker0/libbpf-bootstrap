// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	struct sock_common *sk_common;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// These variables will be set by the user-space program
volatile __u32 target_saddr = 0;
volatile __u32 target_daddr = 0;
volatile __u16 target_sport = 0;
volatile __u16 target_dport = 0;

SEC("iter/tcp")
int tcp_destroy_iterator(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;

	if (!skc)
		return 0;

	if (skc->skc_family != AF_INET || skc->skc_state != TCP_ESTABLISHED)
		return 0;

	// Check if the connection details match the target
	// We check both directions of the connection
	if ((skc->skc_rcv_saddr == target_saddr && skc->skc_daddr == target_daddr &&
	     skc->skc_num == target_sport && bpf_ntohs(skc->skc_dport) == target_dport) ||
	    (skc->skc_rcv_saddr == target_daddr && skc->skc_daddr == target_saddr &&
	     skc->skc_num == target_dport && bpf_ntohs(skc->skc_dport) == target_sport)) {

		bpf_printk("TCP connection matched in iterator. Attempting to destroy sock: %p", skc);
		bpf_sock_destroy(skc);
	}

	return 0;
}
