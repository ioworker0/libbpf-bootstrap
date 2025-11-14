// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct bpf_iter__tcp {
	struct bpf_iter_meta *meta;
	struct sock_common *sk_common;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct tcpconn {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 seq;
	__u32 ack_seq;
};

SEC("iter/tcp")
int tcp_conn(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct tcp_sock *tp;
	struct tcpconn t = {};

	if (!skc)
		return 0;

	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		return 0;

	if (skc->skc_state != TCP_ESTABLISHED)
		return 0;

	/* Add your filters here */

	t.saddr = skc->skc_rcv_saddr;
	t.daddr = skc->skc_daddr;
	t.sport = skc->skc_num;
	t.dport = bpf_ntohs(skc->skc_dport);
	t.seq = tp->snd_nxt;
	t.ack_seq = tp->rcv_nxt;

	bpf_seq_write(ctx->meta->seq, &t, sizeof(t));

	return 0;
}
