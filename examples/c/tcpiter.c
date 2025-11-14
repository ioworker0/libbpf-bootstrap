// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tcpiter.skel.h"

struct tcpconn {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 seq;
	__u32 ack_seq;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct tcpiter_bpf *skel;
	int err, iter_fd, ret;
	struct tcpconn tc;
	ssize_t read_bytes;
	char saddr_str[INET_ADDRSTRLEN];
	char daddr_str[INET_ADDRSTRLEN];

	libbpf_set_print(libbpf_print_fn);

	skel = tcpiter_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = tcpiter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.tcp_conn));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create iter\n");
		goto cleanup;
	}

	printf("%-20s %-20s %-12s %-12s\n", "SADDR:SPORT", "DADDR:DPORT", "SEQ", "ACK_SEQ");

	while (true) {
		read_bytes = read(iter_fd, &tc, sizeof(tc));
		if (read_bytes <= 0)
			break;

		inet_ntop(AF_INET, &tc.saddr, saddr_str, sizeof(saddr_str));
		inet_ntop(AF_INET, &tc.daddr, daddr_str, sizeof(daddr_str));

		printf("%s:%-13d %s:%-13d %-12u %-12u\n",
		       saddr_str, tc.sport, daddr_str, tc.dport, tc.seq, tc.ack_seq);
	}

	close(iter_fd);

cleanup:
	tcpiter_bpf__destroy(skel);
	return -err;
}
