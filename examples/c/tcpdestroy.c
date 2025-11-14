// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcpdestroy.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// Suppress warnings to focus on the verifier's critical errors
	if (level >= LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, format, args);
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <saddr> <sport> <daddr> <dport>\n", prog);
	fprintf(stderr, "Example: %s 192.168.1.10 12345 192.168.1.20 80\n", prog);
}

int main(int argc, char **argv)
{
	struct tcpdestroy_bpf *skel;
	struct in_addr saddr, daddr;
	unsigned long sport_ul, dport_ul;
	int err, iter_fd;
	char buf[4096];

	if (argc != 5) {
		usage(argv[0]);
		return 1;
	}

	if (inet_pton(AF_INET, argv[1], &saddr) != 1) {
		fprintf(stderr, "Invalid source address: %s\n", argv[1]);
		return 1;
	}
	sport_ul = strtoul(argv[2], NULL, 10);
	if (sport_ul == 0 || sport_ul > 65535) {
		fprintf(stderr, "Invalid source port: %s\n", argv[2]);
		return 1;
	}

	if (inet_pton(AF_INET, argv[3], &daddr) != 1) {
		fprintf(stderr, "Invalid destination address: %s\n", argv[3]);
		return 1;
	}
	dport_ul = strtoul(argv[4], NULL, 10);
	if (dport_ul == 0 || dport_ul > 65535) {
		fprintf(stderr, "Invalid destination port: %s\n", argv[4]);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = tcpdestroy_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Pass the target connection details to the BPF program
	skel->bss->target_saddr = saddr.s_addr;
	skel->bss->target_sport = sport_ul;
	skel->bss->target_daddr = daddr.s_addr;
	skel->bss->target_dport = dport_ul;

	err = tcpdestroy_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton. Verifier log:\n");
		goto cleanup;
	}

	printf("BPF program loaded successfully.\n");

	// This attach is for the iterator link
	err = tcpdestroy_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	iter_fd = bpf_iter_create(bpf_link__fd(skel->links.tcp_destroy_iterator));
	if (iter_fd < 0) {
		fprintf(stderr, "Failed to create BPF iterator: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Triggering TCP connection iteration to find and destroy the target...\n");
	// Reading from the iterator FD triggers the BPF program in the kernel
	while (read(iter_fd, buf, sizeof(buf)) > 0);

	printf("Iteration complete.\n");

	close(iter_fd);

cleanup:
	tcpdestroy_bpf__destroy(skel);
	return err;
}
