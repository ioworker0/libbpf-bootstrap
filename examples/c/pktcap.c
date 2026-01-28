// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include "pktcap.skel.h"

static volatile sig_atomic_t exiting = 0;

#define CAPTURE_LEN 128

struct packet_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u16 total_len;
	__u16 data_len;
	__u8  data[CAPTURE_LEN];
};

static void sig_int(int signo) { exiting = 1; }

static const char *proto_name(__u8 proto) {
	switch(proto) {
	case 6: return "TCP";
	case 17: return "UDP";
	case 1: return "ICMP";
	default: return "OTHER";
	}
}

static void print_hex_dump(const __u8 *data, __u16 len) {
	for (int i = 0; i < len; i += 16) {
		printf("  0x%04x:  ", i);
		
		// 打印 hex
		for (int j = 0; j < 16; j++) {
			if (i + j < len)
				printf("%02x ", data[i + j]);
			else
				printf("   ");
			if (j == 7) printf(" ");
		}
		
		printf(" |");
		
		// 打印 ASCII
		for (int j = 0; j < 16 && i + j < len; j++) {
			char c = data[i + j];
			printf("%c", isprint(c) ? c : '.');
		}
		
		printf("|\n");
	}
}

static int handle_packet(void *ctx, void *data, size_t len) {
	struct packet_event *pkt = data;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	static unsigned long count = 0;
	
	inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));
	
	printf("\n[%lu] %-5s %s", ++count, proto_name(pkt->protocol), src);
	if (pkt->src_port)
		printf(":%d", pkt->src_port);
	printf(" -> %s", dst);
	if (pkt->dst_port)
		printf(":%d", pkt->dst_port);
	printf("  len=%d\n", pkt->total_len);
	
	if (pkt->data_len > 0) {
		print_hex_dump(pkt->data, pkt->data_len);
	}
	
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
	struct pktcap_bpf *skel;
	struct ring_buffer *rb;
	int ifindex, err;
	
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
		fprintf(stderr, "Example: %s eth0\n", argv[0]);
		return 1;
	}
	
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Invalid interface: %s\n", argv[1]);
		return 1;
	}
	
	libbpf_set_print(libbpf_print_fn);
	
	const char *btf_path = "/plux/btf/kernel.btf";
	if (access(btf_path, R_OK) == 0) {
		fprintf(stderr, "Found custom BTF at %s\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = pktcap_bpf__open_opts(&opts);
	} else {
		fprintf(stderr, "Using system BTF\n");
		skel = pktcap_bpf__open();
	}
	
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	err = pktcap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	
	fprintf(stderr, "BPF program loaded\n");
	
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_ingress, .handle = 1, .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.packet_capture));
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress, .handle = 1, .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.packet_capture));
	
	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	
	hook.attach_point = BPF_TC_INGRESS;
	if (bpf_tc_attach(&hook, &opts_ingress)) {
		fprintf(stderr, "Failed to attach ingress\n");
		goto cleanup;
	}
	fprintf(stderr, "Attached to ingress\n");
	
	hook.attach_point = BPF_TC_EGRESS;
	if (bpf_tc_attach(&hook, &opts_egress)) {
		fprintf(stderr, "Warning: Failed to attach egress (may already exist)\n");
	} else {
		fprintf(stderr, "Attached to egress\n");
	}
	
	rb = ring_buffer__new(bpf_map__fd(skel->maps.packets), handle_packet, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	printf("\n");
	printf("=======================================================\n");
	printf("Capturing packets on %s (first %d bytes)\n", argv[1], CAPTURE_LEN);
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n");
	
	signal(SIGINT, sig_int);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}
	
	printf("\n\nDetaching...\n");
	opts_ingress.flags = 0;
	opts_ingress.prog_fd = 0;
	opts_ingress.prog_id = 0;
	opts_egress.flags = 0;
	opts_egress.prog_fd = 0;
	opts_egress.prog_id = 0;
	
	hook.attach_point = BPF_TC_INGRESS;
	bpf_tc_detach(&hook, &opts_ingress);
	hook.attach_point = BPF_TC_EGRESS;
	bpf_tc_detach(&hook, &opts_egress);
	
cleanup:
	ring_buffer__free(rb);
	pktcap_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
