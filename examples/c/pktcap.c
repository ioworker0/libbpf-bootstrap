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
	// 过滤掉 "Exclusivity flag" 警告，这是正常的（Calico 已创建 qdisc）
	if (level == LIBBPF_WARN && strstr(format, "Exclusivity flag"))
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
	
	// 参考 egress_filter 的方式
	// 设置 TC hook (ingress)
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress,
			    .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS);
	
	// 创建 qdisc (如果不存在)，忽略已存在错误
	err = bpf_tc_hook_create(&tc_hook_ingress);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	if (err == -EEXIST) {
		fprintf(stderr, "TC qdisc already exists (created by Calico)\n");
	}
	
	// 设置 TC opts (ingress)
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.packet_capture));
	
	// Attach 程序到 TC ingress
	err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
	if (err) {
		fprintf(stderr, "Failed to attach TC ingress: %d\n", err);
		goto cleanup;
	}
	fprintf(stderr, "Attached to ingress (priority: 5, handle: 0x1)\n");
	
	// 设置 TC hook (egress)
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress,
			    .ifindex = ifindex,
			    .attach_point = BPF_TC_EGRESS);
	
	// 设置 TC opts (egress)
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.packet_capture));
	
	// Attach 程序到 TC egress
	err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
	if (err) {
		fprintf(stderr, "Failed to attach TC egress: %d\n", err);
		goto cleanup;
	}
	fprintf(stderr, "Attached to egress (priority: 5, handle: 0x1)\n");
	
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
	
	// Detach ingress
	tc_opts_ingress.flags = 0;
	tc_opts_ingress.prog_fd = 0;
	tc_opts_ingress.prog_id = 0;
	err = bpf_tc_detach(&tc_hook_ingress, &tc_opts_ingress);
	if (err) {
		fprintf(stderr, "Failed to detach TC ingress: %d\n", err);
	}
	
	// Detach egress
	tc_opts_egress.flags = 0;
	tc_opts_egress.prog_fd = 0;
	tc_opts_egress.prog_id = 0;
	err = bpf_tc_detach(&tc_hook_egress, &tc_opts_egress);
	if (err) {
		fprintf(stderr, "Failed to detach TC egress: %d\n", err);
	}
	
cleanup:
	ring_buffer__free(rb);
	pktcap_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
