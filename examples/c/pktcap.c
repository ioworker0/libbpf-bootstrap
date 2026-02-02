// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include "pktcap.skel.h"
#include "plux/bpf_ratelimit.h"
#include "plux/bpf_ratelimit_user.h"

static volatile sig_atomic_t exiting = 0;

#define CAPTURE_LEN 1500

// PCAP 文件头结构
struct pcap_file_header {
	__u32 magic;         // 0xa1b2c3d4
	__u16 version_major; // 2
	__u16 version_minor; // 4
	__s32 thiszone;      // GMT to local correction
	__u32 sigfigs;       // accuracy of timestamps
	__u32 snaplen;       // max length saved
	__u32 linktype;      // Data link type (1 = Ethernet)
} __attribute__((packed));

// PCAP 数据包头
struct pcap_packet_header {
	__u32 ts_sec;        // timestamp seconds
	__u32 ts_usec;       // timestamp microseconds
	__u32 incl_len;      // number of octets saved in file
	__u32 orig_len;      // actual length of packet
} __attribute__((packed));

struct packet_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  protocol;
	__u8  _padding[3]; // 调整填充，使 total_len 对齐到 4 字节
	__u32 total_len;   // 使用 u32 避免巨型帧(Jumbo Frame)溢出
	__u16 data_len;
	__u8  data[CAPTURE_LEN];
};

// 用于传递上下文的结构
struct handler_ctx {
	FILE *pcap_file;
	unsigned long *packet_count;
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
	struct handler_ctx *hctx = (struct handler_ctx *)ctx;
	struct packet_event *pkt = data;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	
	inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
	inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));
	
	// 打印到控制台
	printf("\n[%lu] %-5s %s", ++(*hctx->packet_count), proto_name(pkt->protocol), src);
	if (pkt->src_port)
		printf(":%d", pkt->src_port);
	printf(" -> %s", dst);
	if (pkt->dst_port)
		printf(":%d", pkt->dst_port);
	printf("  len=%u\n", pkt->total_len);
	
	if (pkt->data_len > 0 && pkt->data_len <= 128) {
		// 只显示前 128 字节的 hex dump
		print_hex_dump(pkt->data, pkt->data_len > 128 ? 128 : pkt->data_len);
	}
	
	// 写入 PCAP 文件
	if (hctx->pcap_file && pkt->data_len > 0) {
		// 在用户态获取真实时间戳
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		
		struct pcap_packet_header ph = {
			.ts_sec = (__u32)ts.tv_sec,
			.ts_usec = (__u32)(ts.tv_nsec / 1000),  // 纳秒转微秒
			.incl_len = pkt->data_len,  // 实际捕获长度
			.orig_len = pkt->total_len  // 原始包长度（Wire length）
		};
		
		// 写入数据包头
		if (fwrite(&ph, sizeof(ph), 1, hctx->pcap_file) != 1) {
			fprintf(stderr, "Failed to write pcap packet header\n");
			return -1;
		}
		
		// 写入数据包内容
		if (fwrite(pkt->data, pkt->data_len, 1, hctx->pcap_file) != 1) {
			fprintf(stderr, "Failed to write pcap packet data\n");
			return -1;
		}
		
		// 立即刷新到磁盘
		fflush(hctx->pcap_file);
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
	int watchdog_fd;
	FILE *pcap_file = NULL;
	unsigned long packet_count = 0;
	struct handler_ctx hctx = {0};
	
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <interface> [output.pcap]\n", argv[0]);
		fprintf(stderr, "Example: %s eth0\n", argv[0]);
		fprintf(stderr, "Example: %s eth0 capture.pcap\n", argv[0]);
		return 1;
	}
	
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Invalid interface: %s\n", argv[1]);
		return 1;
	}
	
	// 如果指定了输出文件，打开并写入 PCAP 文件头
	if (argc == 3) {
		pcap_file = fopen(argv[2], "wb");
		if (!pcap_file) {
			fprintf(stderr, "Failed to open output file: %s\n", argv[2]);
			return 1;
		}
		
		// 写入 PCAP 文件头
		struct pcap_file_header fh = {
			.magic = 0xa1b2c3d4,
			.version_major = 2,
			.version_minor = 4,
			.thiszone = 0,
			.sigfigs = 0,
			.snaplen = 65535,
			.linktype = 1  // DLT_EN10MB (Ethernet)
		};
		
		if (fwrite(&fh, sizeof(fh), 1, pcap_file) != 1) {
			fprintf(stderr, "Failed to write pcap file header\n");
			fclose(pcap_file);
			return 1;
		}
		fflush(pcap_file);
		
		fprintf(stderr, "Writing packets to: %s\n", argv[2]);
	}
	
	// 设置回调上下文
	hctx.pcap_file = pcap_file;
	hctx.packet_count = &packet_count;
	
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

	// 配置 RateLimit：load 之前设置 const 全局变量
	BPF_RATELIMIT_SET(skel, 1, 100);
	fprintf(stderr, "RateLimit configured: interval=1 s, burst=100 pkts/s\n");

	err = pktcap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "BPF program loaded\n");

	// 获取 watchdog map fd
	watchdog_fd = bpf_map__fd(skel->maps.plux_watchdog);
	if (watchdog_fd < 0) {
		fprintf(stderr, "Failed to get watchdog map fd\n");
		goto cleanup;
	}
	
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
	
	// Attach 前清理 ingress：删除旧的 plux_packet_capture 程序（priority 5）
	fprintf(stderr, "Cleaning up old ingress filter at priority 5...\n");
	
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, old_opts_ingress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = 0,
			    .prog_id = 0,
			    .flags = 0);
	
	err = bpf_tc_query(&tc_hook_ingress, &old_opts_ingress);
	if (err == 0) {
		fprintf(stderr, "  -> Found old ingress filter (handle=%u, prog_id=%u)\n", 
		       old_opts_ingress.handle, old_opts_ingress.prog_id);
		
		old_opts_ingress.prog_fd = 0;
		old_opts_ingress.prog_id = 0;
		old_opts_ingress.flags = 0;
		
		err = bpf_tc_detach(&tc_hook_ingress, &old_opts_ingress);
		if (err == 0) {
			fprintf(stderr, "  -> Removed successfully\n");
		} else {
			fprintf(stderr, "  -> Failed to remove: %d (continuing anyway)\n", err);
		}
	} else {
		fprintf(stderr, "  -> No old ingress filter with handle 1 found (err=%d)\n", err);
		err = bpf_tc_detach(&tc_hook_ingress, &old_opts_ingress);
		if (err == 0) {
			fprintf(stderr, "  -> Detached handle 1 successfully (blind detach)\n");
		} else if (err != -ENOENT) {
			fprintf(stderr, "  -> Failed to detach handle 1: %d\n", err);
		}
	}
	
	// 设置 TC opts (ingress)
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.plux_packet_capture));
	
	// Attach 程序到 TC ingress
	err = bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress);
	if (err) {
		fprintf(stderr, "Failed to attach TC ingress: %d\n", err);
		goto cleanup_detach;
	}
	fprintf(stderr, "Attached to ingress (priority: 5, handle: 0x1)\n");
	
	// 设置 TC hook (egress)
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress,
			    .ifindex = ifindex,
			    .attach_point = BPF_TC_EGRESS);
	
	// 创建 egress qdisc (如果不存在)
	err = bpf_tc_hook_create(&tc_hook_egress);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC egress hook: %d\n", err);
		goto cleanup_detach;
	}
	
	// Attach 前清理 egress：删除旧的 plux_packet_capture 程序（priority 5）
	fprintf(stderr, "Cleaning up old egress filter at priority 5...\n");
	
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, old_opts_egress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = 0,
			    .prog_id = 0,
			    .flags = 0);
	
	err = bpf_tc_query(&tc_hook_egress, &old_opts_egress);
	if (err == 0) {
		fprintf(stderr, "  -> Found old egress filter (handle=%u, prog_id=%u)\n", 
		       old_opts_egress.handle, old_opts_egress.prog_id);
		
		old_opts_egress.prog_fd = 0;
		old_opts_egress.prog_id = 0;
		old_opts_egress.flags = 0;
		
		err = bpf_tc_detach(&tc_hook_egress, &old_opts_egress);
		if (err == 0) {
			fprintf(stderr, "  -> Removed successfully\n");
		} else {
			fprintf(stderr, "  -> Failed to remove: %d (continuing anyway)\n", err);
		}
	} else {
		fprintf(stderr, "  -> No old egress filter with handle 1 found (err=%d)\n", err);
		err = bpf_tc_detach(&tc_hook_egress, &old_opts_egress);
		if (err == 0) {
			fprintf(stderr, "  -> Detached handle 1 successfully (blind detach)\n");
		} else if (err != -ENOENT) {
			fprintf(stderr, "  -> Failed to detach handle 1: %d\n", err);
		}
	}
	
	// 设置 TC opts (egress)
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress,
			    .handle = 1,
			    .priority = 5,
			    .prog_fd = bpf_program__fd(skel->progs.plux_packet_capture));
	
	// Attach 程序到 TC egress
	err = bpf_tc_attach(&tc_hook_egress, &tc_opts_egress);
	if (err) {
		fprintf(stderr, "Failed to attach TC egress: %d\n", err);
		goto cleanup_detach;
	}
	fprintf(stderr, "Attached to egress (priority: 5, handle: 0x1)\n");
	
	rb = ring_buffer__new(bpf_map__fd(skel->maps.packets), handle_packet, &hctx, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_detach;
	}
	
	printf("\n");
	printf("=======================================================\n");
	printf("Capturing packets on %s (up to %d bytes per packet)\n", argv[1], CAPTURE_LEN);
	if (pcap_file) {
		printf("Saving to: %s\n", argv[2]);
	}
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n");
	
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);
	signal(SIGHUP, sig_int);
	
	// 初始化心跳
	__u32 key = 0;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	__u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	if (bpf_map_update_elem(watchdog_fd, &key, &now, BPF_ANY) < 0) {
		fprintf(stderr, "Failed to initialize watchdog\n");
		goto cleanup_detach;
	}
	fprintf(stderr, "Watchdog initialized (timeout: 30s, update interval: 1s)\n");
	
	// 主循环：轮询 ringbuf 并更新心跳
	int poll_count = 0;
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);  // 100ms 超时
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		
		// 每 10 次轮询（约 1 秒）更新一次心跳
		poll_count++;
		if (poll_count >= 10) {
			poll_count = 0;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
			if (bpf_map_update_elem(watchdog_fd, &key, &now, BPF_ANY) < 0) {
				fprintf(stderr, "Failed to update watchdog\n");
				exiting = 1;
				break;
			}
		}
	}
	
	printf("\n\nDetaching...\n");

cleanup_detach:
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
	if (pcap_file) {
		fclose(pcap_file);
		printf("PCAP file saved: %s (%lu packets)\n", argv[2], packet_count);
	}
	ring_buffer__free(rb);
	pktcap_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}
