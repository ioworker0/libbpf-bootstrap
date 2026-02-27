// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ctype.h>
#include "pktcap.skel.h"
#include "plux/init.h"
#include "plux/btf.h"
#include "plux/user_watchdog.h"
#include "plux/tc.h"

#define CAPTURE_LEN 1500

// ====================================================================
// 数据结构定义
// ====================================================================

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

// PCAP Writer 上下文
struct pcap_writer {
	FILE   *file;
	unsigned long packet_count;
};

// BPF Event
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
	struct pcap_writer *pcap;
	unsigned long *packet_count;
};

// ====================================================================
// 函数声明
// ====================================================================

static const char *proto_name(__u8 proto);
static void print_hex_dump(const __u8 *data, __u16 len);
static int handle_packet(void *ctx, void *data, size_t len);

static struct pcap_writer *pcap_writer_open(const char *filename);
static int pcap_writer_write_packet(struct pcap_writer *w, const __u8 *data, __u32 len, __u32 orig_len);
static unsigned long pcap_writer_close(struct pcap_writer *w);

// ====================================================================
// main
// ====================================================================

int main(int argc, char **argv) {
	struct pktcap_bpf *skel;
	struct ring_buffer *rb;
	int ifindex, err;
	struct pcap_writer *pcap = NULL;
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

	// 如果指定了输出文件，打开 PCAP writer
	if (argc == 3) {
		pcap = pcap_writer_open(argv[2]);
		if (!pcap) {
			fprintf(stderr, "Failed to open PCAP writer: %s\n", argv[2]);
			return 1;
		}
	}

	// 设置回调上下文
	hctx.pcap = pcap;
	hctx.packet_count = &packet_count;

    // ------------------------------------------------
	// STEP 1
	plux_init();

    // STEP 2
	skel = PLUX_BTF_TRY_OPEN_BEFORE_LOAD(skel, pktcap);

	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// STEP 3
	// 配置 RateLimit：load 之前设置 const 全局变量
	skel->rodata->__bpf_ratelimit_interval = 1;
	skel->rodata->__bpf_ratelimit_burst = 100;
	fprintf(stderr, "RateLimit configured: interval=1 s, burst=100 pkts/s\n");

    // STEP 4
	err = pktcap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "BPF program loaded\n");

	// STEP 5
	// 获取 watchdog map fd 并启动 watchdog 线程
	err = plux_watchdog_start(bpf_map__fd(skel->maps.__plux_watchdog), 1);
	if (err) {
		fprintf(stderr, "Failed to start watchdog thread\n");
		goto cleanup;
	}

	// ================================================================
	// STEP 6 TC Ingress
	// ================================================================
	err = plux_tc_hook_create(ifindex, BPF_TC_INGRESS);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC ingress hook: %d\n", err);
		goto cleanup;
	}

    // STEP 7
	fprintf(stderr, "Cleaning up old ingress filter at priority %d...\n", PLUX_PKTCAP_PRIORITY);
	plux_tc_cleanup(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

    // STEP 8
	err = plux_tc_attach_prog(ifindex, BPF_TC_INGRESS,
				  bpf_program__fd(skel->progs.plux_packet_capture),
				  PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	if (err) {
		goto cleanup_detach;
	}

	// ================================================================
	// STEP 9 TC Egress
	// ================================================================
	err = plux_tc_hook_create(ifindex, BPF_TC_EGRESS);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC egress hook: %d\n", err);
		goto cleanup_detach;
	}

    // STEP 10
	fprintf(stderr, "Cleaning up old egress filter at priority %d...\n", PLUX_PKTCAP_PRIORITY);
	plux_tc_cleanup(ifindex, BPF_TC_EGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

    // STEP 11
	err = plux_tc_attach_prog(ifindex, BPF_TC_EGRESS,
				  bpf_program__fd(skel->progs.plux_packet_capture),
				  PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	if (err) {
		goto cleanup_detach;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.packets), handle_packet, &hctx, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup_detach;
	}

	printf("\n");
	printf("=======================================================\n");
	printf("Capturing packets on %s (up to %d bytes per packet)\n", argv[1], CAPTURE_LEN);
	if (pcap) {
		printf("Saving to: %s\n", argv[2]);
	}
	printf("Press Ctrl+C to stop\n");
	printf("=======================================================\n");

	// 主循环：轮询 ringbuf（watchdog 由独立线程处理）
	while (!plux_signal_should_exit()) {
		err = ring_buffer__poll(rb, 100);  // 100ms 超时
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	printf("\n\nDetaching...\n");

cleanup_detach:
	// Detach TC filters
	plux_tc_detach(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
	plux_tc_detach(ifindex, BPF_TC_EGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

cleanup:
	if (pcap) {
		unsigned long count = pcap_writer_close(pcap);
		printf("PCAP file saved: %s (%lu packets)\n", argv[2], count);
	}
	ring_buffer__free(rb);
	pktcap_bpf__destroy(skel);
	printf("Done.\n");
	return err ? 1 : 0;
}

// ====================================================================
// 辅助函数实现
// ====================================================================

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
	if (hctx->pcap && pkt->data_len > 0) {
		pcap_writer_write_packet(hctx->pcap, pkt->data, pkt->data_len, pkt->total_len);
	}

	return 0;
}

// ====================================================================
// PCAP Writer 实现
// ====================================================================

static struct pcap_writer *pcap_writer_open(const char *filename)
{
	struct pcap_writer *w = calloc(1, sizeof(*w));
	if (!w) {
		perror("calloc");
		return NULL;
	}

	w->file = fopen(filename, "wb");
	if (!w->file) {
		perror("fopen");
		free(w);
		return NULL;
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

	if (fwrite(&fh, sizeof(fh), 1, w->file) != 1) {
		fprintf(stderr, "Failed to write pcap file header\n");
		fclose(w->file);
		free(w);
		return NULL;
	}
	fflush(w->file);

	fprintf(stderr, "Writing packets to: %s\n", filename);
	return w;
}

static int pcap_writer_write_packet(struct pcap_writer *w, const __u8 *data, __u32 len, __u32 orig_len)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	struct pcap_packet_header ph = {
		.ts_sec = (__u32)ts.tv_sec,
		.ts_usec = (__u32)(ts.tv_nsec / 1000),  // 纳秒转微秒
		.incl_len = len,       // 实际捕获长度
		.orig_len = orig_len   // 原始包长度（Wire length）
	};

	// 写入数据包头
	if (fwrite(&ph, sizeof(ph), 1, w->file) != 1) {
		fprintf(stderr, "Failed to write pcap packet header\n");
		return -1;
	}

	// 写入数据包内容
	if (fwrite(data, len, 1, w->file) != 1) {
		fprintf(stderr, "Failed to write pcap packet data\n");
		return -1;
	}

	// 立即刷新到磁盘
	fflush(w->file);
	w->packet_count++;
	return 0;
}

static unsigned long pcap_writer_close(struct pcap_writer *w)
{
	unsigned long count = 0;

	if (w) {
		count = w->packet_count;
		if (w->file)
			fclose(w->file);
		free(w);
	}

	return count;
}
