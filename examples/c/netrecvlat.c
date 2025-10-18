// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h> // for bpf_map_update_elem declaration

// Provide user-space copy of struct bpf_ratelimit so skeleton's static_assert succeeds.
#ifndef __USR_BPF_RATELIMIT_DEF
#define __USR_BPF_RATELIMIT_DEF
struct bpf_ratelimit {
    uint64_t interval;
    uint64_t begin;
    uint64_t burst;
    uint64_t max_burst;
    uint64_t events;
    uint64_t nmissed;
    uint64_t total_events;
    uint64_t total_nmissed;
    uint64_t total_interval;
};
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <linux/sockios.h>
#include "netrecvlat.skel.h"

static volatile bool exiting = false;
static int ts_sock_fd = -1; // dummy socket to enable RX SW timestamping

static void sig_handler(int sig) { exiting = true; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
	return vfprintf(stderr, fmt, args);
}

struct perf_event_t {
	char comm[16];
	__u64 latency;
	__u64 tgid_pid;
	__u64 pkt_len;
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
	__u32 seq;
	__u32 ack_seq;
	__u8 state;
	__u8 where;
};

/* TCP state values (from include/net/tcp_states.h). We only care about ESTABLISHED. */
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif

/* Indexed by skc_state (same order as provided). */
static const char *tcp_state_name[] = {
	"<nil>",        // 0
	"ESTABLISHED",  // 1
	"SYN_SENT",     // 2
	"SYN_RECV",     // 3
	"FIN_WAIT1",    // 4
	"FIN_WAIT2",    // 5
	"TIME_WAIT",    // 6
	"CLOSE",        // 7
	"CLOSE_WAIT",   // 8
	"LAST_ACK",     // 9
	"LISTEN",       // 10
	"CLOSING",      // 11
	"NEW_SYN_RECV", // 12
};

static void print_event(const struct perf_event_t *e) {
	const char *stage;
	switch (e->where) {
	case 0: stage = "netif"; break;
	case 1: stage = "tcp_v4_rcv"; break;
	case 2: stage = "user_copy"; break;
	default: stage = "unknown"; break;
	}
	const char *st = "UNK";
	if (e->state < (sizeof(tcp_state_name)/sizeof(tcp_state_name[0])))
		st = tcp_state_name[e->state];
	if (e->where == 2) { // TO_USER_COPY
		__u32 tgid = e->tgid_pid >> 32;
		__u32 pid  = e->tgid_pid & 0xffffffff;
		printf("%-12s %-16s tgid=%u pid=%u lat=%llu ms len=%u sport=%u dport=%u state=%s seq=%u ack=%u\n",
		       stage, e->comm, tgid, pid, (unsigned long long)(e->latency/1000000ULL),
		       (unsigned)e->pkt_len, ntohs(e->sport), ntohs(e->dport), st,
		       e->seq, e->ack_seq);
	} else {
		printf("%-12s %-16s tgid=  pid=   lat=%llu ms len=%u sport=%u dport=%u state=%s seq=%u ack=%u\n",
		       stage, "", (unsigned long long)(e->latency/1000000ULL),
		       (unsigned)e->pkt_len, ntohs(e->sport), ntohs(e->dport), st,
		       e->seq, e->ack_seq);
	}
}

// Adjust perf buffer sample callback signature (void, includes cpu & size)
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    const struct perf_event_t *e = data;
    if (size < sizeof(*e))
        return; // size mismatch safeguard
    // Filter: keep only ESTABLISHED or unknown (0) states.
    if (e->state != 0 && e->state != TCP_ESTABLISHED)
        return; // drop silently
    print_event(e);
}

/* Estimate offset between CLOCK_MONOTONIC and CLOCK_REALTIME (ns) */
static int64_t est_mono_wall_offset_ns(void)
{
	struct timespec t1, t2, t3;
	int64_t best_delta = 0;
	int64_t offset = 0;
	for (int i = 0; i < 10; i++) {
		if (clock_gettime(CLOCK_REALTIME, &t1) != 0)
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &t2) != 0)
			return 0;
		if (clock_gettime(CLOCK_REALTIME, &t3) != 0)
			return 0;
		int64_t n1 = (int64_t)t1.tv_sec * 1000000000LL + t1.tv_nsec;
		int64_t n2 = (int64_t)t2.tv_sec * 1000000000LL + t2.tv_nsec;
		int64_t n3 = (int64_t)t3.tv_sec * 1000000000LL + t3.tv_nsec;
		int64_t delta = n3 - n1; // window size
		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			offset = ((n3 + n1) / 2) - n2; // midpoint real - mono
		}
	}
	return offset;
}

static void update_offset_map(struct netrecvlat_bpf *skel)
{
	__u32 key = 0;
	int64_t off = est_mono_wall_offset_ns();
	if (off == 0) return;
	int map_fd = bpf_map__fd(skel->maps.mono_wall_offset_map);
	if (map_fd < 0) return;
	if (bpf_map_update_elem(map_fd, &key, &off, BPF_ANY) != 0) {
		static int warned = 0;
		if (!warned) {
			fprintf(stderr, "WARN: failed to update mono_wall_offset_map: %s\n", strerror(errno));
			warned = 1;
		}
	}
}

static int enable_rx_sw_timestamping(void) {
    /* If user sets NETRECVLAT_NO_SOCK, skip creating helper socket */
    const char *skip = getenv("NETRECVLAT_NO_SOCK");
    if (skip && *skip) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    /* Request only RX software timestamping (system-wide enabling for skb->tstamp) */
    int flags = SOF_TIMESTAMPING_RX_SOFTWARE;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        perror("setsockopt SO_TIMESTAMPING");
        close(fd);
        return -1;
    }
    /* Bind to ephemeral localhost port so socket is valid */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // ephemeral
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        // Not fatal for tracing, continue
    }
    ts_sock_fd = fd;
    return 0;
}

int main(int argc, char **argv)
{
	const char *btf_path = "/tmp/vmlinux.btf"; // optional custom BTF
	struct netrecvlat_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	if (access(btf_path, R_OK) == 0) {
		printf("INFO: Using custom BTF %s\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = netrecvlat_bpf__open_opts(&opts);
	} else {
		skel = netrecvlat_bpf__open();
	}
	if (!skel) {
		fprintf(stderr, "Failed to open skeleton\n");
		return 1;
	}

	// Optionally allow env overrides for thresholds
	const char *env_netif = getenv("NETRECVLAT_TO_NETIF_MS");
	const char *env_tcp   = getenv("NETRECVLAT_TO_TCPV4_MS");
	const char *env_user  = getenv("NETRECVLAT_TO_USER_MS");
	if (env_netif && env_netif[0]) skel->rodata->to_netif = strtoull(env_netif, NULL, 10) * 1000000ULL;
	if (env_tcp && env_tcp[0])   skel->rodata->to_tcpv4 = strtoull(env_tcp, NULL, 10) * 1000000ULL;
	if (env_user && env_user[0])  skel->rodata->to_user_copy = strtoull(env_user, NULL, 10) * 1000000ULL;

	err = netrecvlat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load skeleton: %d\n", err);
		goto cleanup;
	}
	err = netrecvlat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	// Initial offset map write
	update_offset_map(skel);
	long refresh_ms = 10; // default 10s
	const char *env_refresh = getenv("NETRECVLAT_OFFSET_REFRESH_MS");
	if (env_refresh && env_refresh[0]) {
		long v = strtol(env_refresh, NULL, 10);
		if (v > 0) refresh_ms = v;
	}
	struct timespec last_refresh;
	clock_gettime(CLOCK_MONOTONIC, &last_refresh);

	pb = perf_buffer__new(bpf_map__fd(skel->maps.netrecvlat_events), 64 /*pages*/, handle_event, NULL, NULL, NULL);
	if (!pb) {
		fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
		goto cleanup;
	}

	if (enable_rx_sw_timestamping() == 0) {
        fprintf(stderr, "INFO: RX software timestamping helper socket active (fd=%d)\n", ts_sock_fd);
    } else {
        fprintf(stderr, "WARN: Failed to enable RX software timestamping; skb->tstamp may be zero\n");
    }

	printf("Running... Press Ctrl+C to exit. Refresh interval %ld ms.\n", refresh_ms);
	while (!exiting) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "perf_buffer__poll failed: %d\n", err);
			break;
		}
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		int64_t elapsed_ms = (now.tv_sec - last_refresh.tv_sec) * 1000LL + (now.tv_nsec - last_refresh.tv_nsec) / 1000000LL;
		if (elapsed_ms >= refresh_ms) {
			update_offset_map(skel);
			last_refresh = now;
		}
	}

cleanup:
    if (ts_sock_fd >= 0) close(ts_sock_fd);
	perf_buffer__free(pb);
	netrecvlat_bpf__destroy(skel);
	return err != 0; }
