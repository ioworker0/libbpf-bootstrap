// SPDX-License-Identifier: GPL-2.0
// FILE 1: loopback-sockops.bpf.c
// This program DEFINES the sockhash map and POPULATES it.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define INADDR_LOOPBACK 0x7f000001 // 127.0.0.1

char LICENSE[] SEC("license") = "GPL";

struct sock_key {
    __u64 netns_cookie;
    __u32 sport;
    __u32 dport;
};

// This is the "master" map definition. It will be created by this program.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 4096);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_map SEC(".maps");

static __always_inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    if (skops->remote_ip4 != skops->local_ip4 || skops->local_ip4 != bpf_htonl(INADDR_LOOPBACK))
        return;
    if (skops->family != AF_INET)
        return;

    __u64 netns_cookie = bpf_get_netns_cookie(skops);
    if (netns_cookie == 0)
    	return;

    struct sock_key key = {
        .netns_cookie = netns_cookie,
        .sport = bpf_htonl(skops->local_port),
        .dport = skops->remote_port,
    };
    int ret = bpf_sock_hash_update(skops, &sock_map, &key, BPF_ANY);

    #ifdef DEBUG
    // New, more descriptive logging
    __u64 ports = ((__u64) bpf_ntohl(skops->local_port) << 32) | skops->remote_port;
    char fmt[] = "bypass-log: loc=sockops-UPDATE, ret=%d, netns=%llu, ports(s:d)=%llx\n";
    bpf_trace_printk(fmt, sizeof(fmt), ret, netns_cookie, ports);
    #endif
}

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_ops_ipv4(skops);
            break;
        default:
            break;
    }
    return 0;
}
