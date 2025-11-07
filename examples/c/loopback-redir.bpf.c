// SPDX-License-Identifier: GPL-2.0
// FILE 2: loopback-redir.bpf.c
// This program REUSES the sockhash map created by the sockops program.

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

// This is a "dummy" map definition. It tells the compiler about the map's
// existence, but it will be replaced by the pinned map at load time.
// The name 'sock_map' MUST match the name in the sockops program.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 4096);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_map SEC(".maps");

SEC("sk_msg")
int bpf_redir_handler(struct sk_msg_md *msg)
{
    if (msg->remote_ip4 != msg->local_ip4 || msg->local_ip4 != bpf_htonl(INADDR_LOOPBACK))
        return SK_PASS;

    __u64 netns_cookie = bpf_get_netns_cookie(msg);
    if (netns_cookie == 0)
        return SK_PASS;

    // To find the peer socket, we must use the REVERSE 3-tuple as the key.
    struct sock_key key = {
        .netns_cookie = netns_cookie,
        .sport = msg->remote_port,
        .dport = bpf_htonl(msg->local_port),
    };
    long ret = bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);

    // New, more descriptive logging.
    // We log here regardless of the outcome to help with debugging.
    __u64 ports = ((__u64)bpf_ntohl(msg->local_port) << 32) | msg->remote_port;
    char fmt[] = "bypass-log: loc=redir-REDIRECT, ret=%d, netns=%llu, ports(s:d)=%llx\n";
    // sk_msg_md ports are in different byte order: local_port is host, remote_port is network
    bpf_trace_printk(fmt, sizeof(fmt), ret, netns_cookie, ports);

    // Always return SK_PASS.
    // The kernel will check msg->sk_redir to decide the final action.
    return SK_PASS;
}
