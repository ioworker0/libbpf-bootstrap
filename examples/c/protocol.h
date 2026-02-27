/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PLUX_PROTOCOL_H
#define __PLUX_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

/* Protocol message types */
#define MSG_TYPE_HEARTBEAT  0x0001  /* 心跳包 */
#define MSG_TYPE_EVENTS     0x0003  /* 事件数据 */
#define MSG_TYPE_LOGS_INFO  0x0004  /* 信息日志 */
#define MSG_TYPE_LOGS_WARN  0x0005  /* 警告日志 */
#define MSG_TYPE_LOGS_ERROR 0x0006  /* 错误日志 */
#define MSG_TYPE_HANDSHAKE  0x0007  /* 握手确认 */
#define MSG_TYPE_STACKTRACE 0x0008  /* 堆栈跟踪 */
#define MSG_TYPE_PACKET     0x0009  /* 数据包捕获 */

/* Protocol frame format: [2 bytes: msg_type][4 bytes: data_len][N bytes: data] */
#define FRAME_HEADER_SIZE 6

/* Frame header structure */
struct frame_header {
    uint16_t msg_type;
    uint32_t data_len;
} __attribute__((packed));

/* Handshake data structure */
struct handshake_data {
    char plugin_name[64];
    char version[32];
};

/* Heartbeat data structure */
struct heartbeat_data {
    uint64_t timestamp;
    char status[32];  /* "running", "stopped", "error" */
};

/* Event data structure for captrace */
struct captrace_event_data {
    uint32_t cap;
    uint32_t reaper_pid;
    char comm[8];
    char cmdline[32];
};

/* Stacktrace data structure */
#define MAX_STACK_DEPTH 32  /* 减少到 32 层，覆盖 95%+ 实际场景，节省约 760 字节内存 */
struct stacktrace_data {
    uint32_t depth;  /* 实际堆栈深度 */
    uint64_t addresses[MAX_STACK_DEPTH];  /* 堆栈地址数组 */
    char comm[8];
    char cmdline[32];
    uint32_t cap;
    uint32_t reaper_pid;
};

/* TCP drop stacktrace data structure */
struct tcp_drop_stacktrace_data {
    uint64_t timestamp;       /* 时间戳 (ns) */
    uint32_t saddr;           /* 源 IP (IPv4) */
    uint32_t daddr;           /* 目标 IP (IPv4) */
    uint16_t sport;           /* 源端口 */
    uint16_t dport;           /* 目标端口 */
    uint32_t drop_reason;     /* 丢包原因 (0=不支持) */
    uint8_t tcp_state;        /* TCP 状态 */
    uint8_t tcp_flags;        /* TCP flags */
    uint32_t depth;           /* 堆栈深度 */
    uint64_t addresses[MAX_STACK_DEPTH];  /* 堆栈地址数组 */
};

/* Packet capture data structure */
#define PACKET_CAPTURE_LEN 1600
struct packet_data {
    uint32_t data_len;        /* 实际有效数据长度 */
    /* 5元组信息（固定位置） */
    uint32_t src_ip;          /* 源IP地址（网络字节序） */
    uint32_t dst_ip;          /* 目标IP地址（网络字节序） */
    uint16_t src_port;        /* 源端口（主机字节序） */
    uint16_t dst_port;        /* 目标端口（主机字节序） */
    uint8_t  protocol;        /* 协议（IPPROTO_TCP = 6） */
    uint8_t  reserved[3];     /* 对齐保留字段 */
    uint8_t  data[PACKET_CAPTURE_LEN];  /* 原始包数据（以太网帧） */
};

/* Pack frame header for sending */
static inline void pack_frame_header(struct frame_header *header, uint16_t msg_type, uint32_t data_len)
{
    header->msg_type = msg_type;
    header->data_len = data_len;
}

/* JSON serialization functions */
int create_handshake_json(const struct handshake_data *data, char *json_buf, size_t buf_size);
int create_heartbeat_json(const struct heartbeat_data *data, char *json_buf, size_t buf_size);
int create_captrace_event_json(const struct captrace_event_data *data, char *json_buf, size_t buf_size);
int create_stacktrace_json(const struct stacktrace_data *data, char *json_buf, size_t buf_size);
int create_tcp_drop_stacktrace_json(const struct tcp_drop_stacktrace_data *data, char *json_buf, size_t buf_size);

#endif /* __PLUX_PROTOCOL_H */