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
    uint32_t pid;
    uint32_t tid;
    uint32_t cap;
    uint64_t pid_ns_inum;
    uint32_t reaper_pid;
    uint64_t net_ns_inum;
    char daokeappuk[128];
    char daokeenv[64];
    char instanceid[128];
    char daokeip[64];
    char comm[8];
    char cmdline[32];
};

/* Stacktrace data structure */
#define MAX_STACK_DEPTH 127
struct stacktrace_data {
    uint32_t depth;  /* 实际堆栈深度 */
    uint64_t addresses[MAX_STACK_DEPTH];  /* 堆栈地址数组 */
    char daokeappuk[128];
    char daokeenv[64];
    char instanceid[128];
    char daokeip[64];
    char comm[8];
    char cmdline[32];
    uint32_t cap;
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

#endif /* __PLUX_PROTOCOL_H */