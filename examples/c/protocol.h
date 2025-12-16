/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PLUX_PROTOCOL_H
#define __PLUX_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

/* Protocol message types */
#define MSG_TYPE_HANDSHAKE  0x0007  /* 握手确认 */
#define MSG_TYPE_HEARTBEAT  0x0001  /* 心跳包 */

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

/* Pack frame header for sending */
static inline void pack_frame_header(struct frame_header *header, uint16_t msg_type, uint32_t data_len)
{
    header->msg_type = msg_type;
    header->data_len = data_len;
}

/* JSON serialization functions */
int create_handshake_json(const struct handshake_data *data, char *json_buf, size_t buf_size);
int create_heartbeat_json(const struct heartbeat_data *data, char *json_buf, size_t buf_size);

#endif /* __PLUX_PROTOCOL_H */