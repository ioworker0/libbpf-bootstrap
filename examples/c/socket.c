/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include "socket.h"
#include "protocol.h"

/* Initialize socket protocol structure */
int init_socket_protocol(struct socket_protocol *sp, const struct plugin_config *config)
{
    if (!sp || !config) {
        return -1;
    }

    memset(sp, 0, sizeof(*sp));

    strncpy(sp->socket_path, config->socket_path, sizeof(sp->socket_path) - 1);
    strncpy(sp->plugin_name, config->plugin_name, sizeof(sp->plugin_name) - 1);

    sp->socket_fd = -1;
    sp->running = false;

    /* Initialize send mutex */
    if (pthread_mutex_init(&sp->send_mutex, NULL) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize send_mutex: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* Connect to Agent Unix socket */
int socket_connect(struct socket_protocol *sp)
{
    struct sockaddr_un addr;

    if (!sp || strlen(sp->socket_path) == 0) {
        return -1;
    }

    /* Create socket */
    sp->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sp->socket_fd < 0) {
        fprintf(stderr, "[ERROR] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    /* Setup address */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sp->socket_path, sizeof(addr.sun_path) - 1);

    /* Connect to socket */
    if (connect(sp->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[ERROR] connect() failed: %s\n", strerror(errno));
        close(sp->socket_fd);
        sp->socket_fd = -1;
        return -1;
    }

    return 0;
}

/* Disconnect from socket */
int socket_disconnect(struct socket_protocol *sp)
{
    if (!sp) {
        return -1;
    }

    if (sp->socket_fd >= 0) {
        close(sp->socket_fd);
        sp->socket_fd = -1;
    }

    /* Destroy send mutex */
    pthread_mutex_destroy(&sp->send_mutex);

    return 0;
}

/* Send raw message with frame header - 优化版：header+data 一次发送 */
int socket_send_raw_message(struct socket_protocol *sp, uint16_t msg_type, const char *data, uint32_t data_len)
{
    struct frame_header header;
    ssize_t sent;
    int ret = 0;

    if (!sp || sp->socket_fd < 0) {
        return -1;
    }

    /* Lock to ensure atomic send */
    pthread_mutex_lock(&sp->send_mutex);

    /* Pack header */
    pack_frame_header(&header, msg_type, data_len);

    /* 优化：使用 writev 一次性发送 header + data，减少系统调用 */
    if (data && data_len > 0) {
        struct iovec iov[2];
        iov[0].iov_base = &header;
        iov[0].iov_len = sizeof(header);
        iov[1].iov_base = (void *)data;
        iov[1].iov_len = data_len;
        
        sent = writev(sp->socket_fd, iov, 2);
        if (sent != (ssize_t)(sizeof(header) + data_len)) {
            fprintf(stderr, "[ERROR] writev failed: sent=%zd, expected=%zu, error=%s\n",
                    sent, sizeof(header) + data_len, strerror(errno));
            ret = -1;
        }
    } else {
        /* 无数据，只发送 header */
        sent = send(sp->socket_fd, &header, sizeof(header), 0);
        if (sent != sizeof(header)) {
            fprintf(stderr, "[ERROR] send header failed: %s\n", strerror(errno));
            ret = -1;
        }
    }

    pthread_mutex_unlock(&sp->send_mutex);
    return ret;
}

/* Send handshake message */
int socket_send_handshake(struct socket_protocol *sp)
{
    struct handshake_data handshake;
    char json_buf[512];
    int err;

    if (!sp) {
        return -1;
    }

    /* Prepare handshake data */
    memset(&handshake, 0, sizeof(handshake));
    strncpy(handshake.plugin_name, sp->plugin_name, sizeof(handshake.plugin_name) - 1);
    strncpy(handshake.version, "1.0.0", sizeof(handshake.version) - 1);

    /* Create JSON */
    err = create_handshake_json(&handshake, json_buf, sizeof(json_buf));
    if (err < 0) {
        fprintf(stderr, "[ERROR] Failed to create handshake JSON: %d\n", err);
        return err;
    }

    return socket_send_raw_message(sp, MSG_TYPE_HANDSHAKE, json_buf, strlen(json_buf));
}

/* Send heartbeat message */
int socket_send_heartbeat(struct socket_protocol *sp)
{
    struct heartbeat_data heartbeat;
    char json_buf[256];
    int err;

    if (!sp) {
        return -1;
    }

    /* Prepare heartbeat data */
    memset(&heartbeat, 0, sizeof(heartbeat));
    heartbeat.timestamp = time(NULL);
    strncpy(heartbeat.status, "running", sizeof(heartbeat.status) - 1);

    /* Create JSON */
    err = create_heartbeat_json(&heartbeat, json_buf, sizeof(json_buf));
    if (err < 0) {
        fprintf(stderr, "[ERROR] Failed to create heartbeat JSON: %d\n", err);
        return err;
    }

    return socket_send_raw_message(sp, MSG_TYPE_HEARTBEAT, json_buf, strlen(json_buf));
}


/* Heartbeat thread function */
static void *heartbeat_thread_func(void *arg)
{
    struct socket_protocol *sp = (struct socket_protocol *)arg;
    int heartbeat_interval = 5; /* default */
    int sleep_step_ms = 100;
    int sleep_steps;
    int i;
    struct timespec sleep_step;

    if (!sp) {
        return NULL;
    }

    sleep_steps = heartbeat_interval * 1000 / sleep_step_ms;
    sleep_step.tv_sec = 0;
    sleep_step.tv_nsec = sleep_step_ms * 1000 * 1000L;

    while (sp->running) {
        for (i = 0; i < sleep_steps && sp->running; i++) {
            nanosleep(&sleep_step, NULL);
        }

        if (!sp->running) {
            break;
        }

        if (socket_send_heartbeat(sp) < 0) {
            fprintf(stderr, "[ERROR] Failed to send heartbeat\n");
            /* Continue trying, don't exit thread */
        }
    }

    return NULL;
}

/* Start heartbeat thread */
int socket_start_heartbeat(struct socket_protocol *sp)
{
    if (!sp) {
        return -1;
    }

    if (sp->running) {
        return 0; /* Already running */
    }

    sp->running = true;

    if (pthread_create(&sp->heartbeat_thread, NULL, heartbeat_thread_func, sp) != 0) {
        fprintf(stderr, "[ERROR] pthread_create() failed: %s\n", strerror(errno));
        sp->running = false;
        return -1;
    }

    return 0;
}

/* Stop heartbeat thread */
int socket_stop_heartbeat(struct socket_protocol *sp)
{
    if (!sp) {
        return -1;
    }

    if (!sp->running) {
        return 0; /* Not running */
    }

    sp->running = false;

    /* Wait for thread to finish */
    pthread_join(sp->heartbeat_thread, NULL);

    return 0;
}

/* Check socket file accessibility */
int socket_check_file(const char *socket_path)
{
    return check_socket_file(socket_path);
}

/* Send event message */
int socket_send_event(struct socket_protocol *sp, const void *event_data, size_t data_len)
{
    if (!sp || !event_data || data_len == 0) {
        return -1;
    }

    return socket_send_raw_message(sp, MSG_TYPE_EVENTS, (const char *)event_data, data_len);
}

/* Send stacktrace message */
int socket_send_stacktrace(struct socket_protocol *sp, const struct stacktrace_data *stacktrace)
{
    char json_buf[16384];  // 大缓冲区以容纳堆栈地址数组
    int ret;

    if (!sp || !stacktrace) {
        return -1;
    }

    /* Create JSON */
    ret = create_stacktrace_json(stacktrace, json_buf, sizeof(json_buf));
    if (ret < 0) {
        fprintf(stderr, "[ERROR] Failed to create stacktrace JSON\n");
        return ret;
    }

    return socket_send_raw_message(sp, MSG_TYPE_STACKTRACE, json_buf, strlen(json_buf));
}

/* 5元组长度：src_ip 到 data 之前的字节数 */
#define PACKET_5TUPLE_SIZE  (offsetof(struct packet_data, data) - offsetof(struct packet_data, src_ip))

/* Send packet data message */
int socket_send_packet(struct socket_protocol *sp, const struct packet_data *packet)
{
    if (!sp || !packet) {
        return -1;
    }

    return socket_send_raw_message(sp, MSG_TYPE_PACKET,
                                   (const char *)&packet->src_ip,
                                   PACKET_5TUPLE_SIZE + packet->data_len);
}

/* Send packet data message - zero-copy version (writev with 3 iovecs) */
int socket_send_packet_zerocopy(struct socket_protocol *sp,
                                 uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t protocol, const uint8_t *data, uint32_t data_len)
{
    struct frame_header header;
    ssize_t sent;
    int ret = 0;

    if (!sp || sp->socket_fd < 0 || !data) {
        return -1;
    }

    /* 构造 5元组结构（在栈上，无需完整 packet_data） */
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t  protocol;
        uint8_t  reserved[3];
    } tuple = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .reserved = {0}
    };

    /* Lock to ensure atomic send */
    pthread_mutex_lock(&sp->send_mutex);

    /* Pack header: 5元组(16字节) + data */
    pack_frame_header(&header, MSG_TYPE_PACKET, sizeof(tuple) + data_len);

    /* 使用 writev 一次性发送 header + tuple + data，真正零拷贝 */
    struct iovec iov[3];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = &tuple;
    iov[1].iov_len = sizeof(tuple);
    iov[2].iov_base = (void *)data;  // 直接发送原始 packet 指针，无 memcpy
    iov[2].iov_len = data_len;

    sent = writev(sp->socket_fd, iov, 3);
    if (sent != (ssize_t)(sizeof(header) + sizeof(tuple) + data_len)) {
        fprintf(stderr, "[ERROR] writev failed: sent=%zd, expected=%zu, error=%s\n",
                sent, sizeof(header) + sizeof(tuple) + data_len, strerror(errno));
        ret = -1;
    }

    pthread_mutex_unlock(&sp->send_mutex);
    return ret;
}

/* Send log info message */
int socket_send_log_info(struct socket_protocol *sp, const char *message)
{
    if (!sp || !message) {
        return -1;
    }

    // 不发送 \0 终止符，Go 接收端基于长度处理字符串
    return socket_send_raw_message(sp, MSG_TYPE_LOGS_INFO, message, strlen(message));
}

/* Send log warn message */
int socket_send_log_warn(struct socket_protocol *sp, const char *message)
{
    if (!sp || !message) {
        return -1;
    }

    return socket_send_raw_message(sp, MSG_TYPE_LOGS_WARN, message, strlen(message));
}

/* Send log error message */
int socket_send_log_error(struct socket_protocol *sp, const char *message)
{
    if (!sp || !message) {
        return -1;
    }

    return socket_send_raw_message(sp, MSG_TYPE_LOGS_ERROR, message, strlen(message));
}
