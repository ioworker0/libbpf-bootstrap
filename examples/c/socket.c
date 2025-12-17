/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
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
        perror("socket");
        return -1;
    }

    /* Setup address */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sp->socket_path, sizeof(addr.sun_path) - 1);

    /* Connect to socket */
    if (connect(sp->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
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

    return 0;
}

/* Send raw message with frame header */
int socket_send_raw_message(struct socket_protocol *sp, uint16_t msg_type, const char *data, uint32_t data_len)
{
    struct frame_header header;
    ssize_t sent;

    if (!sp || sp->socket_fd < 0) {
        return -1;
    }

    /* Pack header */
    pack_frame_header(&header, msg_type, data_len);

    /* Send header */
    sent = send(sp->socket_fd, &header, sizeof(header), 0);
    if (sent != sizeof(header)) {
        perror("send header");
        return -1;
    }

    /* Send data if any */
    if (data && data_len > 0) {
        sent = send(sp->socket_fd, data, data_len, 0);
        if (sent != (ssize_t)data_len) {
            perror("send data");
            return -1;
        }
    }

    return 0;
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
        fprintf(stderr, "Failed to create handshake JSON: %d\n", err);
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
        fprintf(stderr, "Failed to create heartbeat JSON: %d\n", err);
        return err;
    }

    return socket_send_raw_message(sp, MSG_TYPE_HEARTBEAT, json_buf, strlen(json_buf));
}


/* Heartbeat thread function */
static void *heartbeat_thread_func(void *arg)
{
    struct socket_protocol *sp = (struct socket_protocol *)arg;
    int heartbeat_interval = 5; /* default */

    if (!sp) {
        return NULL;
    }

    while (sp->running) {
        sleep(heartbeat_interval);

        if (!sp->running) {
            break;
        }

        if (socket_send_heartbeat(sp) < 0) {
            fprintf(stderr, "Failed to send heartbeat\n");
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
        perror("pthread_create");
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

