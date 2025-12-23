/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PLUX_SOCKET_H
#define __PLUX_SOCKET_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pthread.h>

#include "protocol.h"
#include "config.h"

/* Simple socket protocol structure */
struct socket_protocol {
    int socket_fd;
    char socket_path[CONFIG_MAX_SOCKET_PATH];
    char plugin_name[CONFIG_MAX_PLUGIN_NAME];

    /* Heartbeat thread */
    pthread_t heartbeat_thread;
    volatile bool running;

    /* Send mutex to protect concurrent socket writes */
    pthread_mutex_t send_mutex;
};

/* Socket protocol management functions */

/* Initialize socket protocol structure */
int init_socket_protocol(struct socket_protocol *sp, const struct plugin_config *config);

/* Connect to Agent Unix socket */
int socket_connect(struct socket_protocol *sp);

/* Disconnect from socket */
int socket_disconnect(struct socket_protocol *sp);

/* Send raw message with frame header */
int socket_send_raw_message(struct socket_protocol *sp, uint16_t msg_type, const char *data, uint32_t data_len);

/* Send handshake message */
int socket_send_handshake(struct socket_protocol *sp);

/* Send heartbeat message */
int socket_send_heartbeat(struct socket_protocol *sp);

/* Send event message */
int socket_send_event(struct socket_protocol *sp, const void *event_data, size_t data_len);

/* Send stacktrace message */
int socket_send_stacktrace(struct socket_protocol *sp, const struct stacktrace_data *stacktrace);

/* Send log messages */
int socket_send_log_info(struct socket_protocol *sp, const char *message);
int socket_send_log_warn(struct socket_protocol *sp, const char *message);
int socket_send_log_error(struct socket_protocol *sp, const char *message);

/* Start/stop heartbeat */
int socket_start_heartbeat(struct socket_protocol *sp);
int socket_stop_heartbeat(struct socket_protocol *sp);

/* Check socket file accessibility */
int socket_check_file(const char *socket_path);

#endif /* __PLUX_SOCKET_H */