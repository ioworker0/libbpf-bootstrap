/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PLUX_CONFIG_H
#define __PLUX_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/* Configuration limits */
#define CONFIG_MAX_SOCKET_PATH    256
#define CONFIG_MAX_PLUGIN_NAME     64

/* Default values */
#define DEFAULT_HEARTBEAT_INTERVAL 5
#define DEFAULT_VERSION            "1.0.0"

/* Simple plugin configuration structure */
struct plugin_config {
    char socket_path[CONFIG_MAX_SOCKET_PATH];
    char plugin_name[CONFIG_MAX_PLUGIN_NAME];
    int heartbeat_interval;
    bool debug_mode;
};

/* Configuration management functions */

/* Initialize configuration with default values */
void init_plugin_config(struct plugin_config *config);

/* Parse command line arguments --config "json_string" */
int parse_config_args(int argc, char *argv[], struct plugin_config *config);

/* Check if socket file exists and is accessible */
int check_socket_file(const char *socket_path);

#endif /* __PLUX_CONFIG_H */