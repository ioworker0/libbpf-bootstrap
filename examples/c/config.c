/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"
#include "cJSON.h"

/* Initialize configuration with default values */
void init_plugin_config(struct plugin_config *config)
{
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(*config));

    config->heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL;
    config->debug_mode = false;

    /* socket_path and plugin_name will remain empty until set */
}

/* Parse command line arguments --config "json_string" */
int parse_config_args(int argc, char *argv[], struct plugin_config *config)
{
    const char *config_str = NULL;
    cJSON *json = NULL;
    cJSON *item = NULL;

    if (!config) {
        return -1;
    }

    /* Look for --config argument */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_str = argv[i + 1];
            break;
        }
    }

    if (!config_str) {
        /* No config provided, that's okay */
        return 0;
    }

    /* Debug: print received config string with escaped characters visible */
    fprintf(stderr, "Received config string: [%s]\n", config_str);
    fprintf(stderr, "String length: %zu\n", strlen(config_str));
    fprintf(stderr, "First few bytes (hex): ");
    for (size_t i = 0; i < (strlen(config_str) < 20 ? strlen(config_str) : 20); i++) {
        fprintf(stderr, "%02x ", (unsigned char)config_str[i]);
    }
    fprintf(stderr, "\n");

    /* Parse JSON using cJSON */
    json = cJSON_Parse(config_str);
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        fprintf(stderr, "Failed to parse JSON config: %s\n", config_str);
        if (error_ptr) {
            fprintf(stderr, "JSON error before: %s\n", error_ptr);
        }
        fprintf(stderr, "\n=== USAGE HINT ===\n");
        fprintf(stderr, "Make sure to quote the JSON properly:\n");
        fprintf(stderr, "  Correct (single quotes, no escaping):\n");
        fprintf(stderr, "    --config '{\"socket_path\":\"/path/to/socket\"}'\n");
        fprintf(stderr, "  Correct (double quotes, with escaping):\n");
        fprintf(stderr, "    --config \"{\\\"socket_path\\\":\\\"/path/to/socket\\\"}\"\n");
        fprintf(stderr, "==================\n");
        return -1;
    }

    /* Extract socket_path */
    item = cJSON_GetObjectItem(json, "socket_path");
    if (item && cJSON_IsString(item) && item->valuestring) {
        strncpy(config->socket_path, item->valuestring, sizeof(config->socket_path) - 1);
        config->socket_path[sizeof(config->socket_path) - 1] = '\0';
    }

    /* Extract debug_mode */
    item = cJSON_GetObjectItem(json, "debug_mode");
    if (item && cJSON_IsTrue(item)) {
        config->debug_mode = true;
    } else if (item && cJSON_IsFalse(item)) {
        config->debug_mode = false;
    }

    /* Extract heartbeat_interval */
    item = cJSON_GetObjectItem(json, "heartbeat_interval");
    if (item && cJSON_IsNumber(item)) {
        config->heartbeat_interval = (int)item->valuedouble;
    }

    /* Extract plugin_name */
    item = cJSON_GetObjectItem(json, "plugin_name");
    if (item && cJSON_IsString(item) && item->valuestring) {
        strncpy(config->plugin_name, item->valuestring, sizeof(config->plugin_name) - 1);
        config->plugin_name[sizeof(config->plugin_name) - 1] = '\0';
    }

    cJSON_Delete(json);
    return 0;
}

/* Check if socket file exists and is accessible */
int check_socket_file(const char *socket_path)
{
    struct stat st;

    if (!socket_path || strlen(socket_path) == 0) {
        return -1;
    }

    if (stat(socket_path, &st) != 0) {
        return -1;
    }

    /* Check if it's a socket file */
    if (!S_ISSOCK(st.st_mode)) {
        return -1;
    }

    /* Check if we can access it */
    if (access(socket_path, R_OK | W_OK) != 0) {
        return -1;
    }

    return 0;
}