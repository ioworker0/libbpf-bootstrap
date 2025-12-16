/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protocol.h"
#include "cJSON.h"

/* Create handshake JSON */
int create_handshake_json(const struct handshake_data *data, char *json_buf, size_t buf_size)
{
    cJSON *json = NULL;
    char *json_str = NULL;
    int ret = -1;

    if (!data || !json_buf || buf_size == 0) {
        return -1;
    }

    /* Create JSON object */
    json = cJSON_CreateObject();
    if (!json) {
        return -1;
    }

    /* Add fields */
    cJSON_AddStringToObject(json, "plugin_name", data->plugin_name);
    cJSON_AddStringToObject(json, "version", data->version);
    cJSON_AddNullToObject(json, "capabilities");

    /* Print JSON to string */
    json_str = cJSON_PrintUnformatted(json);
    if (!json_str) {
        goto cleanup;
    }

    /* Copy to output buffer */
    if (strlen(json_str) >= buf_size) {
        goto cleanup;
    }

    strcpy(json_buf, json_str);
    ret = 0;

cleanup:
    if (json_str) {
        free(json_str);
    }
    if (json) {
        cJSON_Delete(json);
    }

    return ret;
}

/* Create heartbeat JSON */
int create_heartbeat_json(const struct heartbeat_data *data, char *json_buf, size_t buf_size)
{
    cJSON *json = NULL;
    char *json_str = NULL;
    int ret = -1;

    if (!data || !json_buf || buf_size == 0) {
        return -1;
    }

    /* Create JSON object */
    json = cJSON_CreateObject();
    if (!json) {
        return -1;
    }

    /* Add fields */
    cJSON_AddNumberToObject(json, "timestamp", (double)data->timestamp);
    cJSON_AddStringToObject(json, "status", data->status);

    /* Print JSON to string */
    json_str = cJSON_PrintUnformatted(json);
    if (!json_str) {
        goto cleanup;
    }

    /* Copy to output buffer */
    if (strlen(json_str) >= buf_size) {
        goto cleanup;
    }

    strcpy(json_buf, json_str);
    ret = 0;

cleanup:
    if (json_str) {
        free(json_str);
    }
    if (json) {
        cJSON_Delete(json);
    }

    return ret;
}