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

/* Create captrace event JSON */
int create_captrace_event_json(const struct captrace_event_data *data, char *json_buf, size_t buf_size)
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
    cJSON_AddNumberToObject(json, "pid", data->pid);
    cJSON_AddNumberToObject(json, "tid", data->tid);
    cJSON_AddNumberToObject(json, "cap", data->cap);
    cJSON_AddNumberToObject(json, "pid_ns_inum", (double)data->pid_ns_inum);
    cJSON_AddNumberToObject(json, "reaper_pid", data->reaper_pid);
    cJSON_AddNumberToObject(json, "net_ns_inum", (double)data->net_ns_inum);
    cJSON_AddStringToObject(json, "daokeappuk", data->daokeappuk);
    cJSON_AddStringToObject(json, "daokeenv", data->daokeenv);
    cJSON_AddStringToObject(json, "instanceid", data->instanceid);
    cJSON_AddStringToObject(json, "daokeip", data->daokeip);
    cJSON_AddStringToObject(json, "comm", data->comm);

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
    ret = strlen(json_buf);

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