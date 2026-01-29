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
    cJSON_AddNumberToObject(json, "cap", data->cap);
    cJSON_AddNumberToObject(json, "reaper_pid", data->reaper_pid);
    cJSON_AddStringToObject(json, "comm", data->comm);
    cJSON_AddStringToObject(json, "cmdline", data->cmdline);

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

/* Create stacktrace JSON */
int create_stacktrace_json(const struct stacktrace_data *data, char *json_buf, size_t buf_size)
{
    cJSON *json = NULL;
    cJSON *addresses_array = NULL;
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

    /* Add addresses array */
    addresses_array = cJSON_CreateArray();
    if (!addresses_array) {
        goto cleanup;
    }

    for (uint32_t i = 0; i < data->depth && i < MAX_STACK_DEPTH; i++) {
        /* 遇到 0 地址就停止，防止序列化无效数据 */
        if (data->addresses[i] == 0) {
            break;
        }
        
        char addr_str[32];
        snprintf(addr_str, sizeof(addr_str), "0x%lx", (unsigned long)data->addresses[i]);
        cJSON *addr_item = cJSON_CreateString(addr_str);
        if (!addr_item) {
            cJSON_Delete(addresses_array);
            goto cleanup;
        }
        cJSON_AddItemToArray(addresses_array, addr_item);
    }

    cJSON_AddItemToObject(json, "addresses", addresses_array);

    /* Add additional fields */
    cJSON_AddStringToObject(json, "comm", data->comm);
    cJSON_AddStringToObject(json, "cmdline", data->cmdline);
    cJSON_AddNumberToObject(json, "cap", data->cap);
    cJSON_AddNumberToObject(json, "reaper_pid", data->reaper_pid);

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

/* Create TCP drop stacktrace JSON */
int create_tcp_drop_stacktrace_json(const struct tcp_drop_stacktrace_data *data, char *json_buf, size_t buf_size)
{
    cJSON *json = NULL;
    cJSON *addresses_array = NULL;
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

    /* Add addresses array */
    addresses_array = cJSON_CreateArray();
    if (!addresses_array) {
        goto cleanup;
    }

    for (uint32_t i = 0; i < data->depth && i < MAX_STACK_DEPTH; i++) {
        /* 遇到 0 地址就停止，防止序列化无效数据 */
        if (data->addresses[i] == 0) {
            break;
        }
        
        char addr_str[32];
        snprintf(addr_str, sizeof(addr_str), "0x%lx", (unsigned long)data->addresses[i]);
        cJSON *addr_item = cJSON_CreateString(addr_str);
        if (!addr_item) {
            cJSON_Delete(addresses_array);
            goto cleanup;
        }
        cJSON_AddItemToArray(addresses_array, addr_item);
    }

    cJSON_AddItemToObject(json, "addresses", addresses_array);

    /* Add TCP drop specific fields */
    cJSON_AddNumberToObject(json, "timestamp", (double)data->timestamp);
    
    /* 将 IP 地址转换为字符串 */
    char saddr_str[16], daddr_str[16];
    snprintf(saddr_str, sizeof(saddr_str), "%u.%u.%u.%u",
             (data->saddr) & 0xFF,
             (data->saddr >> 8) & 0xFF,
             (data->saddr >> 16) & 0xFF,
             (data->saddr >> 24) & 0xFF);
    snprintf(daddr_str, sizeof(daddr_str), "%u.%u.%u.%u",
             (data->daddr) & 0xFF,
             (data->daddr >> 8) & 0xFF,
             (data->daddr >> 16) & 0xFF,
             (data->daddr >> 24) & 0xFF);
    
    cJSON_AddStringToObject(json, "saddr", saddr_str);
    cJSON_AddStringToObject(json, "daddr", daddr_str);
    cJSON_AddNumberToObject(json, "sport", data->sport);
    cJSON_AddNumberToObject(json, "dport", data->dport);
    cJSON_AddNumberToObject(json, "drop_reason", data->drop_reason);
    cJSON_AddNumberToObject(json, "tcp_state", data->tcp_state);
    cJSON_AddNumberToObject(json, "tcp_flags", data->tcp_flags);

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