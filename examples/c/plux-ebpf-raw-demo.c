// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "plux-ebpf-raw-demo.skel.h"
#include "plux/btf.h"
#include "plux/init.h"
#include "cJSON.h"

#define PLUGIN_NAME "plux-ebpf-raw-demo"

struct demo_config {
	char socket_path[CONFIG_MAX_SOCKET_PATH];
	__u32 target_pid;
};

struct sample {
	__u32 pid;
};

static struct demo_config g_config;
static struct socket_protocol g_socket;
static bool g_agent_connected;
static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --config JSON\n\n"
		"Required config fields:\n"
		"  socket_path       Agent Unix socket path\n\n"
		"Plugin-specific fields:\n"
		"  target_pid        0 means no PID filter\n\n"
		"Example:\n"
		"  %s --config '{\"socket_path\":\"/tmp/plux.sock\",\"target_pid\":0}'\n",
		prog, prog);
}

static int parse_demo_config(int argc, char **argv, struct demo_config *config)
{
	const char *config_str = NULL;
	cJSON *json, *item;

	memset(config, 0, sizeof(*config));

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config") && i + 1 < argc) {
			config_str = argv[i + 1];
			i++;
		}
	}

	if (!config_str) {
		fprintf(stderr, "missing required argument: --config\n");
		usage(argv[0]);
		return -1;
	}

	json = cJSON_Parse(config_str);
	if (!json) {
		const char *err = cJSON_GetErrorPtr();

		fprintf(stderr, "failed to parse config JSON");
		if (err)
			fprintf(stderr, ": %s", err);
		fprintf(stderr, "\n");
		return -1;
	}

	item = cJSON_GetObjectItem(json, "socket_path");
	if (item && cJSON_IsString(item) && item->valuestring) {
		strncpy(config->socket_path, item->valuestring, sizeof(config->socket_path) - 1);
		config->socket_path[sizeof(config->socket_path) - 1] = '\0';
	}

	item = cJSON_GetObjectItem(json, "target_pid");
	if (item && cJSON_IsNumber(item))
		config->target_pid = (__u32)item->valuedouble;

	cJSON_Delete(json);

	if (config->socket_path[0] == '\0') {
		fprintf(stderr, "missing required config field: socket_path\n");
		return -1;
	}

	return 0;
}

static int init_agent_socket(void)
{
	int err;

	err = check_socket_file(g_config.socket_path);
	if (err < 0) {
		fprintf(stderr, "socket file is not accessible: %s\n", g_config.socket_path);
		return -1;
	}

	err = plux_agent_socket_init(&g_socket, g_config.socket_path, PLUGIN_NAME);
	if (err < 0)
		return err;

	g_agent_connected = true;
	return 0;
}

static void cleanup_agent_socket(void)
{
	if (!g_agent_connected)
		return;

	socket_stop_heartbeat(&g_socket);
	socket_disconnect(&g_socket);
	g_agent_connected = false;
}

static void handle_sample(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct sample *sample = data;
	char log[64];
	int len;

	(void)ctx;
	(void)cpu;
	(void)data_sz;

	len = snprintf(log, sizeof(log), "[%s] pid=%u", PLUGIN_NAME, sample->pid);
	if (len < 0 || len >= (int)sizeof(log))
		return;

	if (socket_send_log_info(&g_socket, log) < 0)
		fprintf(stderr, "failed to send log to Agent\n");
}

static void handle_lost_samples(void *ctx, int cpu, __u64 lost_cnt)
{
	(void)ctx;
	fprintf(stderr, "lost %llu samples on CPU %d\n", (unsigned long long)lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct plux_ebpf_raw_demo_bpf *skel = NULL;
	struct perf_buffer *pb = NULL;
	int err;

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		usage(argv[0]);
		return 0;
	}

	err = parse_demo_config(argc, argv, &g_config);
	if (err)
		return 1;

	plux_init();

	err = init_agent_socket();
	if (err < 0)
		return 1;

	skel = PLUX_BTF_TRY_OPEN_BEFORE_LOAD(skel, plux_ebpf_raw_demo);
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	if (skel->rodata)
		skel->rodata->target_pid = g_config.target_pid;

	err = plux_ebpf_raw_demo_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = plux_ebpf_raw_demo_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.samples), 64,
			      handle_sample, handle_lost_samples, NULL, NULL);
	if (!pb) {
		fprintf(stderr, "failed to create perf buffer: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	fprintf(stderr, "%s started, target_pid=%u\n", PLUGIN_NAME, g_config.target_pid);
	while (!plux_signal_should_exit()) {
		err = perf_buffer__poll(pb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "failed to poll perf buffer: %d\n", err);
			break;
		}
	}
	if (plux_signal_should_exit() && err >= 0)
		err = 0;

cleanup:
	perf_buffer__free(pb);
	plux_ebpf_raw_demo_bpf__destroy(skel);
	cleanup_agent_socket();
	return err < 0 ? -err : err;
}
