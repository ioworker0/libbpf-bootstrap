//Tracing run queue latency higher than 9000 us for TID 1321791 on CPU 4...
//
//-------------------------------------------------------------------------------------------------------
//TIME     COMM             TID     LAT(ms)    SWITCHES     CPU SCHEDULING PATH
//08:17:39 a.out            1321791 9.587      0            [last  4] -> [woken  4] -> [ran  4]
//
//    INTERRUPTER_COMM     TID        ON_CPU_TIME(ms)   DAOKEAPPUK                                         ALERT
//    -------------------- ---------- ----------------- -------------------------------------------------- -----
//    dotnet               351993     10.569            jiesan.netcore.surprisegamepollapi                  !!!
//    migration/4          32         0.012             N/A
//    a.out                1321791    0.000             N/A
//
//-------------------------------------------------------------------------------------------------------
//TIME     COMM             TID     LAT(ms)    SWITCHES     CPU SCHEDULING PATH
//08:17:39 a.out            1321791 13.058     140          [last  4] -> [woken  4] -> [ran  4]
//
//    INTERRUPTER_COMM     TID        ON_CPU_TIME(ms)   DAOKEAPPUK                                         ALERT
//    -------------------- ---------- ----------------- -------------------------------------------------- -----
//    dotnet               351995     13.286            jiesan.netcore.surprisegamepollapi                  !!!
//    a.out                1321791    0.000             N/A
//
//-------------------------------------------------------------------------------------------------------
//TIME     COMM             TID     LAT(ms)    SWITCHES     CPU SCHEDULING PATH
//08:17:39 a.out            1321791 11.129     320          [last  4] -> [woken  4] -> [ran  4]
//
//    INTERRUPTER_COMM     TID        ON_CPU_TIME(ms)   DAOKEAPPUK                                         ALERT
//    -------------------- ---------- ----------------- -------------------------------------------------- -----
//    dotnet               351992     11.906            jiesan.netcore.surprisegamepollapi                  !!!
//    a.out                1321791    0.000             N/A
//
//-------------------------------------------------------------------------------------------------------
//TIME     COMM             TID     LAT(ms)    SWITCHES     CPU SCHEDULING PATH
//08:17:39 a.out            1321791 9.156      6            [last  4] -> [woken  4] -> [ran  4]
//
//    INTERRUPTER_COMM     TID        ON_CPU_TIME(ms)   DAOKEAPPUK                                         ALERT
//    -------------------- ---------- ----------------- -------------------------------------------------- -----
//    dotnet               351992     10.000            jiesan.netcore.surprisegamepollapi                  !!!
//    a.out                1321791    0.000             N/A
//
//-------------------------------------------------------------------------------------------------------
//TIME     COMM             TID     LAT(ms)    SWITCHES     CPU SCHEDULING PATH
//08:17:39 a.out            1321791 14.575     177          [last  4] -> [woken  4] -> [ran  4]
//
//    INTERRUPTER_COMM     TID        ON_CPU_TIME(ms)   DAOKEAPPUK                                         ALERT
//    -------------------- ---------- ----------------- -------------------------------------------------- -----
//    scanner              3933693    6.232             tcbase.phoenix.proxy.scanner                        !!!
//    java                 2114027    0.064             pbssuzhou.java.rc.feature.platfrom
//    scanner              3933693    4.541             tcbase.phoenix.proxy.scanner
//    ksoftirqd/4          33         0.021             N/A
//    java                 2114027    0.025             pbssuzhou.java.rc.feature.platfrom
//    scanner              3933693    0.665             tcbase.phoenix.proxy.scanner
//    java                 2114027    0.016             pbssuzhou.java.rc.feature.platfrom
//    scanner              3933693    0.422             tcbase.phoenix.proxy.scanner
//    java                 2114027    0.012             pbssuzhou.java.rc.feature.platfrom
//
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include "my_runqslower.skel.h"

#define TASK_COMM_LEN 16
#define MAX_INTERRUPTERS 16
#define DAOKEAPPUK_LEN 128

/* C struct to match the BPF's `struct switch_info`. */
struct switch_info {
	__u64 ts;
	pid_t pid;
};

/* C struct to match the BPF's `struct event`. */
struct event {
	__u64 delta_us;
	pid_t pid;
	int last_cpu;
	int wakeup_cpu;
	int on_cpu;
	__u64 final_ran_ts;
	__u32 intr_count;
	struct switch_info interrupters[MAX_INTERRUPTERS];
};

/* Struct to hold command-line arguments. */
static struct env {
	pid_t pid;
	pid_t tgid;
	int cpu;
	__u64 min_us;
	bool verbose;
} env = {
	.min_us = 10000,
	.cpu = -1,
};

static const char doc[] = "Trace high run queue latency for a specific task and show its CPU scheduling path.\n";
static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace a specific process ID (TGID)", 0 },
	{ "tid", 't', "TID", 0, "Trace a specific thread ID (PID)", 0 },
	{ "cpu", 'C', "CPU", 0, "Trace a specific CPU", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "min-latency", 'm', "MIN_US", 0, "Minimum run queue latency to trace (microseconds)"},
	{},
};

/* Parses a single command-line argument. */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'p': env.tgid = strtol(arg, NULL, 10); break;
	case 't': env.pid = strtol(arg, NULL, 10); break;
	case 'C': env.cpu = strtol(arg, NULL, 10); break;
	case 'm': env.min_us = strtoull(arg, NULL, 10); break;
	case ARGP_KEY_ARG: argp_usage(state); break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* libbpf callback for printing debug messages. */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

/* Signal handler for graceful exit. */
static void sig_handler(int sig) {
	exiting = true;
}

/* Struct to hold basic process information from /proc. */
struct proc_info {
	char comm[TASK_COMM_LEN + 1];
	unsigned long long nr_switches;
};

/* Reads task command name and total number of context switches from /proc. */
static int get_proc_info(pid_t pid, struct proc_info *info)
{
	char path[128];
	char line[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (!f) return -1;
	if (!fgets(info->comm, sizeof(info->comm), f)) {
		fclose(f);
		return -1;
	}
	info->comm[strcspn(info->comm, "\n")] = 0;
	fclose(f);

	snprintf(path, sizeof(path), "/proc/%d/sched", pid);
	f = fopen(path, "r");
	if (!f) return -1;

	info->nr_switches = 0;
	int found = 0;

	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "nr_switches") != NULL) {
			char *colon = strchr(line, ':');
			if (colon && sscanf(colon + 1, "%llu", &info->nr_switches) == 1) {
				found = 1;
				break;
			}
		}
	}
	fclose(f);
	if (!found) return -1;

	return 0;
}

/* Reads a task's command name from /proc/[tid]/comm. */
static void get_comm_by_tid(pid_t tid, char *comm_buf, size_t buf_size)
{
    char path[128];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", tid);
    f = fopen(path, "r");
    if (!f) {
        snprintf(comm_buf, buf_size, "<exited>");
        return;
    }
    if (!fgets(comm_buf, buf_size, f)) {
        snprintf(comm_buf, buf_size, "<unknown>");
    } else {
        comm_buf[strcspn(comm_buf, "\n")] = 0;
    }
    fclose(f);
}

/* Reads a specific environment variable for a TID from /proc/[tid]/environ. */
static void get_env_var_by_tid(pid_t tid, const char *var_name, char *val_buf, size_t buf_size)
{
    char path[128];
    char env_buf[8192];
    FILE *f;
    size_t var_name_len = strlen(var_name);

    snprintf(path, sizeof(path), "/proc/%d/environ", tid);
    f = fopen(path, "rb");
    if (!f) {
        snprintf(val_buf, buf_size, "N/A");
        return;
    }

    size_t bytes_read = fread(env_buf, 1, sizeof(env_buf) - 1, f);
    fclose(f);
    env_buf[bytes_read] = '\0';

    for (char *p = env_buf; p < env_buf + bytes_read; ) {
        if (strncmp(p, var_name, var_name_len) == 0 && p[var_name_len] == '=') {
            snprintf(val_buf, buf_size, "%s", p + var_name_len + 1);
            return;
        }
        p += strlen(p) + 1;
    }

    snprintf(val_buf, buf_size, "N/A");
}

static unsigned long long last_total_switches = 0;

/* Callback function for handling events from the BPF ring buffer. */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	struct proc_info current_info;
    const double DURATION_THRESHOLD = 2.0;

	if (get_proc_info(e->pid, &current_info) != 0) {
		return 0;
	}

	unsigned long long delta_switches = 0;
	if (last_total_switches > 0) {
		delta_switches = current_info.nr_switches - last_total_switches;
	}
	last_total_switches = current_info.nr_switches;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    int line_len = 8 + 1 + 16 + 1 + 7 + 1 + 10 + 1 + 12 + 1 + 45;
    for (int i=0; i < line_len; i++) printf("-");
    printf("\n");

    printf("%-8s %-16s %-7s %-10s %-12s %s\n", "TIME", "COMM", "TID", "LAT(ms)", "SWITCHES", "CPU SCHEDULING PATH");
	printf("%-8s %-16s %-7d %-10.3f %-12llu [last %2d] -> [woken %2d] -> [ran %2d]\n",
	       ts, current_info.comm, e->pid,
	       (double)e->delta_us / 1000.0,
	       delta_switches,
	       e->last_cpu, e->wakeup_cpu, e->on_cpu);

    if (e->intr_count > 0) {
        printf("\n    %-20s %-10s %-17s %-50s %s\n", "INTERRUPTER_COMM", "TID", "ON_CPU_TIME(ms)", "DAOKEAPPUK", "ALERT");
        printf("    %-20s %-10s %-17s %-50s %s\n", "--------------------", "----------", "-----------------", "--------------------------------------------------", "-----");
    }

	for (int i = 0; i < e->intr_count; i++) {
		int idx = e->intr_count - 1 - i;
		const struct switch_info *current = &e->interrupters[idx];

		unsigned long long next_event_ts;
		if (idx == 0) {
			next_event_ts = e->final_ran_ts;
		} else {
			next_event_ts = e->interrupters[idx - 1].ts;
		}

		double duration_ms = (double)(next_event_ts - current->ts) / 1000000.0;

        char interrupter_comm[TASK_COMM_LEN + 1];
        get_comm_by_tid(current->pid, interrupter_comm, sizeof(interrupter_comm));

        char daoke_app_uk[DAOKEAPPUK_LEN];
        get_env_var_by_tid(current->pid, "DAOKEAPPUK", daoke_app_uk, sizeof(daoke_app_uk));

		printf("    %-20s %-10d %-17.3f %-50.50s", interrupter_comm, current->pid, duration_ms, daoke_app_uk);

        if (duration_ms >= DURATION_THRESHOLD) {
            printf("  !!!");
        }
        printf("\n");
	}
    printf("\n");

	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	struct ring_buffer *rb = NULL;
	struct my_runqslower_bpf *skel;
	int err;
    const char *btf_path = "/tmp/vmlinux.btf";

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	libbpf_set_print(libbpf_print_fn);

	if (access(btf_path, R_OK) == 0) {
		printf("INFO: Found custom BTF at %s, using it.\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = my_runqslower_bpf__open_opts(&opts);
	} else {
		printf("INFO: Custom BTF %s not found. Letting libbpf find one automatically.\n", btf_path);
		skel = my_runqslower_bpf__open();
	}

	if (!skel) {
		fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->min_us = env.min_us;
	skel->rodata->targ_pid = env.pid;
	skel->rodata->targ_tgid = env.tgid;
	skel->rodata->targ_cpu = env.cpu;

	err = my_runqslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "ERROR: Failed to load BPF skeleton\n");
		goto cleanup;
	}
	err = my_runqslower_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "ERROR: Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ERROR: Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Tracing run queue latency higher than %llu us", env.min_us);
	if (env.pid) printf(" for TID %d", env.pid);
	if (env.tgid) printf(" for TGID %d", env.tgid);
	if (env.cpu != -1) printf(" on CPU %d", env.cpu);
	printf("...\n\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("ERROR: polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	my_runqslower_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}