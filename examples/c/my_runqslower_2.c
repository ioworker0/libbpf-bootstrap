// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// top
//top - 13:56:45 up 990 days, 18:28,  2 users,  load average: 25.08, 26.57, 25.24
//Tasks: 960 total,   2 running, 608 sleeping,   0 stopped,  16 zombie
//%Cpu(s): 34.0 us,  5.2 sy,  0.0 ni, 58.1 id,  0.0 wa,  0.0 hi,  2.8 si,  0.0 st
//
// $ ./my_runqslower -t 2219247  -m 5000
//TIME     COMM             PID     LATENCY      CPU SCHEDULING PATH
//05:52:50 a.out            2366488      6.431 ms   SCHED PATH: [last CPU 55] -> [woken on 49] -> [ran on 34]
//05:53:00 a.out            2366488      6.941 ms   SCHED PATH: [last CPU 51] -> [woken on 51] -> [ran on 51]
//05:53:02 a.out            2366488     11.541 ms   SCHED PATH: [last CPU 16] -> [woken on 16] -> [ran on 16]
//05:53:03 a.out            2366488      6.710 ms   SCHED PATH: [last CPU 54] -> [woken on 54] -> [ran on 54]
//05:53:03 a.out            2366488      6.737 ms   SCHED PATH: [last CPU 57] -> [woken on 57] -> [ran on 57]
//05:53:09 a.out            2366488      8.773 ms   SCHED PATH: [last CPU 27] -> [woken on 49] -> [ran on 50]
//05:53:18 a.out            2366488      8.675 ms   SCHED PATH: [last CPU  1] -> [woken on 49] -> [ran on 49]
//05:53:20 a.out            2366488      6.650 ms   SCHED PATH: [last CPU 51] -> [woken on 51] -> [ran on 40]
//05:53:30 a.out            2366488     10.579 ms   SCHED PATH: [last CPU 58] -> [woken on 49] -> [ran on 49]
//05:53:40 a.out            2366488      7.668 ms   SCHED PATH: [last CPU 17] -> [woken on 17] -> [ran on 17]
//05:53:44 a.out            2366488     11.211 ms   SCHED PATH: [last CPU 57] -> [woken on 49] -> [ran on 17]
//05:53:49 a.out            2366488      9.205 ms   SCHED PATH: [last CPU 59] -> [woken on 59] -> [ran on 59]
//05:53:52 a.out            2366488      8.512 ms   SCHED PATH: [last CPU 38] -> [woken on 49] -> [ran on 49]
//05:54:08 a.out            2366488      6.046 ms   SCHED PATH: [last CPU 49] -> [woken on 49] -> [ran on 49]
//05:54:10 a.out            2366488      5.186 ms   SCHED PATH: [last CPU 49] -> [woken on 49] -> [ran on 23]
//05:54:15 a.out            2366488      8.402 ms   SCHED PATH: [last CPU 59] -> [woken on 59] -> [ran on 59]
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

/* BPF event structure (must match the BPF program's definition) */
struct event {
	__u64 delta_us;
	pid_t pid;
	int last_cpu;
	int wakeup_cpu;
	int on_cpu;
};

/* Command-line arguments */
static struct env {
	pid_t pid;      // Target Thread ID (TID)
	pid_t tgid;     // Target Process ID (PID)
	__u64 min_us;   // Minimum latency to report (in microseconds)
	bool verbose;
} env = {
	.min_us = 10000,
};

static const char doc[] = "Trace high run queue latency for a specific task and show its CPU scheduling path.\n";
static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace a specific process ID (TGID)", 0 },
	{ "tid", 't', "TID", 0, "Trace a specific thread ID (PID)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "min-latency", 'm', "MIN_US", 0, "Minimum run queue latency to trace (microseconds)"},
	{},
};

/* Parses a single command-line argument */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'p': env.tgid = strtol(arg, NULL, 10); break;
	case 't': env.pid = strtol(arg, NULL, 10); break;
	case 'm': env.min_us = strtoull(arg, NULL, 10); break;
	case ARGP_KEY_ARG: argp_usage(state); break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* libbpf callback for printing debug messages */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

/* Signal handler for graceful exit */
static void sig_handler(int sig) {
	exiting = true;
}

/* Helper struct and function to read info from /proc */
struct proc_info {
	char comm[TASK_COMM_LEN + 1];
	unsigned long long nr_switches;
};

/*
 * Reads task command name and total number of context switches from /proc.
 */
static int get_proc_info(pid_t pid, struct proc_info *info)
{
	char path[128];
	char line[256];
	FILE *f;

	// Read command name from /proc/<pid>/comm
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (!f) return -1;
	if (!fgets(info->comm, sizeof(info->comm), f)) {
		fclose(f);
		return -1;
	}
	info->comm[strcspn(info->comm, "\n")] = 0; // Remove trailing newline
	fclose(f);

	// Read nr_switches from /proc/<pid>/sched
	snprintf(path, sizeof(path), "/proc/%d/sched", pid);
	f = fopen(path, "r");
	if (!f) return -1;

	info->nr_switches = 0;
	int found = 0;

	// Skip the first line (header)
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}

	// Parse subsequent lines to find nr_switches
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
	if (!found) return -1; // Return error if not found

	return 0;
}

/* Global state to store the last switch count for the traced TID */
static unsigned long long last_total_switches = 0;


/*
 * Callback function for handling events from the BPF ring buffer.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	struct proc_info current_info;

	// Fetch current process info from /proc
	if (get_proc_info(e->pid, &current_info) != 0) {
		// Process might have exited, skip this event
		return 0;
	}

	// Calculate the number of context switches since the last high-latency event
	unsigned long long delta_switches = 0;
	if (last_total_switches > 0) {
		delta_switches = current_info.nr_switches - last_total_switches;
	}
	last_total_switches = current_info.nr_switches;

	// Get current timestamp for printing
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// Print the final, formatted output
	printf("%-8s %-16s %-7d %-10.3f %-12llu SCHED PATH: [last %2d] -> [woken %2d] -> [ran %2d]\n",
	       ts, current_info.comm, e->pid,
	       (double)e->delta_us / 1000.0,
	       delta_switches,
	       e->last_cpu, e->wakeup_cpu, e->on_cpu);

	return 0;
}

int main(int argc, char **argv)
{
	const char *btf_path = "/tmp/vmlinux.btf";
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	struct ring_buffer *rb = NULL;
	struct my_runqslower_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;

	libbpf_set_print(libbpf_print_fn);

	// Open the BPF skeleton, using an external BTF file if available
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

	// Pass filters from user-space to the BPF program
	skel->rodata->min_us = env.min_us;
	skel->rodata->targ_pid = env.pid;
	skel->rodata->targ_tgid = env.tgid;

	// Load and attach BPF programs
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

	// Set up the ring buffer for receiving events
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ERROR: Failed to create ring buffer\n");
		goto cleanup;
	}

	// Print headers
	const char *pid_type = env.pid ? "TID" : (env.tgid ? "PID" : "ALL");
	int pid_val = env.pid ? env.pid : env.tgid;
	if (pid_val == 0) {
		printf("Tracing run queue latency higher than %llu us for ALL processes...\n", env.min_us);
	} else {
		printf("Tracing run queue latency higher than %llu us for %s %d...\n", env.min_us, pid_type, pid_val);
	}
	printf("%-8s %-16s %-7s %-10s %-12s %s\n", "TIME", "COMM", "TID", "LAT(ms)", "SWITCHES", "CPU SCHEDULING PATH");

	// Setup signal handler for clean exit
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Main event polling loop
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