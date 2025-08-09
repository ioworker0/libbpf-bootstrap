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
[root@wxyd-26-161-86 tmp1]# cat libbpf-bootstrap/examples/c/my_runqslower.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

/* User-space filters, configured via the .rodata section */
const volatile __u64 min_us = 10000;
const volatile pid_t targ_pid = 0; // Target Thread ID (PID in kernel terms)
const volatile pid_t targ_tgid = 0; // Target Process ID (TGID in kernel terms)

/*
 * BPF map to store the context of a task between a switch-out/wakeup
 * and its subsequent switch-in.
 * Key: TID (u32)
 * Value: A struct containing timestamps and CPU IDs.
 */
struct task_info {
	u64 wakeup_ts;   // Timestamp of when the task was woken up
	int wakeup_cpu;  // CPU where the wakeup occurred
	int last_cpu;    // CPU where the task last ran before this wakeup
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct task_info);
} task_ctx SEC(".maps");

/*
 * The event structure sent from kernel to user-space via the ring buffer.
 * It contains the final latency data and the scheduling path.
 */
struct event {
	u64 delta_us;
	pid_t pid;
	int last_cpu;
	int wakeup_cpu;
	int on_cpu;
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");


/*
 * Tracepoint handler for task wakeup events (e.g., I/O completion, timer).
 * This function records the wakeup timestamp and CPU.
 */
static __always_inline void trace_enqueue(struct task_struct *p)
{
	u32 pid, tgid;
	pid = BPF_CORE_READ(p, pid);
	tgid = BPF_CORE_READ(p, tgid);

	// Apply TID/PID filters from user-space.
	if (targ_tgid && targ_tgid != tgid) return;
	if (targ_pid && targ_pid != pid) return;

	// Find the existing context for this task, which should have been created
	// when it was last switched out. If it doesn't exist, we can't
	// reliably track this wakeup event.
	struct task_info *info = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!info) {
		return;
	}

	// Update the context with wakeup information.
	info->wakeup_ts = bpf_ktime_get_ns();
	info->wakeup_cpu = bpf_get_smp_processor_id();
}

SEC("raw_tracepoint/sched_wakeup")
void handle_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	trace_enqueue(p);
}

SEC("raw_tracepoint/sched_wakeup_new")
void handle_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	trace_enqueue(p);
}


/*
 * Tracepoint handler for task scheduling events (context switches).
 * This is the main logic hub.
 */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *prev = (struct task_struct *)ctx->args[1];
	struct task_struct *next = (struct task_struct *)ctx->args[2];
	u32 prev_pid, prev_tgid, next_pid;

	/* Part 1: Handle the task that is being switched OUT (prev) */
	prev_pid = BPF_CORE_READ(prev, pid);
	prev_tgid = BPF_CORE_READ(prev, tgid);

	// If the switched-out task is our target, create/update its context
	// with the CPU it last ran on.
	if ((targ_tgid && targ_tgid == prev_tgid) || (targ_pid && targ_pid == prev_pid)) {
		struct task_info info = {}; // Create a new info struct on the stack.
		info.last_cpu = bpf_get_smp_processor_id();
		// This update operation will create a new entry if one doesn't exist,
		// or overwrite an existing one. Overwriting is problematic if a wakeup
		// event occurred since the last switch-out, as it will clear
		// wakeup_ts and wakeup_cpu. A safer approach is lookup-then-update.
		bpf_map_update_elem(&task_ctx, &prev_pid, &info, BPF_ANY);
	}

	/* Part 2: Handle the task that is being switched IN (next) */
	next_pid = BPF_CORE_READ(next, pid);
	if (next_pid == 0) return 0; // Skip scheduler idle thread.

	// Look up the context for the incoming task.
	// If it doesn't exist, or if it hasn't been woken up yet (wakeup_ts is 0),
	// then we can't calculate latency for it.
	struct task_info *info = bpf_map_lookup_elem(&task_ctx, &next_pid);
	if (!info || info->wakeup_ts == 0)
		return 0;

	// Calculate latency.
	u64 delta_us = (bpf_ktime_get_ns() - info->wakeup_ts) / 1000;

	// Clean up the context map for this task regardless of latency,
	// as its "wait" cycle is now complete.
	if (delta_us < min_us) {
		bpf_map_delete_elem(&task_ctx, &next_pid);
		return 0;
	}

	/* Part 3: Latency is above threshold, send event to user-space */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;

	e->delta_us = delta_us;
	e->pid = next_pid;
	e->last_cpu = info->last_cpu;
	e->wakeup_cpu = info->wakeup_cpu;
	e->on_cpu = bpf_get_smp_processor_id();

	bpf_ringbuf_submit(e, 0);

	bpf_map_delete_elem(&task_ctx, &next_pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";