// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Maximum number of interrupting tasks to report in a single event. */
#define MAX_INTERRUPTERS 16
/* Size of the circular buffer for storing switch events on the target CPU. */
#define SWITCH_LOG_SIZE 1024
/* Maximum number of switch events to trace back through when a high-latency event occurs. */
#define MAX_TRACEBACK 256

/* User-space configurable parameters, defined in the .rodata section. */
const volatile __u64 min_us = 10000;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile int targ_cpu = -1;

/* Stores information about a single sched_switch event. */
struct switch_info {
	u64 ts;
	pid_t pid;
};

/* A circular buffer, implemented as an array, to log the most recent sched_switch events. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SWITCH_LOG_SIZE);
	__type(key, u32);
	__type(value, struct switch_info);
} switch_log SEC(".maps");

/* A single-element array to store the current index of the switch_log circular buffer. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} switch_log_idx SEC(".maps");

/* Stores the context of a task between its wakeup and its subsequent scheduling. */
struct task_info {
	u64 wakeup_ts;
	int wakeup_cpu;
	int last_cpu;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct task_info);
	__uint(max_entries, 10240);
} task_ctx SEC(".maps");

/* The event structure sent from the kernel to user-space via the ring buffer. */
struct event {
	u64 delta_us;
	pid_t pid;
	int last_cpu;
	int wakeup_cpu;
	int on_cpu;
	u64 final_ran_ts; /* Timestamp when the target task finally ran. */
	u32 intr_count;
	struct switch_info interrupters[MAX_INTERRUPTERS];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");


/*
 * Inline helper to trace task enqueue events. It records the wakeup timestamp
 * and the CPU where the wakeup occurred.
 */
static __always_inline void trace_enqueue(struct task_struct *p)
{
	u32 pid, tgid;
	pid = BPF_CORE_READ(p, pid);
	tgid = BPF_CORE_READ(p, tgid);

	if (targ_tgid && targ_tgid != tgid) return;
	if (targ_pid && targ_pid != pid) return;

	struct task_info *info = bpf_map_lookup_elem(&task_ctx, &pid);
	if (!info) {
		return;
	}

	info->wakeup_ts = bpf_ktime_get_ns();
	info->wakeup_cpu = bpf_get_smp_processor_id();
}

/* Raw tracepoint handler for task wakeup events. */
SEC("raw_tracepoint/sched_wakeup")
void handle_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	trace_enqueue(p);
}

/* Raw tracepoint handler for newly created task wakeup events. */
SEC("raw_tracepoint/sched_wakeup_new")
void handle_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	trace_enqueue(p);
}

/*
 * Raw tracepoint handler for task scheduling events (context switches).
 * This is the main logic hub of the BPF program.
 */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *prev = (struct task_struct *)ctx->args[1];
	struct task_struct *next = (struct task_struct *)ctx->args[2];
	u32 prev_pid, prev_tgid, next_pid;
	u32 cpu = bpf_get_smp_processor_id();

	/* Filter out events on CPUs we are not targeting. */
	if (targ_cpu != -1 && cpu != targ_cpu) {
		return 0;
	}

	/* Part 1: Handle the task being switched OUT (prev). */
	prev_pid = BPF_CORE_READ(prev, pid);
	prev_tgid = BPF_CORE_READ(prev, tgid);
	if ((targ_tgid && targ_tgid == prev_tgid) || (targ_pid && targ_pid == prev_pid)) {
		struct task_info info = {};
		info.last_cpu = cpu;
		bpf_map_update_elem(&task_ctx, &prev_pid, &info, BPF_ANY);
	}

	/* Part 2: Continuously log all switch events on the target CPU. */
	u64 now = bpf_ktime_get_ns();
	next_pid = BPF_CORE_READ(next, pid);

	u32 zero = 0;
	u32 *idx_ptr = bpf_map_lookup_elem(&switch_log_idx, &zero);
	if (idx_ptr) {
		u32 idx = *idx_ptr;
		struct switch_info *log_entry = bpf_map_lookup_elem(&switch_log, &idx);
		if (log_entry) {
			log_entry->ts = now;
			log_entry->pid = next_pid;
		}
		*idx_ptr = (idx + 1) % SWITCH_LOG_SIZE;
	}

	/* Skip the idle thread. */
	if (next_pid == 0) {
		return 0;
	}

	/* Part 3: Handle the task being switched IN (next). */
	struct task_info *info = bpf_map_lookup_elem(&task_ctx, &next_pid);
	if (!info || info->wakeup_ts == 0) {
		return 0;
	}

	/* Calculate latency and check if it exceeds the user-defined threshold. */
	u64 wakeup_ts = info->wakeup_ts;
	u64 delta_us = (now - wakeup_ts) / 1000;

	if (delta_us < min_us) {
		bpf_map_delete_elem(&task_ctx, &next_pid);
		return 0;
	}

	/* Part 4: High latency detected. Prepare and send an event to user-space. */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	e->delta_us = delta_us;
	e->pid = next_pid;
	e->last_cpu = info->last_cpu;
	e->wakeup_cpu = info->wakeup_cpu;
	e->on_cpu = cpu;
	e->final_ran_ts = now;
	e->intr_count = 0;

	/* Part 5: Trace back through the switch log to find interrupting tasks. */
	if (idx_ptr) {
		#pragma unroll
		for (int i = 1; i < MAX_TRACEBACK; i++) {
			u32 read_idx = (*idx_ptr - i + SWITCH_LOG_SIZE) % SWITCH_LOG_SIZE;
			struct switch_info *log_entry = bpf_map_lookup_elem(&switch_log, &read_idx);

			if (log_entry) {
				/* Stop if we've filled our interrupters array. */
				if (e->intr_count >= MAX_INTERRUPTERS) {
					break;
				}

				/* Record the interrupter's info. */
				e->interrupters[e->intr_count].pid = log_entry->pid;
				e->interrupters[e->intr_count].ts = log_entry->ts;
				e->intr_count++;

				/*
				 * After recording, check if this entry is the one that was
				 * running when our target was woken up. If so, stop.
				 */
				if (log_entry->ts < wakeup_ts) {
					break;
				}
			}
		}
	}

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&task_ctx, &next_pid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";