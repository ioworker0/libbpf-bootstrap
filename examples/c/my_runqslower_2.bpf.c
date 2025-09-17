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