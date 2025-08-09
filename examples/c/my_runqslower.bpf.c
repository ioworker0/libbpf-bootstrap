// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN	 16
#define TASK_RUNNING	 0
#define KERN_STACK_DEPTH 127 // Standard max stack depth for BPF stack traces

/*
 * User-space filters.
 * These are configured by the user-space application via the .rodata section
 * before the BPF program is loaded into the kernel.
 */
const volatile char targ_comm[TASK_COMM_LEN] = {};
const volatile bool filter_comm = false;
const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile bool targ_prev_stack = false; // User-space flag to enable stack traces

/*
 * The event structure sent from kernel to user-space via the ring buffer.
 */
struct event {
	char task[TASK_COMM_LEN];
	char prev_task[TASK_COMM_LEN];
	__u64 delta_us;
	pid_t pid;
	pid_t prev_pid;
	int cpu;
	bool was_involuntarily_switched; // true if the task was preempted last time
	s32 prev_stack_id; // Kernel stack ID for the 'prev' task
};

/*
 * BPF map to store the timestamp when a task enters the run queue.
 * Key: PID (u32)
 * Value: Timestamp in nanoseconds (u64)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

/*
 * BPF map to store the last switch-out state of a task.
 * Key: PID (u32)
 * Value: boolean (true if the switch-out was involuntary)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, bool);
} last_ivcsw SEC(".maps");

/*
 * BPF ring buffer to send events to user-space efficiently.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10240);
} events SEC(".maps");

/*
 * BPF map to store kernel stack traces.
 * The key is a stack_id (u32) and the value is an array of instruction pointers.
 * The key and value sizes are explicitly defined for robustness.
 */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(u32));
	__uint(value_size, KERN_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

/*
 * A common inline function to record the enqueue timestamp for a given task.
 * It applies all user-specified filters before updating the map.
 */
static __always_inline int trace_enqueue(struct task_struct *p)
{
	u32 pid, tgid;
	pid = BPF_CORE_READ(p, pid);
	tgid = BPF_CORE_READ(p, tgid);

	// Apply user-specified filters.
	if (!pid)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;
	if (filter_comm) {
		char comm[TASK_COMM_LEN];
		BPF_CORE_READ_STR_INTO(&comm, p, comm);
		for (int i = 0; i < TASK_COMM_LEN; i++) {
			if (targ_comm[i] == '\0')
				break;
			if (targ_comm[i] != comm[i])
				return 0;
		}
	}

	// Record the current timestamp in the 'start' map.
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

/*
 * Attach to the sched_wakeup raw tracepoint.
 * This is triggered when a task is woken up and becomes runnable.
 */
SEC("raw_tracepoint/sched_wakeup")
int handle_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
	// The first argument to the sched_wakeup kernel function is the task_struct.
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	return trace_enqueue(p);
}

/*
 * Attach to the sched_wakeup_new raw tracepoint for newly created tasks.
 */
SEC("raw_tracepoint/sched_wakeup_new")
int handle_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx->args[0];
	return trace_enqueue(p);
}

/*
 * Attach to the sched_switch raw tracepoint.
 * This is where we calculate latency and gather all context.
 */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	u64 *tsp, delta_us;
	u32 next_pid, prev_pid;
	struct event *e;
	bool *was_ivcsw_ptr;
	bool was_ivcsw = false;
	s32 prev_stack_id = 0;

	// The second and third arguments to sched_switch are the prev and next tasks.
	struct task_struct *prev = (struct task_struct *)ctx->args[1];
	struct task_struct *next = (struct task_struct *)ctx->args[2];

	/* Step 1: Record the switch-out state of the 'prev' task. */
	prev_pid = BPF_CORE_READ(prev, pid);
	if (prev_pid > 0) {
	    // TODO __state 这个 5.10 不存在
		bool prev_is_running = (BPF_CORE_READ(prev, __state) == TASK_RUNNING);
		bpf_map_update_elem(&last_ivcsw, &prev_pid, &prev_is_running, BPF_ANY);
		// If 'prev' was running, it was involuntarily switched out. Treat this as an enqueue event for it.
		if (prev_is_running) {
			trace_enqueue(prev);
		}
	}

	next_pid = BPF_CORE_READ(next, pid);

	/* Step 2: Calculate latency for the 'next' task. */
	tsp = bpf_map_lookup_elem(&start, &next_pid);
	if (!tsp)
		return 0; // Missed the corresponding wakeup/enqueue event.

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	bpf_map_delete_elem(&start, &next_pid);

	if (min_us && delta_us < min_us)
		return 0;

	/* Step 3: Get the kernel stack trace of the 'prev' task if requested. */
	if (targ_prev_stack) {
		prev_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	}

	/* Step 4: Look up the historical switch-out state for the 'next' task. */
	was_ivcsw_ptr = bpf_map_lookup_elem(&last_ivcsw, &next_pid);
	if (was_ivcsw_ptr) {
		was_ivcsw = *was_ivcsw_ptr;
		bpf_map_delete_elem(&last_ivcsw, &next_pid); // Clean up the entry
	}

	/* Step 5: Populate and submit the event. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = next_pid;
	e->prev_pid = prev_pid;
	e->delta_us = delta_us;
	e->prev_stack_id = prev_stack_id;
	e->was_involuntarily_switched = was_ivcsw;
	e->cpu = bpf_get_smp_processor_id();
	BPF_CORE_READ_STR_INTO(&e->task, next, comm);
	BPF_CORE_READ_STR_INTO(&e->prev_task, prev, comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";