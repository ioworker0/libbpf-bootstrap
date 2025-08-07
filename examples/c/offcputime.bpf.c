// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// KERN_STACK_DEPTH defines the maximum number of stack frames to capture.
// This is a standard value used in many BPF tools.
#define KERN_STACK_DEPTH 127

/*
 * User-space filters, configured via the .rodata section.
 * These are read-only variables that the user-space application can set
 * before the BPF program is loaded into the kernel.
 */
const volatile __u64 min_us = 0;      // Minimum Off-CPU duration in microseconds to trace.
const volatile pid_t target_pid = 0; // The specific process ID (PID/TID) to trace. 0 means all.

/*
 * The event structure sent from the kernel to user-space via the ring buffer.
 * It contains all the necessary information for a single Off-CPU event.
 */
struct event {
	u64 delta_us;          // The total Off-CPU duration in microseconds.
	u32 pid;               // The PID of the task that was off-CPU.
	s32 kern_stack_id;     // The ID of the kernel stack trace captured when the task went to sleep.
	char comm[TASK_COMM_LEN]; // The command name of the task.
};

/*
 * BPF map to store the timestamp when a task goes Off-CPU.
 * This acts as the "start" of our stopwatch.
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
 * BPF map to transfer the correct "sleeper" stack ID from the point a task
 * goes Off-CPU to the point it comes back On-CPU.
 * Key: PID (u32)
 * Value: Stack Trace ID (s32)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, s32);
} sleep_stack SEC(".maps");

/*
 * BPF map of type STACK_TRACE. This is a special map type managed by the
 * kernel to store unique stack traces efficiently.
 * We must explicitly define key_size and value_size for this map type.
 */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(u32));
	__uint(value_size, KERN_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

/*
 * BPF ring buffer for high-performance, unidirectional data transfer
 * from the kernel to user-space.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/**
 * @brief BPF program attached to the sched_switch raw tracepoint.
 *
 * This function is executed every time a task switch occurs in the kernel.
 * It's the core of our tracer, handling both the start and end of Off-CPU events.
 * We use a raw tracepoint for stability and performance, as it's a stable kernel ABI.
 */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	// sched_switch tracepoint arguments: (bool preempt, struct task_struct *prev, struct task_struct *next)
	struct task_struct *prev = (struct task_struct *)ctx->args[1];
	struct task_struct *next = (struct task_struct *)ctx->args[2];
	u32 prev_pid, next_pid;
	u64 ts, *tsp;
	s32 kern_stack_id;

	prev_pid = BPF_CORE_READ(prev, pid);
	next_pid = BPF_CORE_READ(next, pid);

	// Top-level filter: If a target_pid is specified, quickly exit if neither
	// the previous nor the next task matches. This is a crucial performance optimization.
	if (target_pid != 0 && target_pid != prev_pid && target_pid != next_pid) {
		return 0;
	}

	/*
	 * Part 1: Handle the task that is switching OFF the CPU (prev).
	 * This is where we "start the stopwatch" and capture the sleeper stack.
	 */
	if (prev_pid > 0) {
		// Further check to ensure we only process our target PID.
		if (target_pid == 0 || target_pid == prev_pid) {
			// Get the kernel stack trace *at this exact moment*. This is the correct
			// "sleeper" stack, showing why the task is going to sleep.
			kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

			// Store the stack ID and the timestamp for later retrieval.
			bpf_map_update_elem(&sleep_stack, &prev_pid, &kern_stack_id, BPF_ANY);
			ts = bpf_ktime_get_ns();
			bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
		}
	}

	/*
	 * Part 2: Handle the task that is switching ON the CPU (next).
	 * This is where we "stop the stopwatch" and generate the event.
	 */
	if (next_pid == 0)
		return 0; // Skip scheduler idle task.

	// Further check to ensure we only process events for our target PID.
	if (target_pid != 0 && target_pid != next_pid) {
		return 0;
	}

	// Lookup the start timestamp for this task.
	tsp = bpf_map_lookup_elem(&start, &next_pid);
	if (!tsp)
		return 0; // We missed the corresponding switch-out event.

	u64 delta_ns = bpf_ktime_get_ns() - *tsp;
	bpf_map_delete_elem(&start, &next_pid); // Clean up the entry.

	// Lookup the sleeper stack ID we saved earlier.
	s32 *stack_id_ptr = bpf_map_lookup_elem(&sleep_stack, &next_pid);
	if (!stack_id_ptr)
		return 0; // We missed the stack ID, maybe due to map full.

	kern_stack_id = *stack_id_ptr;
	bpf_map_delete_elem(&sleep_stack, &next_pid); // Clean up the entry.

	// Convert duration to microseconds and apply the minimum time filter.
	u64 delta_us = delta_ns / 1000;
	if (min_us > 0 && delta_us < min_us)
		return 0;

	/*
	 * Part 3: Submit the event to user-space.
	 */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	// Populate the event structure with the collected data.
	e->pid = next_pid;
	e->delta_us = delta_us;
	e->kern_stack_id = kern_stack_id; // This is now the correct sleeper stack ID.
	BPF_CORE_READ_STR_INTO(&e->comm, next, comm);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

// All eBPF programs must have a license.
char LICENSE[] SEC("license") = "GPL";