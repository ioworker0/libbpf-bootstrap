// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* --- 数据结构定义 --- */
#define TASK_COMM_LEN 16
#define KERN_STACK_DEPTH 127

struct event {
	__u32 pid;
	__u32 count;
	char comm[TASK_COMM_LEN];
	int kernel_stack_id;
};

struct last_info {
	__u32 pid;
	__u32 count;
};

/* --- 用户空间可配置的全局变量 --- */
const volatile __u32 min_count = 5;
const volatile int target_cpu = -1;
const volatile bool strict_mode = false; // 新增：严格模式开关

/* --- BPF Maps --- */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct last_info);
} last_sample SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(u32));
	__uint(value_size, KERN_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

/* --- Perf Event Handler --- */
SEC("perf_event")
int on_cpu_sample(struct bpf_perf_event_data *ctx)
{
	u32 key = 0;
	struct last_info *last;
	u32 current_pid;
	u32 cpu_id = bpf_get_smp_processor_id();

	if (target_cpu != -1 && cpu_id != target_cpu)
		return 0;

	current_pid = bpf_get_current_pid_tgid() >> 32;
	if (current_pid == 0) {
		bpf_map_delete_elem(&last_sample, &key);
		return 0;
	}

	last = bpf_map_lookup_elem(&last_sample, &key);
	if (!last) {
		struct last_info new_info = { .pid = current_pid, .count = 1 };
		bpf_map_update_elem(&last_sample, &key, &new_info, BPF_ANY);
		return 0;
	}

	if (last->pid == current_pid) {
		last->count++;
	} else {
		last->pid = current_pid;
		last->count = 1;
	}

	if (last->count == min_count) {
		struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->pid = current_pid;
			e->count = last->count;
			bpf_get_current_comm(&e->comm, sizeof(e->comm));
			e->kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
			bpf_ringbuf_submit(e, 0);
		}
		last->count = 0;
	}
	return 0;
}

/* --- Sched Switch Handler (新增) --- */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
	u32 key = 0;
	struct last_info *last;
	struct task_struct *next = (struct task_struct *)ctx->args[2];
	u32 next_pid;
	u32 cpu_id = bpf_get_smp_processor_id();

	// 如果不处于严格模式，或者我们监控的不是这个CPU，则不做任何事
	if (!strict_mode || (target_cpu != -1 && cpu_id != target_cpu))
		return 0;

	last = bpf_map_lookup_elem(&last_sample, &key);
	if (!last)
		return 0;

	next_pid = BPF_CORE_READ(next, pid);

	// 核心逻辑：如果被换出去的进程是我们正在追踪的那个，
	// 就删除记录，因为它的“连续性”被打破了。
	if (last->pid != next_pid) {
		last->count = 1000;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";