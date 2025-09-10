// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* --- 数据结构定义 --- */
#define TASK_COMM_LEN 16
#define KERN_STACK_DEPTH 127

struct event {
	__u32 pid;
	__u64 total_ns;
	char comm[TASK_COMM_LEN];
	int kernel_stack_id;
};

struct last_info {
	__u64 ts;
	__u32 pid;
};

/* --- 用户空间可配置的全局变量 --- */
const volatile __u64 min_duration_ns = 5000000;
const volatile int target_cpu = -1;

/* --- BPF Maps --- */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct last_info);
} last_irq_info SEC(".maps");

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

/* --- Tracepoint --- */

SEC("tracepoint/irq/irq_handler_entry")
int tracepoint__irq_handler_entry(struct trace_event_raw_irq_handler_entry* ctx)
{
	u32 key = 0;
	struct last_info *last;
	struct last_info current = {};
	u32 cpu_id = bpf_get_smp_processor_id();

	if (target_cpu != -1 && cpu_id != target_cpu) {
		return 0;
	}

	current.ts = bpf_ktime_get_ns();
	current.pid = bpf_get_current_pid_tgid() >> 32;

	last = bpf_map_lookup_elem(&last_irq_info, &key);
	if (!last || last->pid == 0) {
		goto update_and_exit;
	}

	if (last->pid == current.pid) {
		u64 delta = current.ts - last->ts;
		if (delta < min_duration_ns) {
			return 0; // 保持状态，不更新时间戳
		} else {
			struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
			if (e) {
				e->pid = current.pid;
				e->total_ns = delta;
				bpf_get_current_comm(&e->comm, sizeof(e->comm));
				e->kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
				bpf_ringbuf_submit(e, 0);
			}
			bpf_map_delete_elem(&last_irq_info, &key);
			return 0;
		}
	}

update_and_exit:
	bpf_map_update_elem(&last_irq_info, &key, &current, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";