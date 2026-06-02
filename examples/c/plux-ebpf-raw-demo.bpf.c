// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const volatile __u32 target_pid = 0;

struct sample {
	__u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} samples SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	struct sample sample = {};
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid && pid != target_pid)
		return 0;

	sample.pid = pid;

	bpf_perf_event_output(ctx, &samples, BPF_F_CURRENT_CPU, &sample, sizeof(sample));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
