#ifndef __BPF_RATELIMIT_H__
#define __BPF_RATELIMIT_H__

#include <bpf/bpf_helpers.h>

// ====================================================================
// 简化版：BPF 程序传入 interval 和 burst 参数
// ====================================================================
//
// 使用方式：
//   if (bpf_ratelimit_check())
//       return;  // 限流，丢弃
//   // 允许通过

// 配置变量（const volatile，用户态可通过 skel->rodata 覆盖）
const volatile __u64 __bpf_ratelimit_interval = 1;  // 时间窗口（秒）
const volatile __u64 __bpf_ratelimit_burst = 100;   // 每个 interval 最多事件数

// 状态变量（存储在 bss 段）
struct {
	__u64 begin;   // 当前窗口开始时间（秒）
	__u64 events;  // 当前窗口已处理事件数
} __bpf_ratelimit = {.begin = 0, .events = 0};

// bpf_ratelimit_check: 限流检查
// @return: true=限流(丢弃), false=允许通过
static __always_inline bool bpf_ratelimit_check(void)
{
	if (__bpf_ratelimit_interval == 0 || __bpf_ratelimit_burst == 0)
		return false;  // 未配置，允许通过

	__u64 now = bpf_ktime_get_ns() / 1000000000ULL;

	if (now >= __bpf_ratelimit.begin + __bpf_ratelimit_interval) {
		__bpf_ratelimit.begin = now;
		__bpf_ratelimit.events = 0;
	}

	if (__bpf_ratelimit.events < __bpf_ratelimit_burst) {
		__sync_fetch_and_add(&__bpf_ratelimit.events, 1);
		return false;  // 允许
	}

	return true;  // 限流
}

#endif /* __BPF_RATELIMIT_H__ */
