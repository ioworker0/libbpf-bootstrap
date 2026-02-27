#ifndef __BPF_WATCHDOG_H__
#define __BPF_WATCHDOG_H__

#include <bpf/bpf_helpers.h>

// ====================================================================
// Watchdog: 检测用户态程序是否存活
// ====================================================================
//
// 使用方式：
//   #include "plux/bpf_watchdog.h"
//
//   if (bpf_watchdog_timed_out())
//       return TC_ACT_UNSPEC;  // 超时，放行
//   // 正常，继续处理

// Watchdog map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);  // 最后更新时间戳（纳秒）
} __plux_watchdog SEC(".maps");

// 配置变量（const volatile，用户态可通过 skel->rodata 覆盖）
const volatile __u64 __bpf_watchdog_timeout_ns = 10ULL * 1000000000ULL;  // 超时时间（纳秒，默认 10 秒）

// bpf_watchdog_timed_out: 检查 watchdog 是否超时
// @return: true=超时(用户态挂了), false=正常
static __always_inline bool bpf_watchdog_timed_out(void)
{
	__u32 key = 0;
	__u64 *last_heartbeat = bpf_map_lookup_elem(&__plux_watchdog, &key);

	if (!last_heartbeat)
		return true;  // map 未初始化，认为不正常

	__u64 now = bpf_ktime_get_ns();
	if (now - *last_heartbeat > __bpf_watchdog_timeout_ns)
		return true;  // 超时

	return false;  // 正常
}

#endif /* __BPF_WATCHDOG_H__ */
