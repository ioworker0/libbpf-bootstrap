#ifndef __BPF_RATELIMIT_USER_H__
#define __BPF_RATELIMIT_USER_H__

#include <bpf/bpf.h>

// 设置 bpf_ratelimit 配置
// @interval_map: __bpf_ratelimit_interval map
// @burst_map: __bpf_ratelimit_burst map
// @interval: 时间窗口（秒）
// @burst: 每个 interval 最多事件数
static inline void bpf_ratelimit_set(struct bpf_map *interval_map,
                                      struct bpf_map *burst_map,
                                      __u64 interval, __u64 burst)
{
	if (interval_map)
		bpf_map_update_elem(bpf_map__fd(interval_map), NULL, &interval, BPF_ANY);
	if (burst_map)
		bpf_map_update_elem(bpf_map__fd(burst_map), NULL, &burst, BPF_ANY);
}

#endif /* __BPF_RATELIMIT_USER_H__ */
