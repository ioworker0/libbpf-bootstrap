#ifndef __BPF_RATELIMIT_USER_H__
#define __BPF_RATELIMIT_USER_H__

#include <bpf/bpf.h>

// BPF_RATELIMIT_SET: 设置 bpf_ratelimit 配置宏
// 必须在 xxx__load() 之前调用，因为 const volatile 变量加载后不可修改
//
// 使用方式:
//   BPF_RATELIMIT_SET(skel, 1, 100);  // interval=1s, burst=100
#define BPF_RATELIMIT_SET(skel, interval, burst) \
	do { \
		(skel)->rodata->__bpf_ratelimit_interval = (interval); \
		(skel)->rodata->__bpf_ratelimit_burst = (burst); \
	} while (0)

#endif /* __BPF_RATELIMIT_USER_H__ */
