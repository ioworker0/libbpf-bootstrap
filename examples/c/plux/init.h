#ifndef __PLUX_INIT_H__
#define __PLUX_INIT_H__

#include <sys/resource.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "signal.h"

// ====================================================================
// BPF 程序初始化 helper
// ====================================================================
//
// 使用方式：
//
//   plux_init();  // 初始化 BPF 运行环境（包含信号处理）
//

// plux_set_memlock_rlimit: 设置 RLIMIT_MEMLOCK 为无限
// 避免 BPF 程序加载时内存限制问题
static inline void plux_set_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "Warning: failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
		// 继续执行，libbpf 会自动处理
	}
}

// plux_init: 初始化 BPF 运行环境
// - 设置 RLIMIT_MEMLOCK
// - 注册信号处理
static inline void plux_init(void)
{
	plux_set_memlock_rlimit();
	plux_signal_init();
}

#endif /* __PLUX_INIT_H__ */
