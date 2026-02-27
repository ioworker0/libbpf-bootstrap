#ifndef __PLUX_USER_WATCHDOG_H__
#define __PLUX_USER_WATCHDOG_H__

#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "signal.h"

// ====================================================================
// 用户态 Watchdog heartbeat 线程
// ====================================================================
//
// 使用方式：
//
//   // 获取 watchdog map fd
//   int watchdog_fd = bpf_map__fd(skel->maps.__plux_watchdog);
//
//   // 启动 watchdog 线程
//   plux_watchdog_start(watchdog_fd);
//
//   // 主循环
//   while (!plux_signal_should_exit()) {
//       // do work
//   }
//
//   // 线程会自动检测退出信号并清理

// 默认更新间隔（秒）
#define PLUX_WATCHDOG_UPDATE_INTERVAL 1

// Watchdog 上下文
struct plux_watchdog {
	int             map_fd;      // watchdog map fd
	pthread_t       thread;      // 线程句柄
	int             interval;    // 更新间隔（秒）
};

// 内部 watchdog 上下文
static struct plux_watchdog __plux_watchdog_ctx = {
	.map_fd = -1,
	.thread = 0,
	.interval = PLUX_WATCHDOG_UPDATE_INTERVAL,
};

// 获取当前时间（纳秒）
static inline __u64 __plux_watchdog_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

// Watchdog 线程函数
static void *__plux_watchdog_thread(void *arg)
{
	struct plux_watchdog *ctx = (struct plux_watchdog *)arg;
	__u32 key = 0;

	fprintf(stderr, "Watchdog thread started (update interval: %ds)\n", ctx->interval);

	while (!plux_signal_should_exit()) {
		// 更新心跳
		__u64 now = __plux_watchdog_now_ns();
		if (bpf_map_update_elem(ctx->map_fd, &key, &now, BPF_ANY) < 0) {
			fprintf(stderr, "Watchdog: failed to update heartbeat, exiting thread\n");
			break;
		}

		// 等待下一个更新周期
		sleep(ctx->interval);
	}

	fprintf(stderr, "Watchdog thread stopped\n");
	return NULL;
}

// plux_watchdog_start: 启动 watchdog heartbeat 线程
// @map_fd: watchdog map 的文件描述符
// @interval: 更新间隔（秒），0 表示使用默认值
// @return: 0=成功, <0=失败
static inline int plux_watchdog_start(int map_fd, int interval)
{
	if (map_fd < 0) {
		fprintf(stderr, "Watchdog: invalid map fd\n");
		return -1;
	}

	// 初始化心跳（第一次更新）
	__u32 key = 0;
	__u64 now = __plux_watchdog_now_ns();
	if (bpf_map_update_elem(map_fd, &key, &now, BPF_ANY) < 0) {
		fprintf(stderr, "Watchdog: failed to initialize heartbeat\n");
		return -1;
	}

	__plux_watchdog_ctx.map_fd = map_fd;
	__plux_watchdog_ctx.interval = interval > 0 ? interval : PLUX_WATCHDOG_UPDATE_INTERVAL;

	if (pthread_create(&__plux_watchdog_ctx.thread, NULL, __plux_watchdog_thread, &__plux_watchdog_ctx) != 0) {
		fprintf(stderr, "Watchdog: failed to create thread\n");
		return -1;
	}

	// detach 线程，使其自动清理
	pthread_detach(__plux_watchdog_ctx.thread);

	return 0;
}

#endif /* __PLUX_USER_WATCHDOG_H__ */
