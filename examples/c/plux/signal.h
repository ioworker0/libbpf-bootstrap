#ifndef __PLUX_SIGNAL_H__
#define __PLUX_SIGNAL_H__

#include <signal.h>
#include <stdbool.h>

// ====================================================================
// 用户态信号处理 helper
// ====================================================================
//
// 使用方式：
//
//   plux_signal_init();           // 初始化信号监听
//
//   // 主循环
//   while (!plux_signal_should_exit()) {
//       // do work
//   }
//

// 内部退出标志
static volatile sig_atomic_t __plux_exiting = 0;

// 内部信号处理函数
static void __plux_signal_handler(int signo)
{
	(void)signo;
	__plux_exiting = 1;
}

// plux_signal_init: 初始化信号监听
// 注册 SIGINT, SIGTERM, SIGHUP 信号处理
static inline void plux_signal_init(void)
{
	signal(SIGINT, __plux_signal_handler);
	signal(SIGTERM, __plux_signal_handler);
	signal(SIGHUP, __plux_signal_handler);
}

// plux_signal_should_exit: 检查是否应该退出
// @return: true=应该退出, false=继续运行
static inline bool plux_signal_should_exit(void)
{
	return __plux_exiting != 0;
}

// plux_signal_exit: 设置退出标志（用于程序内部主动退出）
static inline void plux_signal_exit(void)
{
	__plux_exiting = 1;
}

#endif /* __PLUX_SIGNAL_H__ */
