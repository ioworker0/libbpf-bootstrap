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

// ====================================================================
// Agent Socket 初始化 helper
// ====================================================================
//
// 使用方式：
//
//   struct socket_protocol sock;
//   plux_agent_socket_init(&sock, "/path/to/socket", "plugin-name");
//

#include "socket.h"
#include "config.h"

// plux_agent_socket_init: 初始化 Agent Socket 连接
// - 初始化 socket 协议
// - 连接到 socket
// - 发送握手
// - 启动心跳
static inline int plux_agent_socket_init(struct socket_protocol *sp,
					 const char *socket_path,
					 const char *plugin_name)
{
	struct plugin_config plugin_cfg = {0};
	int err;

	if (!sp || !socket_path || !plugin_name)
		return -1;

	strncpy(plugin_cfg.socket_path, socket_path, sizeof(plugin_cfg.socket_path) - 1);
	strncpy(plugin_cfg.plugin_name, plugin_name, sizeof(plugin_cfg.plugin_name) - 1);

	err = init_socket_protocol(sp, &plugin_cfg);
	if (err < 0) {
		fprintf(stderr, "Failed to init socket protocol: %d\n", err);
		return -1;
	}

	err = socket_connect(sp);
	if (err < 0) {
		fprintf(stderr, "Failed to connect to socket: %d\n", err);
		return -1;
	}

	err = socket_send_handshake(sp);
	if (err < 0) {
		fprintf(stderr, "Failed to send handshake: %d\n", err);
		return -1;
	}

	err = socket_start_heartbeat(sp);
	if (err < 0) {
		fprintf(stderr, "Failed to start heartbeat: %d\n", err);
		return -1;
	}

	return 0;
}

#endif /* __PLUX_INIT_H__ */
