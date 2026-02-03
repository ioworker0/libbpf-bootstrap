#ifndef __PLUX_TC_H__
#define __PLUX_TC_H__

#include <bpf/libbpf.h>
#include <stdio.h>
#include <errno.h>

// ====================================================================
// TC (Traffic Control) helper
// ====================================================================
//
// 使用方式：
//
//   // 创建 qdisc
//   plux_tc_hook_create(ifindex, BPF_TC_INGRESS);
//   plux_tc_hook_create(ifindex, BPF_TC_EGRESS);
//
//   // 清理旧 filter
//   plux_tc_cleanup(ifindex, BPF_TC_INGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
//   plux_tc_cleanup(ifindex, BPF_TC_EGRESS, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
//
//   // 挂载程序
//   plux_tc_attach_prog(ifindex, BPF_TC_INGRESS, prog_fd, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);
//   plux_tc_attach_prog(ifindex, BPF_TC_EGRESS, prog_fd, PLUX_PKTCAP_PRIORITY, PLUX_PKTCAP_HANDLE);

// 默认 TC filter 配置（plux_packet_capture 程序）
#define PLUX_PKTCAP_PRIORITY  5   // plux_packet_capture 默认 priority
#define PLUX_PKTCAP_HANDLE    1   // plux_packet_capture 默认 handle

// plux_tc_hook_create: 创建 TC qdisc（如果不存在）
// @ifindex: 网卡 interface index
// @point: BPF_TC_INGRESS 或 BPF_TC_EGRESS
// @return: 0=成功, -EEXIST=已存在, <0=失败
static inline int plux_tc_hook_create(int ifindex, enum bpf_tc_attach_point point)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);

	int err = bpf_tc_hook_create(&hook);
	if (err == -EEXIST) {
		// qdisc 已存在，这是正常的
		return -EEXIST;
	}
	return err;
}

// plux_tc_cleanup: 清理指定 priority/handle 的旧 filter
// @ifindex: 网卡 interface index
// @point: BPF_TC_INGRESS 或 BPF_TC_EGRESS
// @priority: filter priority
// @handle: filter handle
// @return: 0=成功或不存在, <0=失败
static inline int plux_tc_cleanup(int ifindex, enum bpf_tc_attach_point point,
				   int priority, int handle)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .handle = handle,
			    .priority = priority,
			    .prog_fd = 0,
			    .prog_id = 0,
			    .flags = 0);

	// 先 query 检查是否存在
	int err = bpf_tc_query(&hook, &opts);
	if (err == 0) {
		// 找到了，执行 detach
		fprintf(stderr, "  -> Found old %s filter (handle=%u, prog_id=%u)\n",
		       point == BPF_TC_INGRESS ? "ingress" : "egress",
		       opts.handle, opts.prog_id);

		opts.prog_fd = 0;
		opts.prog_id = 0;
		opts.flags = 0;

		err = bpf_tc_detach(&hook, &opts);
		if (err == 0) {
			fprintf(stderr, "  -> Removed successfully\n");
		} else if (err != -ENOENT) {
			fprintf(stderr, "  -> Failed to remove: %d (continuing anyway)\n", err);
		}
		return 0;
	}

	// query 失败，尝试 blind detach
	err = bpf_tc_detach(&hook, &opts);
	if (err == 0) {
		fprintf(stderr, "  -> Detached handle %u successfully (blind detach)\n", handle);
	} else if (err == -ENOENT) {
		// 不存在，也是成功
		fprintf(stderr, "  -> No old %s filter with handle %u found\n",
		       point == BPF_TC_INGRESS ? "ingress" : "egress", handle);
		return 0;
	} else {
		fprintf(stderr, "  -> Failed to detach handle %u: %d\n", handle, err);
	}

	return err;
}

// plux_tc_attach_prog: 挂载 BPF 程序到 TC
// @ifindex: 网卡 interface index
// @point: BPF_TC_INGRESS 或 BPF_TC_EGRESS
// @prog_fd: BPF 程序 fd
// @priority: filter priority
// @handle: filter handle
// @return: 0=成功, <0=失败
static inline int plux_tc_attach_prog(int ifindex, enum bpf_tc_attach_point point,
				      int prog_fd, int priority, int handle)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .handle = handle,
			    .priority = priority,
			    .prog_fd = prog_fd);

	int err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC %s: %d\n",
		       point == BPF_TC_INGRESS ? "ingress" : "egress", err);
		return err;
	}

	fprintf(stderr, "Attached to %s (priority: %d, handle: 0x%x)\n",
	       point == BPF_TC_INGRESS ? "ingress" : "egress", priority, handle);
	return 0;
}

// plux_tc_detach: 分离指定 priority/handle 的 filter
// @ifindex: 网卡 interface index
// @point: BPF_TC_INGRESS 或 BPF_TC_EGRESS
// @priority: filter priority
// @handle: filter handle
// @return: 0=成功或不存在, <0=失败
static inline int plux_tc_detach(int ifindex, enum bpf_tc_attach_point point,
				  int priority, int handle)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .ifindex = ifindex,
			    .attach_point = point);

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
			    .handle = handle,
			    .priority = priority,
			    .prog_fd = 0,
			    .prog_id = 0,
			    .flags = 0);

	int err = bpf_tc_detach(&hook, &opts);
	if (err && err != -ENOENT) {
		fprintf(stderr, "Failed to detach TC %s: %d\n",
		       point == BPF_TC_INGRESS ? "ingress" : "egress", err);
		return err;
	}
	return 0;
}

#endif /* __PLUX_TC_H__ */
