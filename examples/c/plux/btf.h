#ifndef __PLUX_BTF_H__
#define __PLUX_BTF_H__

#include <bpf/libbpf.h>
#include <unistd.h>

// 默认自定义 BTF 路径
#define PLUX_BTF_PATH "/plux/btf/kernel.btf"

// ====================================================================
// BTF 加载 helper
// ====================================================================
//
// 使用方式：
//
//   struct pktcap_bpf *skel;
//   skel = PLUX_BTF_TRY_OPEN(skel, pktcap);
//
// 或者自定义 BTF 路径：
//
//   skel = PLUX_BTF_TRY_OPEN_WITH_PATH(skel, pktcap, "/custom/path/kernel.btf");
//

#define __PLUX_BTF_OPEN_IMPL(skel_type, btf_path) \
	({ \
		struct skel_type##_bpf *__skel = NULL; \
		const char *__btf_path = (btf_path); \
		if (access(__btf_path, R_OK) == 0) { \
			fprintf(stderr, "Found custom BTF at %s\n", __btf_path); \
			LIBBPF_OPTS(bpf_object_open_opts, __opts, .btf_custom_path = __btf_path); \
			__skel = skel_type##_bpf__open_opts(&__opts); \
		} else { \
			fprintf(stderr, "Using system BTF\n"); \
			__skel = skel_type##_bpf__open(); \
		} \
		__skel; \
	})

// PLUX_BTF_TRY_OPEN: 尝试使用自定义 BTF，否则使用系统默认（使用默认路径）
// 返回 skeleton 指针
#define PLUX_BTF_TRY_OPEN(skel, skel_type) \
	__PLUX_BTF_OPEN_IMPL(skel_type, PLUX_BTF_PATH)

// PLUX_BTF_TRY_OPEN_WITH_PATH: 尝试使用自定义 BTF，否则使用系统默认（指定路径）
#define PLUX_BTF_TRY_OPEN_WITH_PATH(skel, skel_type, btf_path) \
	__PLUX_BTF_OPEN_IMPL(skel_type, btf_path)

// 别名
#define PLUX_BTF_TRY_OPEN_BEFORE_LOAD PLUX_BTF_TRY_OPEN

#endif /* __PLUX_BTF_H__ */
