// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM  1

// TODO 没开 BTF 就别想了 。。。
// 拦截 mount 系统调用
// SEC("lsm/sb_mount") 对应内核 LSM hook security_sb_mount
SEC("lsm/sb_mount")
int BPF_PROG(lsm_sb_mount, const char *dev_name,
             const struct path *path, const char *type,
             unsigned long flags, void *data, int ret)
{
    // ret 是之前 BPF 程序的返回值，如果是第一个 hook 则为 0
    if (ret != 0)
        return ret;

    // 记录挂载尝试
    bpf_printk("LSM: mount attempt - dev_name=%pA, type=%pA",
               dev_name, type);

    // 在这里可以添加自定义逻辑来决定是否允许挂载
    // 例如：
    // - 只允许特定类型的文件系统
    // - 阻止挂载到特定路径
    // - 需要特定权限等

    // 示例：阻止所有挂载操作（取消注释下面的代码来启用）
     return -EPERM;

    // 返回 0 表示允许挂载
//    return 0;
}
