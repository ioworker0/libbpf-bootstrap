// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * LSM sb_mount 拦截示例
 *
 * 注意：确保你的内核版本 >= 5.7，BTF 已启用，
 * 并且 '/sys/kernel/security/lsm' 包含 'bpf'
 */
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "lsm_mount.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct lsm_mount_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    // 打开、加载并验证 BPF 程序
    skel = lsm_mount_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    // 附加 LSM hook
    err = lsm_mount_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! LSM sb_mount hook is now active.\n\n");
    printf("View BPF output with:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    printf("Test mount operations to see the LSM hook in action.\n");
    printf("Press Ctrl-C to exit.\n");

    for (;;) {
        sleep(1);
    }

cleanup:
    lsm_mount_bpf__destroy(skel);
    return err != 0;
}
