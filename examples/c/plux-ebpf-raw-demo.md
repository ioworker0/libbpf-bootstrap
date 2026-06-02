# plux-ebpf-raw-demo 接入说明

`plux-ebpf-raw-demo` 是一个最小 Plux eBPF 插件 demo。它只展示配置、Agent socket 生命周期、perf buffer 采样和日志写入。

不包含 stack trace、watchdog、ratelimit、TC attach 或 packet zero-copy。

## 配置

插件通过 `--config` 接收 JSON。`socket_path` 是唯一默认接入字段，必填。

其他字段由插件自己定义。本 demo 只有一个自定义字段：

- `target_pid`: 只上报指定 PID，`0` 表示不过滤。

示例：

```sh
sudo ./plux-ebpf-raw-demo --config '{"socket_path":"/tmp/plux.sock","target_pid":0}'
```

插件名不从配置读取，代码中固定为 `plux-ebpf-raw-demo`，用于 Agent handshake。

## Socket 生命周期

用户态程序按这个顺序接入 Agent：

1. 解析 `--config`。
2. 调用 `plux_init()` 初始化 memlock 和信号处理。
3. 校验 `socket_path`。
4. 调用 `plux_agent_socket_init()`，它会完成 socket 初始化、连接、handshake 和 heartbeat。
5. perf buffer 收到 PID 后调用 `socket_send_log_info()`。
6. 退出时先 `socket_stop_heartbeat()`，再 `socket_disconnect()`。

初始化中途失败时，需要释放已经初始化的 socket 状态。

## 公共 helper

demo 用户态接入 helper 需要包含：

```c
#include "plux/btf.h"
#include "plux/init.h"
```

其中 `plux/init.h` 会继续引用 `plux/signal.h`、`socket.h` 和 `config.h`。demo 用到的公共能力来自这些头文件：

- `plux_init()`：来自 `plux/init.h`。设置 memlock，并注册 `SIGINT`、`SIGTERM`、`SIGHUP` 的信号处理。
- `plux_signal_should_exit()`：来自 `plux/signal.h`，通过 `plux/init.h` 间接引入。主循环里用它判断是否收到退出信号，收到后停止 `perf_buffer__poll()` 循环并走清理流程。
- `plux_agent_socket_init()`：来自 `plux/init.h`。封装 Agent socket 初始化、连接、handshake 和 heartbeat。
- `PLUX_BTF_TRY_OPEN_BEFORE_LOAD()`：来自 `plux/btf.h`。打开 skeleton 时优先使用自定义 BTF，找不到时交给 libbpf 使用系统 BTF。
- `CONFIG_MAX_SOCKET_PATH`、`check_socket_file()`：来自 `config.h`，用于保存和校验 `socket_path`。
- `struct socket_protocol`、`socket_send_log_info()`、`socket_stop_heartbeat()`、`socket_disconnect()`：来自 `socket.h`，用于写 Agent 日志和释放 socket。

## BTF

BPF 侧包含 `vmlinux.h`：

```c
#include "vmlinux.h"
```

用户态打开 skeleton 时使用公共 BTF helper：

```c
skel = PLUX_BTF_TRY_OPEN_BEFORE_LOAD(skel, plux_ebpf_raw_demo);
```

这个宏来自 `plux/btf.h`。默认会先检查：

```text
/plux/btf/kernel.btf
```

如果这个文件存在，就通过 `bpf_object_open_opts.btf_custom_path` 使用它；如果不存在，就调用普通的 `*_bpf__open()`，让 libbpf 自动查找系统 BTF，比如 `/sys/kernel/btf/vmlinux`。

这一步必须发生在 `*_bpf__load()` 之前。

## BPF 生命周期

BPF 程序按这个顺序运行：

1. 通过 `PLUX_BTF_TRY_OPEN_BEFORE_LOAD()` 打开 skeleton。
2. 在 load 前设置 `skel->rodata->target_pid`。
3. `plux_ebpf_raw_demo_bpf__load()`。
4. `plux_ebpf_raw_demo_bpf__attach()`。
5. 用 `perf_buffer__new()` 绑定 BPF 端 `samples` map。
6. 主循环中调用 `perf_buffer__poll()`，并用 `plux_signal_should_exit()` 判断是否退出。
7. 退出时释放 perf buffer 并 destroy skeleton。

`target_pid` 是 BPF 端的 `const volatile` 变量，必须在 load 前设置。

## Makefile 接入

新增插件时，需要把程序名加入 `examples/c/Makefile` 的 `APPS`。

本 demo 的文件名是：

```text
examples/c/plux-ebpf-raw-demo.bpf.c
examples/c/plux-ebpf-raw-demo.c
```

Makefile 中对应的程序名是：

```make
plux-ebpf-raw-demo
```

程序名前缀必须和 `.c`、`.bpf.c` 文件名前缀一致。Makefile 会根据这个名字生成 BPF object、skeleton 和最终二进制。

构建：

```sh
cd examples/c
make plux-ebpf-raw-demo
```
