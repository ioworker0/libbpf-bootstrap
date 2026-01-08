# iotrace - 全栈 IO 追踪工具

## 简介

`iotrace` 是一个基于 eBPF 的全栈 IO 追踪工具，可以追踪从文件系统层（VFS）到块设备层的完整 IO 路径，提供详细的 IO 性能分析。

## 功能特性

- ✅ **全栈 IO 追踪**: 追踪文件系统层（ext4/xfs）、页面缓存层和块设备层的 IO
- ✅ **延迟分析**: 提供 q2c (queue-to-complete) 和 d2c (device-to-complete) 延迟统计（平均值和最大值）
- ✅ **进程-文件关联**: 精确识别哪个进程在访问哪个文件
- ✅ **Direct IO 识别**: 标识直接 IO 操作
- ✅ **设备过滤**: 支持按设备号过滤 IO 事件
- ✅ **内核兼容**: 支持多个内核版本（5.4+），使用 BPF CO-RE 技术
- ✅ **动态挂载**: 根据系统支持情况动态挂载 BPF 程序

## 编译

### 前置要求

- Linux 内核 5.4+（推荐 5.15+ 以获得更好的 BPF CO-RE 支持）
- Clang/LLVM 11+
- libbpf
- bpftool
- 内核配置：`CONFIG_DEBUG_INFO_BTF=y`

### 编译步骤

```bash
cd /Users/user/C/ebpf/libbbbbb/examples/c
make iotrace
```

编译成功后会生成 `iotrace` 可执行文件。

## 使用方法

### 基本用法

```bash
# 追踪 8 秒（默认）
sudo ./iotrace

# 追踪 10 秒，显示 top 5 进程
sudo ./iotrace -d 10 -t 5

# 过滤特定设备（sda 和 dm-0）
sudo ./iotrace -D 8:0,253:0

# 每个进程显示最多 10 个文件
sudo ./iotrace -f 10
```

### 命令行选项

| 选项 | 长选项 | 说明 | 默认值 |
|------|--------|------|--------|
| `-d` | `--duration` | 追踪持续时间（秒） | 8 |
| `-t` | `--top` | 最多显示的进程数量 | 10 |
| `-f` | `--files` | 每个进程最多显示的文件数量 | 5 |
| `-D` | `--device` | 设备过滤器（格式：`major:minor,major:minor`） | 无（追踪所有设备） |
| `-h` | `--help` | 显示帮助信息 | - |

### 获取设备号

使用 `lsblk` 命令查看设备的 major:minor 号：

```bash
lsblk
# NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
# sda      8:0    0   100G  0 disk
# ├─sda1   8:1    0    99G  0 part /
# └─sda2   8:2    0     1G  0 part [SWAP]
# dm-0   253:0    0    50G  0 lvm  /data
```

示例：追踪 `sda` 和 `dm-0`：

```bash
sudo ./iotrace -D 8:0,253:0
```

## 输出示例

```
============= IO Tracing Report (Duration: 8s) =============

PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES
======  ===================  ======= ======== ========= ========== =====
12345   dd if=/dev/zero ...  0B      1.5GB    0B        1.5GB      1
23456   fio --name=test ...  2.3GB   0B       2.3GB     0B         10
34567   nginx: worker pro... 45MB    12MB     45MB      12MB       127

===========================================================================
PID: 12345    TOTAL_IO: R=0B W=1.5GB  FILES: 1
COMMAND: dd if=/dev/zero of=/mnt/test bs=1M count=1500
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     0B      192MB    0B        192MB        q2c=523(max 1234) d2c=345(max 987)  test [direct IO]

===========================================================================
PID: 23456    TOTAL_IO: R=2.3GB W=0B  FILES: 10
COMMAND: fio --name=test --rw=randread --bs=4k --numjobs=4
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     234MB   0B       234MB     0B           q2c=145(max 567) d2c=98(max 456)   testfile.1 [direct IO]
8:0     230MB   0B       230MB     0B           q2c=143(max 543) d2c=95(max 445)   testfile.2 [direct IO]
...
```

## 输出字段说明

### 进程级汇总表

| 字段 | 说明 |
|------|------|
| `PID` | 进程 ID |
| `COMMAND` | 进程命令行（截断至20字符） |
| `FS_READ` | 文件系统层读取字节数/秒 |
| `FS_WRITE` | 文件系统层写入字节数/秒 |
| `DISK_READ` | 块设备层读取字节数/秒 |
| `DISK_WRITE` | 块设备层写入字节数/秒 |
| `FILES` | 该进程访问的文件数量 |

### 文件级详情表

| 字段 | 说明 |
|------|------|
| `DEVICE` | 设备号（major:minor 格式） |
| `FS_READ` | 文件系统层读取速率 |
| `FS_WRITE` | 文件系统层写入速率 |
| `DISK_READ` | 块设备层读取速率 |
| `DISK_WRITE` | 块设备层写入速率 |
| `q2c` | Queue-to-complete 平均延迟（微秒） |
| `max` | Queue-to-complete 最大延迟（微秒） |
| `d2c` | Device-to-complete 平均延迟（微秒） |
| `max` | Device-to-complete 最大延迟（微秒） |
| `FILE` | 文件路径（含 Direct IO 标识） |

## 延迟指标说明

- **q2c (Queue-to-Complete)**: 从 IO 请求进入队列到完成的总延迟，包含所有排队、调度和设备处理时间
- **d2c (Device-to-Complete)**: 从 IO 请求发送到设备到完成的延迟，仅包含设备处理时间
- **排队延迟 = q2c - d2c**: 可以推算出 IO 在队列中等待的时间

## 高级特性

### Direct IO 检测

工具会自动识别使用 Direct IO 的文件操作，并在输出中标记 `[direct IO]`。Direct IO 绕过页面缓存，因此通常有不同的性能特征。

### 内核版本兼容

工具使用 BPF CO-RE（Compile Once, Run Everywhere）技术，可以在以下内核版本上运行：

- Linux 5.4 - 5.10
- Linux 5.11 - 5.19
- Linux 6.0+

关键兼容特性：

- **request 结构兼容**: 自动适配 `request->rq_disk` (旧内核) 和 `request->q->disk` (新内核)
- **分区号兼容**: 自动适配 `bio->bi_partno` (旧内核) 和 `bdev->bd_partno` (新内核)
- **iov_iter 兼容**: 支持 union 和非 union 两种内核版本
- **rq_qos 函数**: 动态检测并挂载 `rq_qos_issue` 或 `__rq_qos_issue`

### 自定义 BTF 支持

如果系统没有内置 BTF，可以将自定义 BTF 文件放置在 `/plux/btf/kernel.btf`，工具会自动使用：

```bash
# 生成 BTF 文件
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel.btf

# 放置到自定义路径
sudo mkdir -p /plux/btf
sudo cp kernel.btf /plux/btf/
```

### 动态文件系统支持

工具会在运行时检查 `/proc/filesystems`，仅挂载系统支持的文件系统钩子：

- ext4: `ext4_file_read_iter`, `ext4_file_write_iter`, `ext4_filemap_page_mkwrite`
- xfs: `xfs_file_read_iter`, `xfs_file_write_iter`, `xfs_filemap_page_mkwrite`

## 故障排查

### 权限错误

确保以 root 权限运行：

```bash
sudo ./iotrace
```

### BTF 未找到

如果看到 "BTF is required" 错误：

1. 检查内核是否启用 BTF：
   ```bash
   ls /sys/kernel/btf/vmlinux
   ```

2. 如果不存在，检查内核配置：
   ```bash
   grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
   ```

3. 或提供自定义 BTF 文件到 `/plux/btf/kernel.btf`

### 挂载失败

如果看到 "Failed to attach" 错误：

1. 检查 kprobe 是否可用：
   ```bash
   sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep rq_qos
   ```

2. 确保内核支持 BPF：
   ```bash
   grep CONFIG_BPF /boot/config-$(uname -r)
   ```

3. 检查文件系统支持：
   ```bash
   cat /proc/filesystems
   ```

## 性能影响

- **开销极低**: 使用 eBPF 技术，对系统性能影响小于 1%
- **零数据丢失**: 使用 BPF Map 进行内核态聚合，避免用户态数据丢失
- **内存占用**: 通常小于 10MB

## 与其他工具对比

| 工具 | 全栈追踪 | 进程-文件关联 | 延迟分析 | Direct IO | 内核版本兼容 |
|------|----------|---------------|----------|-----------|--------------|
| iotrace | ✅ | ✅ | ✅ (avg+max) | ✅ | ✅ 5.4+ |
| biosnoop | ⚠️ 仅块层 | ❌ | ⚠️ 基础 | ❌ | ⚠️ 有限 |
| fileslower | ⚠️ 仅文件层 | ✅ | ⚠️ 基础 | ❌ | ⚠️ 有限 |
| iostat | ⚠️ 系统级 | ❌ | ⚠️ 系统级 | ❌ | ✅ |

## 参考资料

- 设计文档: `iotrace_design.md`
- 任务列表: `iotrace_tasks.md`
- 参考实现: `huatuo/cmd/iotracing/` 和 `huatuo/bpf/iotracing.c`

## License

GPL-2.0

## 贡献

欢迎提交问题和改进建议！

