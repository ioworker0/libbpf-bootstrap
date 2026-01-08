# iotrace 工具实现规划

## 📋 项目概述

我们将基于 `captrace` 的架构,参考 `huatuo` 的 `iotracing` 实现,创建一个简化的 **iotrace** 工具用于追踪 Linux 系统的 IO 操作。

## 🎯 核心目标

1. **不需要 agent 模式** - 只实现 standalone 模式,直接输出到终端
2. **全栈 IO 追踪** - 从文件系统层到块设备层的完整追踪
3. **延迟分析** - 提供 q2c(队列到完成)和 d2c(设备到完成)延迟指标
4. **进程-文件关联** - 精确追踪哪个进程在操作哪个文件

---

## 📚 参考资料对比

### captrace 的特点

- ✅ 简洁的 C 实现
- ✅ 使用 ringbuf 机制
- ✅ 支持堆栈追踪
- ✅ 有 agent 和 standalone 两种模式
- ✅ 使用 skeleton 框架

### huatuo iotracing 的特点

- ✅ 完整的 IO 追踪实现
- ✅ 块层钩子(rq_qos_issue/done)进行 issue/done 配对
- ✅ 文件系统钩子(ext4/xfs_file_read/write_iter)
- ✅ 页面缓存钩子(filemap_fault/page_mkwrite)
- ✅ 使用 BPF map 进行内核空间数据聚合
- ✅ 延迟统计(q2c, d2c)
- ✅ 文件路径提取(3级目录)

---

## 🔨 实现策略

我们将:

1. **借鉴 captrace 的框架结构** - C 程序框架、skeleton 使用方式
2. **移植 huatuo 的 IO 追踪逻辑** - BPF 钩子、数据结构、追踪逻辑
3. **简化输出** - 不需要 agent、不需要容器环境变量提取、直接终端输出

---

## 📁 文件结构

```
examples/c/
├── iotrace.bpf.c          # BPF 端程序(内核空间)
├── iotrace.c              # 用户态程序(用户空间)
└── iotrace.h              # 共享数据结构定义(可选)
```

---

## 🗂️ 核心数据结构设计

### BPF 端数据结构

```c
// IO 源 Map 的 key：用于聚合同一进程/文件/设备的 IO
struct io_key {
    __u32 pid;      // 进程 PID
    __u32 dev;      // 设备号
    __u64 inode;    // 文件 inode
};

// IO 数据统计：聚合后的完整 IO 信息
struct io_data {
    __u32 pid;                   // 进程 PID
    __u32 dev;                   // 设备号
    __u64 fs_write_bytes;        // 文件系统写入字节数
    __u64 fs_read_bytes;         // 文件系统读取字节数
    __u64 block_write_bytes;     // 块设备写入字节数
    __u64 block_read_bytes;      // 块设备读取字节数
    __u64 inode;                 // 文件 inode
    struct latency_info latency; // 延迟统计(包含 sum/max/count)
    char  comm[16];              // 进程名
    char  filename[64];          // 文件名
    char  d1name[64];            // 父目录
    char  d2name[64];            // 爷目录
    char  d3name[64];            // 曾祖目录
};

// IO 起始信息：issue 阶段记录的临时信息
struct io_start_info {
    __u64 inode;                // 文件 inode
    __u32 pid;                  // 进程 PID
    __u32 dev;                  // 设备号
    __u64 data_len;             // IO 数据长度
    char  comm[16];             // 进程名
};

// 块层 issue/done 配对的 key
struct hash_key {
    __u32 dev;       // 设备号
    __u32 _pad;
    __u64 sector;    // 扇区号(唯一标识 IO 请求)
};
```

### BPF Maps

```c
// 1. IO 统计 map - 存储聚合后的 IO 数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __uint(key_size, sizeof(struct io_key));
    __uint(value_size, sizeof(struct io_data));
} io_source_map SEC(".maps");

// 2. IO 起始信息 map - 用于 issue/done 配对
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(struct hash_key));
    __uint(value_size, sizeof(struct io_start_info));
} start_info_map SEC(".maps");

// 3. IO 调度堆栈 map - 用于追踪 io_schedule 延迟 (可选)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // pid
    __uint(value_size, sizeof(struct iodelay_entry));
    __uint(max_entries, 128);
} io_schedule_stack SEC(".maps");

// 4. IO 延迟事件 perf buffer - 发送超阈值的延迟事件 (可选)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} iodelay_perf_events SEC(".maps");
```

---

## 🪝 BPF 钩子设计

### 1. 块层钩子 (核心)

```c
SEC("kprobe/rq_qos_issue")
// IO 提交到块设备队列时触发
// - 记录: 设备号、扇区号、inode、PID、时间戳
// - 保存到 start_info_map 等待 done 时匹配

SEC("kprobe/rq_qos_done")
// IO 完成时触发
// - 通过(dev, sector)查找 issue 阶段信息
// - 计算延迟: q2c, d2c
// - 累加字节数: block_read/write_bytes
// - 更新到 io_source_map
```

### 2. 文件系统钩子

```c
SEC("kprobe/ext4_file_read_iter")
SEC("kprobe/ext4_file_write_iter")
SEC("kprobe/xfs_file_read_iter")
SEC("kprobe/xfs_file_write_iter")
// 文件系统读写操作时触发
// - 提取: inode, 文件路径(3级目录), 读写字节数
// - 累加: fs_read/write_bytes
// - 更新到 io_source_map
```

### 3. 页面缓存钩子

```c
SEC("kprobe/filemap_fault")
// mmap 读取触发页面错误
// - 累加 PAGE_SIZE 到 fs_read_bytes

SEC("kprobe/anyfs_filemap_page_mkwrite")
// mmap 写入触发页面写回 (通用，适配 ext4/xfs)
// - 累加 PAGE_SIZE 到 fs_write_bytes
```

### 4. IO 调度延迟追踪 (可选，高级功能)

```c
SEC("kprobe/io_schedule")
SEC("kprobe/io_schedule_timeout")
// 进程因等待 IO 而阻塞时触发
// - 记录时间戳和内核堆栈
// - 保存到 io_schedule_stack map

SEC("kretprobe/io_schedule")
SEC("kretprobe/io_schedule_timeout")
// io_schedule 返回时触发
// - 计算阻塞时间
// - 如果超过阈值(如 100ms)，通过 perf event 发送到用户空间
// - 包含堆栈信息，用于分析为什么阻塞
```

**用途**：发现哪些进程因为慢速 IO 而长时间阻塞，以及阻塞时的调用栈。

---

## 🔄 数据流程

```
┌────────────────────────────────────────────────────────────┐
│                     用户进程                                │
│              read()/write()/mmap()                         │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│                  文件系统层 (VFS)                           │
│   ext4_file_read_iter / xfs_file_write_iter (BPF Hook)     │
│   ✅ 捕获: fs_read_bytes, fs_write_bytes                   │
│   ✅ 提取: inode, 文件路径, PID, comm                      │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│                    页面缓存层                               │
│              (缓存命中则不走块层)                            │
└────────────────────────────────────────────────────────────┘
                         ↓ (缓存未命中)
┌────────────────────────────────────────────────────────────┐
│                     块层 (Block)                            │
│   rq_qos_issue (BPF Hook)                                  │
│   ✅ 记录: start_time, dev, sector, inode                  │
│   ✅ 保存到 start_info_map[dev, sector]                    │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│                    磁盘设备                                 │
│                  (执行实际 IO)                              │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│   rq_qos_done (BPF Hook)                                   │
│   ✅ 查找 start_info_map[dev, sector]                      │
│   ✅ 计算延迟: q2c, d2c                                    │
│   ✅ 累加: block_read_bytes, block_write_bytes             │
│   ✅ 更新到 io_source_map[pid, dev, inode]                │
│   ✅ 删除 start_info_map[dev, sector]                      │
└────────────────────────────────────────────────────────────┘
                         ↓
┌────────────────────────────────────────────────────────────┐
│              用户态程序读取 io_source_map                   │
│   - 按 PID 聚合并排序                                       │
│   - 格式化输出                                              │
└────────────────────────────────────────────────────────────┘
```

---

## 📤 输出格式设计

### 进程级汇总

```
PID     COMMAND              FS_READ  FS_WRITE  DISK_READ  DISK_WRITE  FILES
======  ===================  =======  ========  =========  ==========  =====
1234    mysqld               5.2GB    1.8GB     5.1GB      1.7GB       156
5678    java_app             120MB    5.6GB     115MB      5.5GB       23
```

### 文件级详情

```
===========================================================================
PID: 1234     COMMAND: mysqld     TOTAL_IO: R=5.2GB W=1.8GB     FILES: 156
---------------------------------------------------------------------------
DEVICE  FS_READ  FS_WRITE  DISK_READ  DISK_WRITE  Q2C_AVG  Q2C_MAX  D2C_AVG  D2C_MAX  FILE
8:0     3.2GB    800MB     3.1GB      780MB       450μs    2.1ms    380μs    1.8ms    /var/lib/mysql/ibdata1
8:0     1.5GB    600MB     1.4GB      590MB       520μs    3.5ms    410μs    2.9ms    /var/lib/mysql/ib_logfile0
```

#### IO 调度延迟报告 (可选)

如果进程因 IO 阻塞超过阈值(如 100ms)，输出：

```
===========================================================================
IO SCHEDULE DELAYS (processes blocked on IO > 100ms)
---------------------------------------------------------------------------
PID     COMMAND      BLOCKED_TIME  STACK_TRACE
1234    mysqld       156ms         io_schedule+0x10
                                   wait_on_page_bit_common+0x120
                                   filemap_fault+0x8a0
                                   ...
```

---

## 🚀 实施步骤

### 阶段 1: BPF 端开发

1. ✅ 设计核心数据结构 (io_key, io_data, io_start_info, latency_info)
2. ✅ 实现块层钩子 (rq_qos_issue/done)
3. ✅ 实现文件系统钩子 (ext4/xfs_file_*_iter)
4. ✅ 实现页面缓存钩子 (filemap_fault/page_mkwrite)
5. ✅ 实现 issue/done 配对逻辑
6. ✅ 实现延迟计算 (q2c_avg, q2c_max, d2c_avg, d2c_max)
7. 🔧 (可选) 实现 io_schedule 延迟追踪

### 阶段 2: 用户态开发

1. ✅ 创建 skeleton 框架
2. ✅ 实现 map 数据读取
3. ✅ 实现数据聚合和排序
4. ✅ 实现格式化输出
5. ✅ 添加命令行参数支持 (duration, device filter)

### 阶段 3: 测试与优化

1. ✅ 功能测试
2. ✅ 性能测试
3. ✅ 边界条件测试

---

## ⚙️ 命令行参数设计

```bash
# 基本用法
sudo ./iotrace --duration 10        # 追踪 10 秒

# 设备过滤
sudo ./iotrace --device sda         # 只追踪 sda 设备

# Top N 控制
sudo ./iotrace --top-processes 20   # 显示前 20 个进程
sudo ./iotrace --top-files 50       # 每个进程显示前 50 个文件
```

---

## 🔍 与 huatuo 的区别

| 特性 | huatuo iotracing | 我们的 iotrace |
|------|-----------------|---------------|
| 语言 | Go + BPF | C + BPF |
| 输出 | JSON/文本 | 文本 |
| Agent 支持 | ✅ | ❌ (不需要) |
| 容器支持 | ✅ | ❌ (简化) |
| Autotracing | ✅ | ❌ (简化) |
| 核心追踪逻辑 | ✅ | ✅ (移植) |
| 延迟分析 | ✅ | ✅ |
| 文件路径 | ✅ | ✅ |

---

## 📝 代码复用策略

### 从 captrace 复用:

- ✅ C 程序框架结构
- ✅ skeleton 加载和初始化
- ✅ signal 处理
- ✅ libbpf 错误处理
- ✅ 命令行参数解析框架

### 从 huatuo 移植:

- ✅ BPF 端的数据结构定义
- ✅ 块层钩子实现 (rq_qos_issue/done)
- ✅ 文件系统钩子实现
- ✅ 页面缓存钩子实现
- ✅ issue/done 配对逻辑
- ✅ 延迟计算逻辑
- ✅ 设备号和文件路径提取

### 新增实现:

- ✅ C 语言的数据聚合和排序
- ✅ 简化的文本输出格式
- ✅ 命令行参数处理

---

## 🎯 技术要点

### 1. 设备过滤器配置

```c
// 使用 volatile const 数组，用户态可通过 rodata section 配置
volatile const u32 FILTER_DEVS[16] = {};
volatile const u32 FILTER_DEV_COUNT = 0;

// 检查函数
static __always_inline int should_process_device(u32 dev)
{
    if (FILTER_DEV_COUNT == 0)
        return 1;  // 不过滤，处理所有设备
    
    for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
        if (FILTER_DEVS[i] == dev)
            return 1;  // 在白名单中
    
    return 0;  // 过滤掉
}
```

### 2. issue/done 配对机制

- **关键**: 使用 (dev, sector) 作为唯一标识
- **issue 时**: 保存到 start_info_map
- **done 时**: 查找并删除

### 3. 数据聚合策略

- 在 BPF 端按 (pid, dev, inode) 聚合
- 减少用户空间处理压力
- 使用 map update 进行累加
- 首次访问时初始化 tgid, comm, 文件路径

### 4. 延迟计算

```c
// BPF 端计算并更新
now = bpf_ktime_get_ns();
u64 q2c = now - BPF_CORE_READ(req, start_time_ns);
u64 d2c = now - BPF_CORE_READ(req, io_start_time_ns);

entry->latency.sum_q2c += q2c;
entry->latency.sum_d2c += d2c;
entry->latency.cnt++;

// 更新最大值
if (q2c > entry->latency.max_q2c)
    entry->latency.max_q2c = q2c;
if (d2c > entry->latency.max_d2c)
    entry->latency.max_d2c = d2c;

// 用户态计算
avg_q2c = sum_q2c / cnt;
avg_d2c = sum_d2c / cnt;
```

### 5. 文件路径提取

- 从 dentry 提取 3 级目录名
- 用户态拼接完整路径: `d3name/d2name/d1name/filename`

### 6. IO 调度延迟追踪 (高级功能)

```c
// 进入 io_schedule 时
SEC("kprobe/io_schedule")
- 记录 timestamp
- 捕获内核堆栈 (bpf_get_stack)
- 保存到 io_schedule_stack[pid]

// 返回 io_schedule 时
SEC("kretprobe/io_schedule")
- 计算 cost = now - timestamp
- 如果 cost > 阈值(100ms)
  - 通过 perf event 发送到用户空间
  - 包含堆栈信息
```

---

## 🔧 关键技术细节

### 块层 IO 追踪原理

#### issue/done 配对流程

```
步骤 1: rq_qos_issue（IO 提交时）
  ├─ 触发进程：业务进程（如 mysqld, pid=1234）
  ├─ 捕获信息：
  │   ├─ pid = 1234
  │   ├─ dev = 8:0
  │   ├─ sector = 12345
  │   ├─ inode = 3456789
  │   └─ data_len = 16384
  └─ 保存到 start_info_map[key=(dev=8:0, sector=12345)]
      └─ value = {pid=1234, inode=3456789, data_len=16384, ...}

步骤 2: [磁盘处理 IO...]

步骤 3: rq_qos_done（IO 完成时）
  ├─ 触发进程：可能是 kworker（不重要）
  ├─ 捕获信息：
  │   ├─ dev = 8:0
  │   └─ sector = 12345
  ├─ 从 start_info_map 查找：key=(dev=8:0, sector=12345)
  │   └─ 找到 issue 阶段保存的信息！
  │       ├─ pid = 1234  ← 关键：这是发起 IO 的进程
  │       ├─ inode = 3456789
  │       └─ data_len = 16384
  ├─ 计算：q2c = now - start_time_ns
  ├─ 更新到 io_source_map[key=(pid=1234, inode=3456789, dev=8:0)]
  │   └─ block_read_bytes += 16384
  │   └─ sum_q2c += q2c
  └─ 删除 start_info_map 中的临时记录
```

### 为什么 FS_READ 和 DISK_READ 可能不一样？

| 场景 | FS_READ | DISK_READ | 原因 |
|------|---------|-----------|------|
| **缓存命中** | 16KB | 0 | 数据在页面缓存中，不需要读磁盘 |
| **预读** | 16KB | 32KB | 内核预读了相邻数据 |
| **直接 IO** | 16KB | 16KB | 绕过缓存，两者相等 |
| **压缩文件** | 50KB | 10KB | 文件系统压缩后实际存储更少 |
| **写回** | 100KB | 0 | 写入缓存，尚未刷盘 |

---

## 📊 性能考虑

### BPF Map 大小设计

- `io_source_map`: 512 条目
  - 假设追踪 Top 100 进程，每进程平均 5 个文件
  - 512 = 100 × 5 (有余量)

- `start_info_map`: 4096 条目
  - 支持高并发 IO 场景
  - 临时存储，IO 完成后立即删除
  - 4096 足够应对大多数场景

### 内存占用估算

- `io_source_map`: 512 × ~300 bytes = ~150KB
- `start_info_map`: 4096 × ~50 bytes = ~200KB
- **总计**: ~350KB (非常小)

---

## 🐛 调试技巧

### 1. 验证 BPF 程序是否挂载成功

```bash
# 查看已挂载的 kprobe
sudo cat /sys/kernel/debug/tracing/kprobe_events | grep rq_qos

# 查看 BPF maps
sudo bpftool map list | grep io_source
```

### 2. 检查 map 内容

```bash
# 读取 io_source_map
sudo bpftool map dump name io_source_map

# 读取 start_info_map
sudo bpftool map dump name start_info_map
```

### 3. 追踪 BPF 程序执行

```bash
# 查看 kprobe 触发次数
sudo cat /sys/kernel/debug/tracing/kprobe_profile | grep rq_qos
```

---

## 📖 参考资料

### 核心参考文档

- **huatuo iotracing 源码分析**: `/Users/user/TC/huatuo/docs/iotracing_source_analysis.md`
  - 完整的 iotracing 技术原理和源码解析
  - 包含数据流程、输出格式、技术细节等
- **huatuo 项目地址**: `https://github.com/ccfos/huatuo`

### 主要参考源码

#### huatuo iotracing (Go + BPF 实现)

**BPF 端** (主要参考)：
- 文件路径: `/Users/user/TC/huatuo/bpf/iotracing.c`
- 总行数: ~620 行
- 关键内容:
  - 块层钩子: `rq_qos_issue`, `rq_qos_done` (行 171-305)
  - 文件系统钩子: `anyfs_file_read_iter`, `anyfs_file_write_iter` (行 345-420)
  - 页面缓存钩子: `filemap_fault`, `anyfs_filemap_page_mkwrite` (行 423-508)
  - IO 调度延迟: `io_schedule`, `io_schedule_timeout` (行 510-619)
  - 数据结构定义: (行 1-110)
  - 辅助函数: `get_request_disk`, `get_partition_number`, `init_io_data` 等

**用户态** (参考数据处理逻辑)：
- 文件路径: `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go`
- 总行数: ~756 行
- 关键内容:
  - BPF 程序加载和挂载: `mainAction`, `attachAndEventPipe`
  - Map 数据读取: `DumpMapByName("io_source_map")`
  - 数据聚合和排序: `SortTable`, `FileTable` 优先队列
  - 格式化输出: `printIOTracingData`
  - 设备号解析: `parseDevice`
  - 容器信息提取: `HostnameByPid` (我们简化版不需要)

#### captrace (C + BPF 实现，作为框架参考)

**BPF 端** (参考框架结构)：
- 文件路径: `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.bpf.c`
- 总行数: ~204 行
- 参考点:
  - Ringbuf 使用方式 (我们用 hash map，不用 ringbuf)
  - 过滤器实现: `ignored_caps_bitmap`, `filter_net_ns_inum`
  - 堆栈采集: `bpf_get_stackid`
  - 数据结构定义

**用户态** (参考框架结构)：
- 文件路径: `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c`
- 总行数: ~655 行
- 参考点:
  - Skeleton 加载: `captrace_bpf__open_opts`, `captrace_bpf__load`, `captrace_bpf__attach`
  - 命令行参数解析: `getopt_long`
  - Signal 处理: `handle_signal`
  - 内核符号解析: `load_kernel_symbols`, `resolve_kernel_symbol`
  - BTF 路径处理
  - 事件处理循环

### 代码复用策略总结

| 来源 | 复用内容 | 用途 |
|------|---------|------|
| **huatuo BPF 端** | 完整的 IO 追踪逻辑 | 核心功能实现 |
| - 块层钩子 | `rq_qos_issue/done` | issue/done 配对 |
| - 文件系统钩子 | `anyfs_file_*_iter` | 文件系统层统计 |
| - 页面缓存钩子 | `filemap_fault`, `page_mkwrite` | mmap IO 追踪 |
| - 数据结构 | `io_key`, `io_data`, `latency_info` | 数据聚合 |
| - 辅助函数 | `should_process_device` 等 | 设备过滤、兼容性 |
| **huatuo 用户态** | 数据处理思路 | 参考实现 |
| - Map 读取 | `DumpMapByName` | 读取 BPF map |
| - 数据聚合 | 优先队列排序 | 性能优化 |
| - 格式化输出 | 表格展示 | 输出格式 |
| **captrace 用户态** | C 程序框架 | 直接复用 |
| - Skeleton 加载 | `*_bpf__open/load/attach` | BPF 程序生命周期 |
| - 参数解析 | `getopt_long` | 命令行接口 |
| - 错误处理 | libbpf 错误处理 | 健壮性 |
| - 符号解析 | kallsyms 解析 | 堆栈符号化 |

### 目录结构参考

```
huatuo 项目结构:
├── bpf/
│   ├── iotracing.c              ⬅️ 主要参考: BPF 端实现
│   ├── include/
│   │   ├── bpf_common.h         (通用 BPF 宏和定义)
│   │   └── vmlinux.h
├── cmd/
│   └── iotracing/
│       ├── iotracing.go          ⬅️ 参考: 数据处理逻辑
│       ├── iotracing_priority_queue.go
│       └── sort.go
└── internal/
    ├── bpf/                      (BPF 管理器)
    ├── symbol/                   (符号解析)
    └── utils/                    (工具函数)

captrace 项目结构:
└── examples/c/
    ├── captrace.bpf.c            ⬅️ 参考: C+BPF 框架
    └── captrace.c                ⬅️ 参考: 用户态框架
```

---

## ✅ TODO 清单

### 阶段 1: BPF 端开发
- [ ] 1. 设计 iotrace BPF 端核心数据结构(io_key, io_data, latency_info等)
- [ ] 2. 实现内核版本兼容性辅助函数(get_request_disk/get_partition_number)
- [ ] 3. 实现 BPF 端块层钩子(rq_qos_issue/done)用于IO追踪
- [ ] 4. 实现 BPF 端文件系统钩子(anyfs_file_read/write_iter，含iov_iter兼容)
- [ ] 5. 实现 BPF 端页面缓存钩子(filemap_fault/anyfs_filemap_page_mkwrite)
- [ ] 5.5 (可选) 实现 io_schedule 延迟追踪钩子

### 阶段 2: 用户态开发
- [ ] 5. 创建用户态 C 程序框架(skeleton加载、ringbuf处理)
- [ ] 6. 实现用户态事件处理函数(数据聚合、格式化输出)
- [ ] 7. 添加设备过滤和命令行参数支持

### 阶段 3: 延迟统计与展示
- [ ] 8. 实现延迟统计(q2c/d2c)和数据展示

### 阶段 4: 测试
- [ ] 9. 测试和验证程序功能

---

## 🎉 预期成果

完成后，我们将拥有一个简洁高效的 IO 追踪工具：

- ✅ **轻量级**: 纯 C 实现，无需 Go 运行时
- ✅ **精准**: 进程级别的 IO 归属分析
- ✅ **全面**: 文件系统层 + 块设备层完整追踪
- ✅ **直观**: 清晰的文本输出格式
- ✅ **高效**: BPF 端聚合，用户态处理压力小

---

## 📌 补充功能说明 (2025-01-08 更新)

### ⚠️ 用户态代码补充遗漏 (第二次审查)

在详细审查 `huatuo/cmd/iotracing/iotracing.go` 后，发现以下重要功能：

#### 1. **动态文件系统检测和挂载** ⭐⭐⭐ (重要)

**功能**：根据系统支持的文件系统动态挂载 BPF 程序

**实现** (Go 代码 298-336 行)：
```go
func fsBpfOption() []bpf.AttachOption {
    var opts []bpf.AttachOption
    
    // 检查是否支持 ext4
    if procfsutil.FsSupported("ext4") {
        opts = append(opts, []bpf.AttachOption{
            {ProgramName: "bpf_anyfs_file_read_iter", Symbol: "ext4_file_read_iter"},
            {ProgramName: "bpf_anyfs_file_write_iter", Symbol: "ext4_file_write_iter"},
            {ProgramName: "bpf_anyfs_filemap_page_mkwrite", Symbol: "ext4_page_mkwrite"},
        }...)
    }
    
    // 检查是否支持 xfs
    if procfsutil.FsSupported("xfs") {
        opts = append(opts, []bpf.AttachOption{
            {ProgramName: "bpf_anyfs_file_read_iter", Symbol: "xfs_file_read_iter"},
            {ProgramName: "bpf_anyfs_file_write_iter", Symbol: "xfs_file_write_iter"},
            {ProgramName: "bpf_anyfs_filemap_page_mkwrite", Symbol: "xfs_filemap_page_mkwrite"},
        }...)
    }
    
    return opts
}
```

**如何检测** (读取 `/proc/filesystems`):
```c
// C 实现伪代码
bool is_fs_supported(const char *fs_name) {
    FILE *f = fopen("/proc/filesystems", "r");
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, fs_name))
            return true;
    }
    return false;
}
```

**为什么重要**：
- ✅ 避免在不支持的文件系统上挂载导致失败
- ✅ 自动适配系统环境（有些系统只有 ext4，有些只有 xfs）
- ✅ 提高兼容性

#### 2. **kprobe 函数可用性检测** ⭐⭐⭐ (重要)

**功能**：检查内核是否支持特定的 kprobe 函数

**实现** (Go 代码 272-292 行)：
```go
func checkKprobeFunctionExists(functionName string) bool {
    file, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
    if err != nil {
        return false
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        name := strings.Fields(line)[0]
        if name == functionName {
            return true
        }
    }
    return false
}
```

**使用场景** (Go 代码 364-371 行)：
```go
// 动态选择 rq_qos_issue 或 __rq_qos_issue
var requestQosIssue, requestQosDone string
if checkKprobeFunctionExists("rq_qos_issue") {
    requestQosIssue = "rq_qos_issue"
    requestQosDone = "rq_qos_done"
} else {
    requestQosIssue = "__rq_qos_issue"    // 5.0+ 内核
    requestQosDone = "__rq_qos_done"
}
```

**为什么重要**：
- ✅ 4.19 内核使用 `rq_qos_issue`
- ✅ 5.0+ 内核改为 `__rq_qos_issue`
- ✅ 自动适配，无需用户干预

**C 实现**：
```c
bool check_kprobe_exists(const char *func_name) {
    FILE *f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
    if (!f) return false;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *space = strchr(line, ' ');
        if (space) *space = '\0';
        if (strcmp(line, func_name) == 0) {
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}
```

#### 3. **kretprobe 优先挂载顺序** ⭐⭐ (性能优化)

**问题**：`io_schedule` 的 kprobe 和 kretprobe 挂载顺序很重要

**解决方案** (Go 代码 396-411 行)：
```go
// 确保先挂载 kretprobe，再挂载 kprobe
switch symbol[0] {
case "kretprobe":
    // 插入到列表开头
    defaultOption = append([]bpf.AttachOption{
        {ProgramName: i.Name, Symbol: symbol[1]},
    }, defaultOption...)
default:
    // 插入到列表末尾
    defaultOption = append(defaultOption, bpf.AttachOption{
        ProgramName: i.Name, Symbol: symbol[1],
    })
}
```

**为什么重要**：
- ✅ kretprobe 必须在 kprobe 之前注册
- ✅ 否则堆栈信息可能无法正确获取
- ✅ 这是 io_schedule 延迟追踪的关键

#### 4. **设备号解析和验证** ⭐⭐

**功能**：解析用户输入的设备号 (如 "8:0,253:0")

**实现** (Go 代码 154-197 行)：
```go
func parseDeviceNumbers(deviceStr string) ([]uint32, error) {
    var deviceNums []uint32
    
    deviceSpecs := strings.Split(deviceStr, ",")  // 支持多设备
    for _, spec := range deviceSpecs {
        parts := strings.Split(spec, ":")
        
        major, _ := strconv.ParseUint(parts[0], 10, 32)
        minor, _ := strconv.ParseUint(parts[1], 10, 32)
        
        // 转换为内核设备号格式
        devNum := (uint32(major)&0xfff)<<20 | uint32(minor)
        deviceNums = append(deviceNums, devNum)
    }
    
    // 限制最多 16 个设备
    if len(deviceNums) > 16 {
        return nil, fmt.Errorf("too many devices (max 16)")
    }
    
    return deviceNums, nil
}
```

**设备号格式**：
- **输入格式**: `major:minor` (如 8:0 表示 /dev/sda)
- **内核格式**: `(major & 0xfff) << 20 | minor`
- **支持多设备**: 逗号分隔 (如 "8:0,253:0")

**如何找设备号**：
```bash
# 方法 1: ls -l
ls -l /dev/sda
# brw-rw---- 1 root disk 8, 0 Jan  8 10:00 /dev/sda
#                         ^  ^
#                       major minor

# 方法 2: lsblk
lsblk -o NAME,MAJ:MIN
# NAME   MAJ:MIN
# sda      8:0
# ├─sda1   8:1
# └─sda2   8:2
```

#### 5. **数据聚合使用优先队列** ⭐⭐ (性能优化)

**功能**：高效地获取 Top N 进程和文件

**实现** (使用 Go 的 heap 包)：
```go
// 进程级排序 - 按 IO 总量
sortTable := NewSortTable()
for _, data := range iodata {
    blkSize := data.BlockWriteBytes + data.BlockReadBytes
    sortTable.Update(data.Pid, blkSize)  // 累加每个进程的 IO
}
pids := sortTable.TopKeyN(int(maxProcess))  // 获取 Top N

// 文件级排序 - 每个进程的 Top 文件
fileTable := NewFileTable()
for _, data := range iodata {
    fileTable.Update(data.Pid, &IODataStat{&data, blkSize})
}
files := fileTable.QueueByKey(pid)  // 获取该进程的所有文件
```

**为什么不用简单排序**：
- ✅ 优先队列时间复杂度 O(n log k)，k = Top N
- ✅ 简单排序时间复杂度 O(n log n)
- ✅ 当 n 很大，k 很小时，优先队列更快

**C 实现建议**：
- 可以用 qsort 简化（性能差异在可接受范围）
- 或实现简单的小顶堆

#### 6. **cmdline 读取优化** ⭐

**功能**：获取进程完整命令行（不是简短的 comm）

**实现** (Go 代码 251-254 行)：
```go
cmdline, err := procfsutil.ProcNameByPid(pid)
if err != nil {
    cmdline = comm  // 降级到 comm (16 字符)
}
```

**读取方式** (读取 `/proc/[pid]/cmdline`):
```c
char* get_proc_cmdline(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    
    static char cmdline[256];
    size_t n = fread(cmdline, 1, sizeof(cmdline)-1, f);
    fclose(f);
    
    // 将 \0 分隔符替换为空格
    for (size_t i = 0; i < n; i++) {
        if (cmdline[i] == '\0' && i < n-1)
            cmdline[i] = ' ';
    }
    cmdline[n] = '\0';
    return cmdline;
}
```

**输出差异**：
- **comm**: `mysqld` (只有 16 字符)
- **cmdline**: `/usr/sbin/mysqld --defaults-file=/etc/mysql/my.cnf` (完整命令)

#### 7. **Direct IO 标识** ⭐

**功能**：标识是否为 Direct IO（绕过页面缓存）

**实现** (Go 代码 142-149 行)：
```go
if data.InodeNum == 0 {
    fileName = "[direct IO]"
}

// 检查 IOCB_DIRECT 标志 (bit 2)
if data.Flag & 0x4 == 0x4 {
    fileName += " [direct IO]"
}
```

**为什么重要**：
- ✅ Direct IO 绕过页面缓存，FS_READ ≈ DISK_READ
- ✅ 帮助理解 IO 行为
- ✅ 数据库常用 Direct IO

#### 8. **字节格式化** ⭐

**功能**：人类可读的字节单位 (B/KB/MB/GB/TB/PB)

**实现** (Go 代码 688-706 行)：
```go
func formatBytes(nbytes uint64) string {
    units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
    i := 0
    value := float64(nbytes)
    
    for value >= 1024 && i < len(units)-1 {
        value /= 1024
        i++
    }
    
    // 小于 10 时显示 1 位小数
    if value < 10 && i > 0 {
        return fmt.Sprintf("%.1f%s", value, units[i])
    }
    return fmt.Sprintf("%.0f%s", value, units[i])
}
```

**输出示例**：
- `1536` → `1.5KB`
- `1048576` → `1.0MB`
- `1073741824` → `1GB`

---

## 🎯 v1 必须实现的用户态功能清单（更新）

### 核心功能
1. ✅ **动态文件系统检测**
   - 检查 `/proc/filesystems`
   - 根据支持的文件系统动态挂载

2. ✅ **kprobe 函数可用性检测**
   - 检查 `/sys/kernel/debug/tracing/available_filter_functions`
   - 自动选择 `rq_qos_issue` 或 `__rq_qos_issue`

3. ✅ **设备号解析**
   - 支持 `major:minor` 格式
   - 支持多设备（逗号分隔）
   - 最多 16 个设备

4. ✅ **Map 数据读取和反序列化**
   - 使用 `bpf_map_get_next_key` + `bpf_map_lookup_elem`
   - 二进制反序列化 (little-endian)

5. ✅ **数据排序**
   - 按 IO 总量排序进程
   - 按 IO 量排序每个进程的文件
   - Top N 选择

6. ✅ **格式化输出**
   - 进程级汇总表格
   - 文件级详情表格
   - 字节单位格式化
   - 延迟单位 (微秒)
   - Direct IO 标识

### 高级功能 (v2 或可选)
7. 🔧 **容器支持** (我们简化版不需要)
8. 🔧 **JSON 输出** (我们简化版不需要)
9. 🔧 **io_schedule 延迟追踪** (v2 实现)

### ✅ 新增功能清单

在详细研读 huatuo 源码后，发现并补充了以下重要功能：

#### 1. **延迟统计增强** ⭐⭐⭐ (重要)

**之前的设计**：只记录 sum 和 count，计算平均值
```c
__u64 sum_q2c;
__u64 sum_d2c;
__u64 latency_count;
```

**现在的设计**：增加最大值统计
```c
struct latency_info {
    __u64 cnt;       // IO 计数
    __u64 max_d2c;   // 最大设备到完成延迟 ⬅️ 新增
    __u64 sum_d2c;   // 累计设备到完成延迟
    __u64 max_q2c;   // 最大队列到完成延迟 ⬅️ 新增
    __u64 sum_q2c;   // 累计队列到完成延迟
};
```

**优势**：
- 可以看到平均延迟和峰值延迟
- 帮助发现偶发的性能抖动
- 更全面的性能分析

**输出格式改进**：
```
DEVICE  FS_READ  FS_WRITE  DISK_READ  DISK_WRITE  Q2C_AVG  Q2C_MAX  D2C_AVG  D2C_MAX  FILE
8:0     3.2GB    800MB     3.1GB      780MB       450μs    2.1ms    380μs    1.8ms    /var/lib/mysql/ibdata1
```

#### 2. **IO 调度延迟追踪** ⭐⭐⭐ (可选高级功能)

**功能**：追踪进程因等待 IO 而阻塞的时间

**实现钩子**：
```c
// 进入 io_schedule 时
SEC("kprobe/io_schedule")
SEC("kprobe/io_schedule_timeout")
- 记录开始时间戳 (bpf_ktime_get_ns)
- 捕获内核堆栈 (bpf_get_stack)
- 保存到 io_schedule_stack map

// 返回 io_schedule 时
SEC("kretprobe/io_schedule")
SEC("kretprobe/io_schedule_timeout")
- 计算阻塞时间 cost = now - start_time
- 如果 cost > 阈值(默认 100ms)
  - 通过 perf event 发送到用户空间
  - 包含完整的内核堆栈信息
```

**数据结构**：
```c
struct iodelay_entry {
    u64 stack[PERF_MIN_STACK_DEPTH];  // 内核堆栈
    u64 ts;                            // 开始时间戳
    u64 cost;                          // 延迟时间（纳秒）
    int stack_size;                    // 堆栈深度
    u32 pid;                           // 进程 PID
    u32 tid;                           // 线程 TID
    u32 cpu;                           // CPU 编号
    char comm[TASK_COMM_LEN];          // 进程名
};
```

**输出格式**：
```
===========================================================================
IO SCHEDULE DELAYS (processes blocked on IO > 100ms)
---------------------------------------------------------------------------
PID     COMMAND      BLOCKED_TIME  STACK_TRACE
1234    mysqld       156ms         io_schedule+0x10
                                   wait_on_page_bit_common+0x120
                                   filemap_fault+0x8a0
                                   ext4_filemap_fault+0x2c
                                   __do_fault+0x38
                                   do_fault+0x15e
                                   ...
```

**用途**：
- 发现哪些进程因慢速 IO 而长时间阻塞
- 通过堆栈分析阻塞发生在内核的哪个路径
- 区分不同类型的 IO 阻塞（读、写、元数据等）

#### 3. **设备过滤器实现细节**

**配置方式**：
```c
// BPF 端定义
volatile const u32 FILTER_DEVS[16] = {};
volatile const u32 FILTER_DEV_COUNT = 0;

// 过滤函数
static __always_inline int should_process_device(u32 dev)
{
    if (FILTER_DEV_COUNT == 0)
        return 1;  // 不过滤，处理所有设备
    
    for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
        if (FILTER_DEVS[i] == dev)
            return 1;  // 在白名单中，处理
    
    return 0;  // 不在白名单，过滤掉
}
```

**用户态配置**：
```c
// 在 skeleton load 之前，通过 rodata section 设置
skel->rodata->FILTER_DEV_COUNT = device_count;
for (int i = 0; i < device_count; i++) {
    skel->rodata->FILTER_DEVS[i] = device_numbers[i];
}
```

**支持场景**：
- 只追踪特定磁盘（如只看 nvme0n1）
- 过滤掉系统分区，只看数据分区
- 支持最多 16 个设备白名单

#### 4. **通用文件系统钩子命名**

**之前的命名**：
```c
SEC("kprobe/ext4_file_read_iter")
SEC("kprobe/xfs_file_read_iter")
```

**现在的命名**：
```c
SEC("kprobe/anyfs_file_read_iter")     // 通用命名
SEC("kprobe/anyfs_file_write_iter")
SEC("kprobe/anyfs_filemap_page_mkwrite")
```

**用户态动态挂载**：
```c
// 用户态根据系统支持的文件系统动态挂载
bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, 
                           false, "ext4_file_read_iter");
bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, 
                           false, "xfs_file_read_iter");
```

**优势**：
- 一个 BPF 程序支持多个文件系统
- 减少代码重复
- 更容易扩展到其他文件系统

#### 5. **内核版本兼容性处理** ⭐⭐⭐ (v1 必须实现)

Linux 内核在不同版本中对数据结构有所调整，必须使用 BPF CO-RE (Compile Once, Run Everywhere) 技术来保证兼容性。

##### 5.1 磁盘设备获取兼容

**问题**：5.10+ 内核将 `request->rq_disk` 移到了 `request->q->disk`

**解决方案**：
```c
// 定义新内核的结构（使用三个下划线后缀标记）
struct request_queue___new {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_request_disk(struct request *req)
{
    // 使用 bpf_core_field_exists 检查字段是否存在
    if (bpf_core_field_exists(req->rq_disk)) {
        // 旧内核 (<5.10): request->rq_disk 直接存在
        return BPF_CORE_READ(req, rq_disk);
    } else {
        // 新内核 (>=5.10): request->q->disk
        struct request_queue___new *q;
        q = (struct request_queue___new *)BPF_CORE_READ(req, q);
        return BPF_CORE_READ(q, disk);
    }
}
```

**支持内核版本**：
- ✅ Linux 4.x (旧内核)
- ✅ Linux 5.0-5.9 (中期内核)
- ✅ Linux 5.10+ (新内核)
- ✅ Linux 6.x (最新内核)

##### 5.2 分区号获取兼容

**问题**：5.11+ 内核将 `hd_struct` 改为 `block_device`

**解决方案**：
```c
// 定义新内核的结构
struct block_device___new {
    dev_t bd_dev;
} __attribute__((preserve_access_index));

static __always_inline int get_partition_number(struct request *req)
{
    void *part = BPF_CORE_READ(req, part);
    
    // 检查是否为旧的 hd_struct
    if (bpf_core_field_exists(((struct hd_struct *)part)->partno)) {
        // 旧内核: 使用 hd_struct->partno
        return BPF_CORE_READ((struct hd_struct *)part, partno);
    } else {
        // 新内核: 使用 block_device->bd_dev 的低 8 位
        struct block_device___new *new_part;
        int partno;
        new_part = (struct block_device___new *)part;
        partno = BPF_CORE_READ(new_part, bd_dev);
        return partno & 0xff;  // 取低 8 位作为分区号
    }
}
```

**支持内核版本**：
- ✅ Linux <5.11 (使用 hd_struct)
- ✅ Linux >=5.11 (使用 block_device)

##### 5.3 iov_iter 结构兼容

**问题**：6.4+ 内核将 `iov_iter->type` 改为 `iov_iter->data_source`

**解决方案**：
```c
// 定义新内核的 iov_iter 结构
struct iov_iter___new {
    bool data_source;  // 新内核使用 data_source
} __attribute__((preserve_access_index));

// 在文件读写处理函数中
struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2(ctx);
unsigned int type;

// 检查字段存在性
if (bpf_core_field_exists(from->type)) {
    // 旧内核 (<6.4): 使用 type 字段
    type = BPF_CORE_READ(from, type);
} else {
    // 新内核 (>=6.4): 使用 data_source 字段
    struct iov_iter___new *from_new;
    from_new = (struct iov_iter___new *)from;
    type = BPF_CORE_READ(from_new, data_source);
}

// 最低位表示读写方向: 0=read, 1=write
type = type & 0x1;
if (type)
    entry->fs_write_bytes += count;  // 写
else
    entry->fs_read_bytes += count;   // 读
```

**支持内核版本**：
- ✅ Linux <6.4 (使用 type)
- ✅ Linux >=6.4 (使用 data_source)

##### 5.4 兼容性测试建议

在以下内核版本上测试：
- **Ubuntu 20.04**: Linux 5.4 (LTS)
- **Ubuntu 22.04**: Linux 5.15 (LTS)
- **Ubuntu 24.04**: Linux 6.8 (LTS)
- **Fedora 39**: Linux 6.5+
- **RHEL 9**: Linux 5.14+

**关键原则**：
1. ✅ 使用 `bpf_core_field_exists()` 检查字段
2. ✅ 使用 `___new` 后缀定义新内核结构
3. ✅ 使用 `__attribute__((preserve_access_index))` 保持索引
4. ✅ 使用 `BPF_CORE_READ()` 读取内核数据
5. ✅ 避免直接指针解引用

---

## 🎯 实现策略：分阶段开发

基于补充的功能，我们调整实现策略为两个版本：

### **Version 1: 核心版本** (优先实现) 🎯

**目标**：实现完整的 IO 追踪功能，不包含高级特性

**包含功能**：
- ✅ 块层 IO 追踪 (rq_qos_issue/done)
- ✅ 文件系统层追踪 (anyfs_file_read/write_iter)
- ✅ 页面缓存追踪 (filemap_fault/anyfs_filemap_page_mkwrite)
- ✅ issue/done 配对机制
- ✅ 延迟统计 (avg + max)  ⬅️ 包含最大值
- ✅ 设备过滤器
- ✅ 文件路径提取 (3级目录)
- ✅ 进程级和文件级统计输出
- ✅ **内核版本兼容性处理** ⬅️ 必须实现！
  - `get_request_disk()` - 兼容不同内核的磁盘获取方式
  - `get_partition_number()` - 兼容不同内核的分区号获取
  - `iov_iter` 结构兼容 - 兼容 type/data_source 字段变化

**不包含**：
- ❌ io_schedule 延迟追踪
- ❌ 内核堆栈符号解析
- ❌ 容器支持
- ❌ JSON 输出

**预计工作量**：
- BPF 端：~550 行代码
  - 数据结构定义：~100 行
  - 内核兼容函数：~80 行 ⬅️ 新增
  - 块层钩子：~150 行
  - 文件系统钩子：~120 行
  - 页面缓存钩子：~100 行
- 用户态：~800 行代码
- 总计：~1350 行

**开发周期**：1-2 天

**测试重点**：
- ✅ 在多个内核版本上测试（5.4, 5.15, 6.8）
- ✅ 验证设备号正确获取
- ✅ 验证分区号正确解析
- ✅ 验证读写方向识别

---

### **Version 2: 增强版本** (可选扩展) 🚀

**目标**：添加高级诊断功能

**新增功能**：
- ✅ IO 调度延迟追踪 (io_schedule)
- ✅ 内核堆栈采集
- ✅ 堆栈符号解析 (/proc/kallsyms)
- ✅ 阻塞分析报告

**额外代码**：
- BPF 端：+200 行
- 用户态：+400 行

**开发周期**：1 天

---

## 📊 功能对比表

| 功能 | huatuo iotracing | iotrace v1 | iotrace v2 |
|------|-----------------|------------|------------|
| **语言** | Go + BPF | C + BPF | C + BPF |
| **块层追踪** | ✅ | ✅ | ✅ |
| **文件系统追踪** | ✅ | ✅ | ✅ |
| **页面缓存追踪** | ✅ | ✅ | ✅ |
| **延迟统计 (avg)** | ✅ | ✅ | ✅ |
| **延迟统计 (max)** | ✅ | ✅ | ✅ |
| **设备过滤** | ✅ | ✅ | ✅ |
| **文件路径提取** | ✅ | ✅ | ✅ |
| **内核版本兼容** | ✅ | ✅ | ✅ |
| **io_schedule 追踪** | ✅ | ❌ | ✅ |
| **内核堆栈** | ✅ | ❌ | ✅ |
| **Agent 模式** | ✅ | ❌ | ❌ |
| **容器支持** | ✅ | ❌ | ❌ |
| **Autotracing** | ✅ | ❌ | ❌ |
| **JSON 输出** | ✅ | ❌ | ❌ |

---

## 🏁 下一步行动

1. **立即开始 Version 1 开发**
   - 创建 `iotrace.bpf.c` - BPF 端核心实现
   - 创建 `iotrace.c` - 用户态程序
   - 实现基本的追踪和输出功能

2. **测试和验证**
   - 在测试系统上验证功能
   - 使用 dd、fio 等工具生成测试负载

3. **Version 2 评估**
   - 根据 Version 1 的使用反馈
   - 决定是否需要 io_schedule 追踪

---

## 🔑 关键代码片段速查

### BPF 端延迟计算（含最大值）

```c
// 在 rq_qos_done 中计算延迟
now = bpf_ktime_get_ns();
u64 q2c = now - BPF_CORE_READ(req, start_time_ns);
u64 d2c = now - BPF_CORE_READ(req, io_start_time_ns);

// 累加总和
entry->latency.sum_q2c += q2c;
entry->latency.sum_d2c += d2c;
entry->latency.cnt++;

// 更新最大值
if (q2c > entry->latency.max_q2c)
    entry->latency.max_q2c = q2c;
if (d2c > entry->latency.max_d2c)
    entry->latency.max_d2c = d2c;
```

### 用户态延迟展示

```c
// 计算平均值和最大值
if (data->latency.cnt > 0) {
    uint64_t avg_q2c_us = data->latency.sum_q2c / data->latency.cnt / 1000;
    uint64_t max_q2c_us = data->latency.max_q2c / 1000;
    uint64_t avg_d2c_us = data->latency.sum_d2c / data->latency.cnt / 1000;
    uint64_t max_d2c_us = data->latency.max_d2c / 1000;
    
    printf("Q2C: %lluμs (max %lluμs)  D2C: %lluμs (max %lluμs)\n",
           avg_q2c_us, max_q2c_us, avg_d2c_us, max_d2c_us);
}
```

### 设备号转换

```c
// 设备号编码: (major & 0xfff) << 20 | (minor + partno)
// 解码回 major:minor 格式
static void print_device(uint32_t dev)
{
    unsigned int major = (dev >> 20) & 0xfff;
    unsigned int minor = dev & 0xfffff;
    printf("%u:%u", major, minor);
}
```

---

**文档版本**: v1.1  
**创建时间**: 2025-01-08  
**最后更新**: 2025-01-08 (补充功能说明)  
**作者**: AI Assistant

