# iotrace 实现详解 (1/6): 整体架构与数据流

## 目录
1. [整体架构](#整体架构)
2. [数据流转过程](#数据流转过程)
3. [关键数据结构](#关键数据结构)
4. [设计思想](#设计思想)

---

## 1. 整体架构

iotrace 是一个基于 eBPF 的 IO 追踪工具，采用**分层追踪**的设计思想，在 Linux 内核的三个关键层面插入探针：

```
用户空间进程
    │
    ├─ read()/write()/mmap()  ← 应用层
    │
    ▼
┌─────────────────────────────────────────────┐
│  文件系统层 (VFS + ext4/xfs)                │
│  ├─ file_read_iter/file_write_iter         │ ← 🔍 探针层 1: 文件系统操作
│  └─ page_mkwrite                            │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  页缓存层 (Page Cache)                      │
│  └─ filemap_fault                           │ ← 🔍 探针层 2: mmap 读取
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  块设备层 (Block Layer)                     │
│  ├─ rq_qos_issue   (IO 提交)               │ ← 🔍 探针层 3: 块设备 IO
│  └─ rq_qos_done    (IO 完成)               │
└─────────────────────────────────────────────┘
    │
    ▼
物理磁盘
```

### 为什么需要三层追踪？

| 层级 | 追踪目的 | 捕获信息 |
|------|----------|----------|
| **文件系统层** | 捕获**谁**在操作**哪个文件** | 进程 PID、文件路径、文件系统读写字节数 |
| **页缓存层** | 捕获 mmap 方式的读写 | mmap 读写字节数（按页统计） |
| **块设备层** | 捕获**物理 IO** 和**延迟** | 块设备读写字节数、IO 延迟（q2c、d2c） |

---

## 2. 数据流转过程

### 场景 1: 普通文件读取 (read 系统调用)

```
┌─────────────┐
│ 用户进程    │ read(fd, buf, 4096)
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ 1️⃣ 文件系统层: ext4_file_read_iter                       │
│    Hook: bpf_anyfs_file_read_iter()                      │
│                                                           │
│    动作:                                                  │
│    • 提取 kiocb->ki_filp->f_inode (获取 inode)           │
│    • 提取 iov_iter->count (读取字节数)                   │
│    • 构建 key = {pid: 0, dev: sda_dev, inode: 12345}    │
│    • io_source_map[key].fs_read_bytes += 4096           │
│    • 保存文件路径: filename, d1name, d2name, d3name      │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ 2️⃣ 块设备层 Issue: rq_qos_issue                          │
│    Hook: bpf_rq_qos_issue()                              │
│                                                           │
│    动作:                                                  │
│    • 从 request 提取: dev, sector, data_len              │
│    • 从 bio 提取: inode (通过 bio->bi_io_vec->bv_page)  │
│    • 构建 hash_key = {dev: sda_dev, sector: 2048000}    │
│    • start_info_map[hash_key] = {                        │
│        inode: 12345,                                     │
│        pid: 1234,                                        │
│        data_len: 4096,                                   │
│        timestamp: start_time_ns                          │
│      }                                                    │
└──────────────────────────────────────────────────────────┘
       │
       │ (磁盘操作中...)
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ 3️⃣ 块设备层 Done: rq_qos_done                            │
│    Hook: bpf_rq_qos_done()                               │
│                                                           │
│    动作:                                                  │
│    • 构建 hash_key = {dev: sda_dev, sector: 2048000}    │
│    • 从 start_info_map[hash_key] 读取 issue 信息         │
│    • 计算延迟:                                            │
│      - q2c = now - req->start_time_ns                   │
│      - d2c = now - req->io_start_time_ns                │
│    • 构建 io_key = {pid: 0, dev: sda_dev, inode: 12345} │
│    • io_source_map[io_key].block_read_bytes += 4096     │
│    • io_source_map[io_key].latency.sum_q2c += q2c       │
│    • io_source_map[io_key].latency.sum_d2c += d2c       │
│    • 删除 start_info_map[hash_key]                       │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────┐
│ 用户态程序  │ 从 io_source_map 读取聚合数据
└─────────────┘
```

### 场景 2: mmap 读取

```
┌─────────────┐
│ 用户进程    │ 访问 mmap 映射的内存地址
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ 页缓存层: filemap_fault                                   │
│ Hook: bpf_filemap_fault()                                 │
│                                                           │
│ 动作:                                                     │
│ • 从 vm_fault->vma 提取 inode                             │
│ • io_source_map[key].fs_read_bytes += PAGE_SIZE (4096)  │
└──────────────────────────────────────────────────────────┘
       │
       ▼
   (后续流程同场景 1 的块设备层)
```

---

## 3. 关键数据结构

### 3.1 BPF Map: io_source_map

**用途**: 存储最终的 IO 统计数据（用户态会读取这个 map）

```c
struct io_key {
    __u32 pid;      // 进程 PID (Direct IO 时使用)
    __u32 dev;      // 设备号 (文件系统设备，不是块设备)
    __u64 inode;    // 文件 inode (Direct IO 时为 0)
};

struct io_data {
    __u32 pid;                      // 进程 PID
    __u32 tgid;                     // 线程组 ID
    __u32 dev;                      // 设备号
    __u32 flag;                     // IOCB 标志 (检测 Direct IO)
    __u64 fs_write_bytes;           // 文件系统层写入字节
    __u64 fs_read_bytes;            // 文件系统层读取字节
    __u64 block_write_bytes;        // 块设备层写入字节
    __u64 block_read_bytes;         // 块设备层读取字节
    __u64 inode;                    // Inode 号
    struct latency_info latency;    // 延迟统计
    char comm[16];                  // 进程名
    char filename[64];              // 文件名
    char d1name[64];                // 父目录
    char d2name[64];                // 祖父目录
    char d3name[64];                // 曾祖父目录
};

// Map 定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);      // ~100 进程 × 5 文件
    __uint(key_size, sizeof(struct io_key));
    __uint(value_size, sizeof(struct io_data));
} io_source_map SEC(".maps");
```

**聚合规则**:
- **普通文件 IO**: 按 `(pid=0, dev=文件系统设备, inode=文件inode)` 聚合
- **Direct IO**: 按 `(pid=进程PID, dev=块设备, inode=0)` 聚合

### 3.2 BPF Map: start_info_map

**用途**: 临时存储 IO issue 阶段的信息，等待 done 阶段匹配

```c
struct hash_key {
    __u32 dev;       // 块设备号
    __u32 _pad;
    __u64 sector;    // 扇区号 (唯一标识一个 IO 请求)
};

struct io_start_info {
    __u64 inode;                // 文件 inode
    __u32 pid;                  // 进程 PID
    __u32 dev;                  // 设备号 (可能是文件系统或块设备)
    __u64 data_len;             // IO 数据长度
    char  comm[16];             // 进程名
};

// Map 定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);     // 支持高并发 IO
    __uint(key_size, sizeof(struct hash_key));
    __uint(value_size, sizeof(struct io_start_info));
} start_info_map SEC(".maps");
```

**生命周期**:
1. `rq_qos_issue`: 插入记录
2. `rq_qos_done`: 读取记录 → 计算延迟 → **删除记录**

---

## 4. 设计思想

### 4.1 为什么要分两个 Map？

| Map | 用途 | Key | 生命周期 |
|-----|------|-----|----------|
| `start_info_map` | 临时匹配 issue/done | `(dev, sector)` | 短暂（微秒级） |
| `io_source_map` | 最终统计 | `(pid, dev, inode)` | 整个追踪期间 |

**原因**: 
- 块设备层只能看到 `(dev, sector)`，无法直接知道是哪个进程的哪个文件
- 文件系统层知道 `(pid, inode)`，但不知道物理 IO 和延迟
- 通过 `inode` 在两个 Map 之间建立关联

### 4.2 为什么 tgid 用于判断是否已初始化？

```c
// 在 bpf_file_read_write() 中:
if (entry->tgid == 0) {
    init_io_data(entry, root_dentry, dentry, inode);  // 首次从文件系统层
}
```

**关键点**:
- **块设备层**先执行，但只设置 `pid` 和 `comm`，**不设置 `tgid`**
- **文件系统层**后执行，检查 `tgid == 0`，说明还未初始化文件路径
- 只有 `init_io_data()` 才会设置 `tgid`

**为什么这样设计？**
- 保证文件路径信息来自**正确的进程上下文**（文件系统层）
- 避免块设备层的进程上下文覆盖文件系统层的信息

### 4.3 Direct IO 的特殊处理

```c
// 在 bpf_rq_qos_issue() 中:
inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
info.inode = BPF_CORE_READ(inode, i_ino);

if (info.inode == 0)
    info.dev = key.dev;         // Direct IO: 使用块设备号
else
    info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 普通 IO: 使用文件系统设备号
```

**Direct IO 特征**:
- `inode == 0`（绕过页缓存，无 mapping）
- `io_key.pid = 进程PID`（需要区分进程）
- `io_key.dev = 块设备号`（而非文件系统设备）

---

## 5. 数据一致性保证

### 5.1 文件系统和块设备数据可能不一致

```
fs_read_bytes:    10MB   (文件系统层统计)
block_read_bytes: 8MB    (块设备层统计)
                  ↑
                  2MB 从页缓存命中，未触发块设备 IO
```

**这是正常的！** 说明页缓存工作良好。

### 5.2 延迟数据来源

- **q2c (Queue to Complete)**: 从 IO 请求进入队列到完成的时间
- **d2c (Device to Complete)**: 从 IO 请求发送到设备到完成的时间

```
q2c = now - req->start_time_ns
d2c = now - req->io_start_time_ns

q2c ≥ d2c  (队列等待 + 设备处理时间)
```

---

## 下一篇

[📘 第 2 篇: 内核版本兼容性处理](./02_compatibility.md)

讲解如何使用 BPF CO-RE 实现跨内核版本的兼容。


