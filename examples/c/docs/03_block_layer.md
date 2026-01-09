# iotrace 实现详解 (3/6): 块设备层追踪

## 目录
1. [块设备层概述](#块设备层概述)
2. [rq_qos_issue 实现](#rq_qos_issue-实现)
3. [rq_qos_done 实现](#rq_qos_done-实现)
4. [延迟计算](#延迟计算)
5. [设备号处理](#设备号处理)

---

## 1. 块设备层概述

### 1.1 为什么选择 rq_qos_issue/rq_qos_done？

Linux 块设备层的 IO 路径：

```
应用层
  │
  ├─ submit_bio()
  │     │
  │     ▼
  │  [块设备队列]
  │     │
  │     ▼
  │  ⏱️ rq_qos_issue()      ← 🔍 追踪点 1 (IO 进入队列)
  │     │
  │     ├─ [IO 调度器]
  │     ├─ [设备队列]
  │     │
  │     ▼
  │  [硬件驱动发送到磁盘]
  │     │
  │     ▼
  │  [磁盘处理中...]
  │     │
  │     ▼
  │  ⏱️ rq_qos_done()       ← 🔍 追踪点 2 (IO 完成)
  │
  ▼
完成回调
```

**优势**:
- ✅ 覆盖整个 IO 路径（队列等待 + 磁盘处理）
- ✅ 稳定的内核接口（4.19+ 内核支持）
- ✅ 可以关联到具体文件（通过 bio->inode）

### 1.2 内核版本兼容性

| 内核版本 | 函数名 | 状态 |
|---------|--------|------|
| 4.19 - 4.x | `rq_qos_issue` / `rq_qos_done` | ✅ 支持 |
| 5.0+ | `__rq_qos_issue` / `__rq_qos_done` | ✅ 支持 (函数名前加 `__`) |

**用户态动态选择**:
```c
// iotrace.c (line 426-441)
bool has_rq_qos_issue = check_kprobe_exists("rq_qos_issue");
bool has___rq_qos_issue = check_kprobe_exists("__rq_qos_issue");

if (has_rq_qos_issue) {
    issue_symbol = "rq_qos_issue";
    done_symbol = "rq_qos_done";
} else if (has___rq_qos_issue) {
    issue_symbol = "__rq_qos_issue";
    done_symbol = "__rq_qos_done";
}
```

---

## 2. rq_qos_issue 实现

### 2.1 函数签名

```c
// 内核函数原型:
void rq_qos_issue(struct request_queue *q, struct request *rq);
//                         参数1: 队列            参数2: 请求

// BPF kprobe hook:
SEC("kprobe/rq_qos_issue")
int bpf_rq_qos_issue(struct pt_regs *ctx)
{
    // PT_REGS_PARM1(ctx) = q (struct request_queue *)
    // PT_REGS_PARM2(ctx) = rq (struct request *)
    struct request *req = (struct request *)PT_REGS_PARM2(ctx);
    // ...
}
```

### 2.2 核心逻辑

```c
SEC("kprobe/rq_qos_issue")
int bpf_rq_qos_issue(struct pt_regs *ctx)
{
    struct request *req = (struct request *)PT_REGS_PARM2(ctx);
    struct hash_key key = {};
    struct io_start_info info = {};
    
    // 步骤 1: 获取 bio
    struct bio *bio = BPF_CORE_READ(req, bio);
    
    // 步骤 2: 过滤元数据请求 (只追踪数据 IO)
    __u32 cmd_flags = BPF_CORE_READ(req, cmd_flags);
    if (cmd_flags & REQ_META)  // 元数据请求？
        return 0;              // 过滤掉
    
    // 步骤 3: 构建 hash_key (用于 done 阶段匹配)
    struct gendisk *disk = get_request_disk(req);  // 兼容性处理
    int devn[2];  // devn[0]=major, devn[1]=minor
    if (bpf_probe_read(devn, sizeof(devn), disk))
        return -1;
    
    int partno = get_partition_number(req);  // 兼容性处理
    key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
    key.sector = BPF_CORE_READ(req, __sector);
    
    // 步骤 4: 设备过滤
    if (!should_process_device(key.dev))
        return 0;
    
    // 步骤 5: 提取 inode (区分普通 IO 和 Direct IO)
    struct inode *inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
    info.inode = BPF_CORE_READ(inode, i_ino);
    
    if (info.inode == 0)
        info.dev = key.dev;  // Direct IO: 使用块设备号
    else
        info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 普通 IO: 使用文件系统设备号
    
    // 步骤 6: 记录进程信息
    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.data_len = BPF_CORE_READ(req, __data_len);
    bpf_get_current_comm(info.comm, TASK_COMM_LEN);
    
    // 步骤 7: 保存到临时 map (等待 done 匹配)
    bpf_map_update_elem(&start_info_map, &key, &info, BPF_ANY);
    
    return 0;
}
```

### 2.3 关键点解析

#### 关键点 1: 为什么过滤 REQ_META？

```c
#define REQ_META (1ULL << __REQ_META)  // __REQ_META = 12

if (cmd_flags & REQ_META)
    return 0;
```

**原因**: 
- 元数据请求（如文件系统日志、inode 更新）不是用户 IO
- 追踪元数据会干扰真实的应用 IO 统计

**cmd_flags 结构**:
```
cmd_flags (32位)
├─ [0:7]   REQ_OP (操作类型: READ/WRITE/DISCARD...)
├─ [8:31]  REQ_FLAGS (标志位: META/SYNC/FUA...)
```

#### 关键点 2: hash_key 的构建

```c
struct hash_key {
    __u32 dev;       // 块设备号
    __u32 _pad;
    __u64 sector;    // 扇区号
};
```

**为什么用 (dev, sector) 作为 key？**
- `sector`: 扇区号在一次 IO 请求的生命周期内**唯一**
- `dev`: 区分不同的块设备
- **唯一标识**: 一个 IO 请求从 issue 到 done

#### 关键点 3: inode 提取

```c
// bio -> bi_io_vec -> bv_page -> mapping -> host -> i_ino
struct inode *inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
```

**数据结构关系**:
```
struct request
  └─ struct bio               (块 IO 描述符)
      └─ struct bio_vec       (物理页向量)
          └─ struct page      (物理页)
              └─ struct address_space  (页缓存映射)
                  └─ struct inode      (文件 inode)
```

**Direct IO 特殊情况**:
- Direct IO 绕过页缓存，`mapping = NULL`
- 因此 `inode->i_ino = 0`
- 需要特殊处理（见下文）

#### 关键点 4: Direct IO 的设备号处理

```c
if (info.inode == 0)
    info.dev = key.dev;         // 块设备号 (如 8:0)
else
    info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 文件系统设备号
```

**为什么要区分？**

**场景 1: 普通文件 IO**
```
文件: /mnt/data/file.txt
文件系统设备: 253:0 (dm-0, LVM)
块设备: 8:0 (sda)

→ info.dev = 253:0 (使用文件系统设备，便于聚合同一文件的 IO)
```

**场景 2: Direct IO**
```
直接读写块设备: /dev/sda1
块设备: 8:1 (sda1)

→ info.dev = 8:1 (无文件系统，只能用块设备号)
```

---

## 3. rq_qos_done 实现

### 3.1 核心逻辑

```c
SEC("kprobe/rq_qos_done")
int bpf_rq_qos_done(struct pt_regs *ctx)
{
    struct request *req = (struct request *)PT_REGS_PARM2(ctx);
    struct io_start_info *info = NULL;
    struct hash_key info_key = {};
    struct io_key io_key = {};
    struct io_data data = {};
    struct io_data *entry;
    
    // 步骤 1: 重建 hash_key (必须与 issue 时完全一致)
    struct gendisk *disk = get_request_disk(req);
    int devn[2];
    if (bpf_probe_read(devn, sizeof(devn), disk))
        return -1;
    
    int partno = get_partition_number(req);
    info_key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
    info_key.sector = BPF_CORE_READ(req, __sector);
    
    // 设备过滤
    if (!should_process_device(info_key.dev))
        return 0;
    
    // 步骤 2: 从 start_info_map 查找 issue 时保存的信息
    info = bpf_map_lookup_elem(&start_info_map, &info_key);
    if (!info)
        return 0;  // 找不到？可能被过滤了
    
    // 步骤 3: 构建 io_source_map 的 key
    io_key.dev = info->dev;
    io_key.inode = info->inode;
    
    if (io_key.inode == 0)
        io_key.pid = info->pid;  // Direct IO: 需要区分进程
    
    // 步骤 4: 查找或创建 io_source_map 条目
    entry = bpf_map_lookup_elem(&io_source_map, &io_key);
    if (!entry)
        entry = &data;  // 新条目
    
    // 步骤 5: 累加块设备字节数
    __u32 cmd_flags = BPF_CORE_READ(req, cmd_flags);
    if (is_write_request(cmd_flags)) {
        entry->block_write_bytes += info->data_len;
    } else if ((cmd_flags & REQ_OP_MASK) == REQ_OP_READ) {
        entry->block_read_bytes += info->data_len;
    } else {
        // 其他操作 (DISCARD/FLUSH...)，跳过
        bpf_map_delete_elem(&start_info_map, &info_key);
        return 0;
    }
    
    // 步骤 6: 计算延迟
    __u64 now = bpf_ktime_get_ns();
    __u64 q2c = now - BPF_CORE_READ(req, start_time_ns);
    __u64 d2c = now - BPF_CORE_READ(req, io_start_time_ns);
    
    entry->latency.sum_q2c += q2c;
    entry->latency.sum_d2c += d2c;
    entry->latency.cnt++;
    
    if (q2c > entry->latency.max_q2c)
        entry->latency.max_q2c = q2c;
    if (d2c > entry->latency.max_d2c)
        entry->latency.max_d2c = d2c;
    
    // 步骤 7: 如果是新条目，初始化基本信息
    if (entry == &data) {
        entry->pid = info->pid;
        entry->dev = info->dev;
        entry->inode = info->inode;
        bpf_probe_read_str(entry->comm, TASK_COMM_LEN, info->comm);
        bpf_map_update_elem(&io_source_map, &io_key, &data, BPF_ANY);
    }
    
    // 步骤 8: 删除临时记录
    bpf_map_delete_elem(&start_info_map, &info_key);
    
    return 0;
}
```

### 3.2 关键点解析

#### 关键点 1: 为什么要删除 start_info_map 条目？

```c
bpf_map_delete_elem(&start_info_map, &info_key);
```

**原因**:
- `start_info_map` 只是**临时存储**
- 每个 IO 请求: issue → done → 删除
- 避免内存泄漏（map 满了会导致新 IO 无法记录）

#### 关键点 2: 为什么 Direct IO 需要 pid？

```c
if (io_key.inode == 0)
    io_key.pid = info->pid;  // Direct IO: 设置 pid
```

**原因**:
```
进程 A: 写 /dev/sda1 (Direct IO)
进程 B: 写 /dev/sda1 (Direct IO)

→ 如果不加 pid，两个进程的 IO 会聚合到同一个 key:
  {pid: 0, dev: 8:1, inode: 0}

→ 加了 pid 后，分别聚合:
  进程 A: {pid: 1234, dev: 8:1, inode: 0}
  进程 B: {pid: 5678, dev: 8:1, inode: 0}
```

#### 关键点 3: 为什么不在 done 阶段初始化文件路径？

```c
// done 阶段只初始化 pid/dev/inode
if (entry == &data) {
    entry->pid = info->pid;
    entry->dev = info->dev;
    entry->inode = info->inode;
    // 没有调用 init_io_data() ❌
}
```

**原因**:
- `rq_qos_done` 在**中断上下文**执行，此时进程上下文可能不正确
- 文件路径信息应该在**文件系统层**（正确的进程上下文）初始化
- 参见第 1 篇的"tgid 判断"逻辑

---

## 4. 延迟计算

### 4.1 两种延迟指标

```c
__u64 now = bpf_ktime_get_ns();
__u64 q2c = now - BPF_CORE_READ(req, start_time_ns);      // Queue to Complete
__u64 d2c = now - BPF_CORE_READ(req, io_start_time_ns);   // Device to Complete
```

**时间线**:
```
t1: start_time_ns         IO 请求进入队列
    │
    ├─ [IO 调度器排队]
    │
t2: io_start_time_ns      IO 发送到设备
    │
    ├─ [设备处理]
    │
t3: now                   IO 完成

q2c = t3 - t1  (总延迟: 队列等待 + 设备处理)
d2c = t3 - t2  (设备延迟: 仅设备处理)
```

### 4.2 统计量

```c
struct latency_info {
    __u64 cnt;       // IO 次数
    __u64 max_d2c;   // 最大设备延迟
    __u64 sum_d2c;   // 总设备延迟
    __u64 max_q2c;   // 最大总延迟
    __u64 sum_q2c;   // 总延迟
};
```

**用户态计算平均值**:
```c
// iotrace.c (line 348-353)
if (data.latency.cnt > 0) {
    q2c_avg = data.latency.sum_q2c / data.latency.cnt / 1000;  // ns→μs
    d2c_avg = data.latency.sum_d2c / data.latency.cnt / 1000;
    q2c_max = data.latency.max_q2c / 1000;
    d2c_max = data.latency.max_d2c / 1000;
}
```

---

## 5. 设备号处理

### 5.1 Linux 设备号格式

```
内核设备号 (32 位):
┌──────────────┬──────────────────────┐
│  major (12位) │  minor (20位)        │
└──────────────┴──────────────────────┘

示例: 8:0 (sda)
major = 8
minor = 0
kernel_dev = (8 & 0xfff) << 20 | 0 = 0x00800000
```

### 5.2 构建设备号

```c
// 读取 gendisk.major 和 gendisk.first_minor
int devn[2];  // devn[0]=major, devn[1]=first_minor
bpf_probe_read(devn, sizeof(devn), disk);

// 计算完整设备号: (major & 0xfff) << 20 | (minor + partno)
int partno = get_partition_number(req);
__u32 dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
```

### 5.3 设备过滤实现

```c
// 用户态配置 (iotrace.c):
volatile const __u32 FILTER_DEVS[16] = {};
volatile const __u32 FILTER_DEV_COUNT = 0;

// BPF 端过滤:
static __always_inline int should_process_device(__u32 dev)
{
    if (FILTER_DEV_COUNT == 0)
        return 1;  // 无过滤，处理所有设备
    
    for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
        if (FILTER_DEVS[i] == dev)
            return 1;  // 在白名单中
    
    return 0;  // 过滤掉
}
```

**使用方式**:
```bash
# 只追踪 sda (8:0) 和 dm-0 (253:0)
./iotrace -D 8:0,253:0
```

---

## 6. 性能优化考虑

### 6.1 Map 大小选择

```c
// start_info_map: 4096 条
// 原因: 高并发场景下同时有大量 IO 在进行中

// io_source_map: 512 条
// 原因: ~100 进程 × 5 文件/进程 = 500
```

### 6.2 过滤策略

1. **元数据过滤**: `cmd_flags & REQ_META` → 减少 ~30% 的无用 IO
2. **设备过滤**: `should_process_device()` → 只追踪关心的设备
3. **操作过滤**: 只统计 READ/WRITE，忽略 DISCARD/FLUSH

---

## 下一篇

[📘 第 4 篇: 文件系统层追踪实现](./04_filesystem_layer.md)

详细讲解文件系统层的 read/write 追踪。


