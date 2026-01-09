# iotrace 实现详解 (4/6): 文件系统层追踪

## 目录
1. [文件系统层的作用](#文件系统层的作用)
2. [file_read_iter/write_iter 追踪](#file_read_iterwrite_iter-追踪)
3. [动态附加机制](#动态附加机制)
4. [文件路径提取](#文件路径提取)
5. [Direct IO 检测](#direct-io-检测)

---

## 1. 文件系统层的作用

### 1.1 为什么需要文件系统层追踪？

块设备层**无法**提供的信息：
- ❌ 不知道是**哪个进程**在读写（done 在中断上下文）
- ❌ 不知道是**哪个文件**（只有 sector 号）
- ❌ 不知道文件系统层的**逻辑读写量**（页缓存命中不触发块 IO）

文件系统层**可以**提供：
- ✅ 准确的**进程上下文**（PID、TGID、comm）
- ✅ **文件路径**（通过 dentry）
- ✅ **文件系统层的读写字节数**（包括页缓存命中）
- ✅ **Direct IO 标志**（ki_flags）

### 1.2 数据对比

```
场景: 读取 10MB 文件，8MB 命中页缓存

文件系统层统计:
  fs_read_bytes = 10MB  ✅ (完整的逻辑读取量)

块设备层统计:
  block_read_bytes = 2MB  ✅ (实际的物理 IO)
```

**两者结合**才能完整评估 IO 性能：
- 高 `fs_read_bytes`，低 `block_read_bytes` → 页缓存命中率高 👍
- 高 `fs_read_bytes`，高 `block_read_bytes` → 页缓存效率低 👎

---

## 2. file_read_iter/write_iter 追踪

### 2.1 内核调用路径

```
用户空间: read(fd, buf, size)
    │
    ▼
VFS 层: vfs_read()
    │
    ▼
文件系统层:
    ├─ ext4_file_read_iter()     ← 🔍 ext4 文件系统
    ├─ xfs_file_read_iter()      ← 🔍 xfs 文件系统
    └─ ...
    │
    ▼
通用读取: generic_file_read_iter()
    │
    ▼
页缓存: filemap_read()
    │
    ├─ 页缓存命中? → 直接返回 ✅
    │
    └─ 页缓存未命中? → 触发块 IO
        │
        ▼
    块设备层: submit_bio()
```

### 2.2 BPF 程序实现

```c
// 通用处理函数 (同时处理 read 和 write)
static __always_inline int bpf_file_read_write(struct pt_regs *ctx)
{
    // 步骤 1: 提取参数 (kiocb 和 iov_iter)
    struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
    struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2(ctx);
    
    // 步骤 2: 提取 inode 和设备号
    struct inode *inode = BPF_CORE_READ(iocb, ki_filp, f_inode);
    struct io_key key = {};
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // 文件系统设备号
    
    // 设备过滤
    if (!should_process_device(key.dev))
        return 0;
    
    // 步骤 3: 查找或创建 io_source_map 条目
    struct io_data *entry = bpf_map_lookup_elem(&io_source_map, &key);
    struct io_data data = {};
    if (!entry)
        entry = &data;
    
    // 步骤 4: 首次访问? 初始化文件路径信息
    if (entry->tgid == 0) {
        struct dentry *dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
        struct dentry *root_dentry = BPF_CORE_READ(iocb, ki_filp, f_path.mnt, mnt_root);
        init_io_data(entry, root_dentry, dentry, inode);
        entry->dev = key.dev;
        entry->inode = key.inode;
    }
    
    // 步骤 5: 获取读写字节数
    size_t count = BPF_CORE_READ(from, count);
    
    // 步骤 6: 判断读/写方向 (兼容不同内核版本)
    unsigned int type;
    struct iov_iter___old *from_old = (struct iov_iter___old *)from;
    struct iov_iter___new *from_new = (struct iov_iter___new *)from;
    
    if (bpf_core_field_exists(from_old->type)) {
        type = BPF_CORE_READ(from_old, type);  // 老内核: type 字段
    } else {
        type = BPF_CORE_READ(from_new, data_source);  // 新内核: data_source 字段
    }
    
    // 步骤 7: 累加文件系统字节数
    type = type & 0x1;  // 最低位: 0=读, 1=写
    if (type)
        entry->fs_write_bytes += count;
    else
        entry->fs_read_bytes += count;
    
    // 步骤 8: 保存 IOCB 标志 (用于 Direct IO 检测)
    entry->flag = BPF_CORE_READ(iocb, ki_flags);
    
    // 步骤 9: 更新 map
    if (entry == &data)
        bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);
    
    return 0;
}

// 实际的 kprobe 程序 (会动态附加到 ext4/xfs)
SEC("kprobe/anyfs_file_read_iter")
int bpf_anyfs_file_read_iter(struct pt_regs *ctx)
{
    return bpf_file_read_write(ctx);
}

SEC("kprobe/anyfs_file_write_iter")
int bpf_anyfs_file_write_iter(struct pt_regs *ctx)
{
    return bpf_file_read_write(ctx);
}
```

### 2.3 关键点解析

#### 关键点 1: 为什么用 tgid == 0 判断？

```c
if (entry->tgid == 0) {
    init_io_data(entry, root_dentry, dentry, inode);
}
```

**场景分析**:
```
时间轴:
t1: 块设备层 rq_qos_done 先执行
    → 创建 io_source_map 条目
    → 设置 pid, comm (但不设置 tgid)
    → entry->tgid = 0

t2: 文件系统层 file_read_iter 后执行
    → 检查 entry->tgid == 0? 是！
    → 调用 init_io_data() 初始化文件路径
    → 设置 tgid (线程组 ID)
```

**为什么这样设计？**
- 块设备层的进程上下文**不可靠**（可能在中断上下文）
- 文件系统层的进程上下文**可靠**（一定在正确的进程上下文）
- 使用 `tgid` 作为"已初始化"的标志

#### 关键点 2: iov_iter 的读写方向判断

```c
// iov_iter 结构体 (老内核):
struct iov_iter {
    unsigned int type;  // 读写方向 + 类型
    // type 的各个位:
    // [0]: 0=READ, 1=WRITE
    // [1-7]: 类型 (IOVEC/KVEC/BVEC/PIPE...)
};

// 提取最低位:
type = type & 0x1;  // 0=读, 1=写
```

#### 关键点 3: kiocb 和 iov_iter 的关系

```c
// 内核函数签名:
ssize_t ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to);
ssize_t ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
```

| 参数 | 作用 |
|------|------|
| `struct kiocb` | IO 控制块（包含文件指针、偏移量、标志位） |
| `struct iov_iter` | IO 向量迭代器（包含缓冲区、字节数、方向） |

**数据流**:
```
struct kiocb
  └─ struct file *ki_filp
      ├─ struct inode *f_inode      → 提取 inode
      └─ struct path f_path
          └─ struct dentry *dentry  → 提取文件路径
```

---

## 3. 动态附加机制

### 3.1 为什么需要动态附加？

不同文件系统有**不同的函数名**：
```
ext4: ext4_file_read_iter()
xfs:  xfs_file_read_iter()
btrfs: btrfs_file_read_iter()
...
```

**解决方案**: 用同一个 BPF 程序，动态附加到不同的内核符号

### 3.2 用户态实现

```c
// iotrace.c (line 464-506)

// 检查文件系统是否被支持
bool has_ext4 = is_fs_supported("ext4");
bool has_xfs = is_fs_supported("xfs");

if (has_ext4) {
    // 将 anyfs_file_read_iter 附加到 ext4_file_read_iter
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_file_read_iter,  // BPF 程序
        false,                                   // 不是 kretprobe
        "ext4_file_read_iter"                   // 内核符号
    );
    
    // 将 anyfs_file_write_iter 附加到 ext4_file_write_iter
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_file_write_iter,
        false,
        "ext4_file_write_iter"
    );
    
    // 将 anyfs_filemap_page_mkwrite 附加到 ext4_page_mkwrite
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_filemap_page_mkwrite,
        false,
        "ext4_page_mkwrite"
    );
}

if (has_xfs) {
    // 同样的 BPF 程序，附加到 xfs 函数
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_file_read_iter,
        false,
        "xfs_file_read_iter"
    );
    // ... xfs 的其他 hook
}
```

### 3.3 BPF 程序命名约定

```c
SEC("kprobe/anyfs_file_read_iter")  // 'anyfs' 表示通用文件系统
int bpf_anyfs_file_read_iter(struct pt_regs *ctx)
```

**命名规则**:
- `anyfs` 前缀: 表示可以附加到任何文件系统的同名函数
- 用户态负责动态附加到具体的内核符号

### 3.4 检查文件系统是否支持

```c
// iotrace.c (line 106-122)
static bool is_fs_supported(const char *fs_name)
{
    FILE *f = fopen("/proc/filesystems", "r");
    if (!f)
        return false;
    
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, fs_name)) {  // 查找文件系统名称
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}
```

**示例输出** (`/proc/filesystems`):
```
nodev   sysfs
nodev   tmpfs
        ext4      ← 找到了！
        xfs       ← 找到了！
nodev   bpf
```

---

## 4. 文件路径提取

### 4.1 init_io_data() 实现

```c
static __always_inline void init_io_data(struct io_data *entry,
                                         struct dentry *root_dentry,
                                         struct dentry *dentry,
                                         struct inode *inode)
{
    // 步骤 1: 提取 PID 和 TGID
    __u64 t = bpf_get_current_pid_tgid();
    entry->pid = t >> 32;         // 高 32 位: PID
    entry->tgid = t & 0xffffffff; // 低 32 位: TGID (线程组 ID)
    
    // 步骤 2: 提取进程名
    bpf_get_current_comm(entry->comm, TASK_COMM_LEN);
    
    // 步骤 3: 提取文件名 (0 级)
    bpf_probe_read_str(entry->filename, DNAME_INLINE_LEN,
                       BPF_CORE_READ(dentry, d_name.name));
    
    // 步骤 4: 提取父目录 (1 级)
    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d1name, DNAME_INLINE_LEN,
                       BPF_CORE_READ(dentry, d_name.name));
    
    // 步骤 5: 提取祖父目录 (2 级)
    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d2name, DNAME_INLINE_LEN,
                       BPF_CORE_READ(dentry, d_name.name));
    
    // 步骤 6: 提取曾祖父目录 (3 级)
    dentry = BPF_CORE_READ(dentry, d_parent);
    bpf_probe_read_str(entry->d3name, DNAME_INLINE_LEN,
                       BPF_CORE_READ(dentry, d_name.name));
}
```

### 4.2 dentry 树结构

```
文件路径: /mnt/data/logs/app.log

dentry 树:
    (root)
      │
      └─ mnt         ← d3name (层级 3)
          │
          └─ data    ← d2name (层级 2)
              │
              └─ logs    ← d1name (层级 1)
                  │
                  └─ app.log  ← filename (层级 0)
```

**结构体关系**:
```c
struct dentry {
    struct qstr d_name;       // 当前目录/文件名
    struct dentry *d_parent;  // 父 dentry (向上遍历)
    struct inode *d_inode;    // 对应的 inode
};

struct qstr {
    const unsigned char *name;  // 字符串指针
    unsigned int len;           // 长度
};
```

### 4.3 用户态路径拼接

```c
// iotrace.c (line 356-375)

// 拼接路径: d3name/d2name/d1name/filename
char filepath[256];
snprintf(filepath, sizeof(filepath), "%s/%s/%s/%s",
         data.d3name, data.d2name, data.d1name, data.filename);

// 移除开头多余的斜杠
char *p = filepath;
while (*p == '/')
    p++;
if (p != filepath)
    memmove(filepath, p, strlen(p) + 1);

// 输出: mnt/data/logs/app.log
```

### 4.4 为什么只提取 3 层？

**原因**:
1. **BPF 栈空间限制**: 512 字节，每层 64 字节已占用 256 字节
2. **性能考虑**: 遍历 dentry 树需要多次内核内存访问
3. **实用性**: 3 层已足够定位大多数文件

**不足之处**:
```
完整路径: /home/user/projects/myapp/data/logs/app.log
提取路径: data/logs/app.log  (前面被截断)
```

---

## 5. Direct IO 检测

### 5.1 什么是 Direct IO？

```c
// 普通 IO (带缓存)
int fd = open("/path/to/file", O_RDWR);
read(fd, buf, size);  // 经过页缓存

// Direct IO (绕过缓存)
int fd = open("/path/to/file", O_RDWR | O_DIRECT);
read(fd, buf, size);  // 直接访问磁盘
```

**特点**:
- ✅ 减少内存拷贝
- ✅ 数据库常用（避免双重缓存）
- ❌ 不利用页缓存，性能可能更差

### 5.2 BPF 端检测

```c
// 保存 IOCB 标志
entry->flag = BPF_CORE_READ(iocb, ki_flags);
```

**ki_flags 包含**:
```c
// 内核定义 (include/linux/fs.h)
#define IOCB_DIRECT   (1 << 2)   // 0x4: Direct IO
#define IOCB_DSYNC    (1 << 3)   // 0x8: Data sync
#define IOCB_SYNC     (1 << 4)   // 0x10: Full sync
```

### 5.3 用户态显示

```c
// iotrace.c (line 372-374)
if (data.flag & 0x4) {  // IOCB_DIRECT
    strcat(filepath, " [direct IO]");
}
```

**输出示例**:
```
FILE
data/mydb.bin [direct IO]
logs/app.log
```

---

## 6. 多进程/多线程处理

### 6.1 PID vs TGID

```c
__u64 t = bpf_get_current_pid_tgid();
entry->pid = t >> 32;         // 线程 PID (Thread ID)
entry->tgid = t & 0xffffffff; // 进程 PID (Process ID / Thread Group ID)
```

**关系**:
```
进程 1234 (主线程)
  ├─ Thread 1234 (主线程): pid=1234, tgid=1234
  ├─ Thread 1235 (工作线程): pid=1235, tgid=1234
  └─ Thread 1236 (工作线程): pid=1236, tgid=1234
```

### 6.2 聚合策略

```c
// io_source_map 的 key:
struct io_key {
    __u32 pid;      // 注意: 这里实际存的是线程 pid (不是 tgid)
    __u32 dev;
    __u64 inode;
};
```

**聚合行为**:
- **同一文件**: 不同线程的 IO 会聚合到同一个 key（pid=0, dev, inode）
- **用户态展示**: 按 `entry->tgid` 聚合到进程级别

---

## 7. 性能考虑

### 7.1 为什么不追踪 vfs_read/vfs_write？

```c
// VFS 层 (通用层)
vfs_read()
  └─ ext4_file_read_iter()  ← 我们追踪这里
      └─ generic_file_read_iter()
```

**原因**:
- `vfs_read/vfs_write` 调用频率**极高**（所有文件操作）
- 文件系统层的函数调用频率**较低**（只有真正的文件 IO）
- 减少 BPF 程序执行次数，降低性能影响

### 7.2 BPF 程序开销

**测量点**:
- `bpf_file_read_write()`: ~500 ns/次（现代 CPU）
- 每秒 10 万次 IO → 50 ms CPU 时间（~5% 单核开销）

---

## 下一篇

[📘 第 5 篇: 页缓存层追踪实现](./05_pagecache_layer.md)

详细讲解 mmap 方式的 IO 追踪。


