# iotrace 实现详解 (5/6): 页缓存层追踪

## 目录
1. [mmap 机制简介](#mmap-机制简介)
2. [filemap_fault 追踪（mmap 读）](#filemap_fault-追踪mmap-读)
3. [page_mkwrite 追踪（mmap 写）](#page_mkwrite-追踪mmap-写)
4. [按页统计的原理](#按页统计的原理)
5. [与文件系统层的区别](#与文件系统层的区别)

---

## 1. mmap 机制简介

### 1.1 什么是 mmap？

**Memory Mapped File**: 将文件映射到进程的虚拟地址空间

```c
// 用户程序
int fd = open("/path/to/file", O_RDWR);
char *addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

// 直接访问内存 = 访问文件
addr[0] = 'A';  // 写入文件
char c = addr[100];  // 读取文件

munmap(addr, 4096);
close(fd);
```

### 1.2 mmap 的优势

| 方式 | 数据拷贝次数 | 系统调用次数 | 适用场景 |
|------|-------------|-------------|----------|
| **read/write** | 2 次（内核→用户） | 每次 IO 一次 | 小文件、流式 IO |
| **mmap** | 0 次（直接访问页缓存） | 一次 mmap | 大文件、随机访问 |

**mmap 数据流**:
```
用户访问 addr[0]
    │
    ▼
页表查找
    │
    ├─ 页在内存? → 直接访问 ✅ (零拷贝)
    │
    └─ 页不在内存? → 触发缺页中断
        │
        ▼
    filemap_fault()     ← 🔍 追踪点 1 (读取)
        │
        ├─ 页缓存命中? → 映射到进程地址空间
        │
        └─ 页缓存未命中? → 从磁盘读取
            │
            ▼
        submit_bio() → 块设备 IO
```

### 1.3 为什么需要单独追踪 mmap？

**问题**: `file_read_iter/write_iter` **不会**被 mmap 触发

```c
// 场景: 使用 mmap 读写文件
int fd = open("/data/file.txt", O_RDWR);
char *addr = mmap(NULL, 1024*1024, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

addr[0] = 'X';  // 写入
    ↓
    ❌ ext4_file_write_iter() 不会被调用！
    ✅ ext4_page_mkwrite() 会被调用！

char c = addr[100];  // 读取
    ↓
    ❌ ext4_file_read_iter() 不会被调用！
    ✅ filemap_fault() 会被调用！
```

**解决方案**: 增加页缓存层的 hook

---

## 2. filemap_fault 追踪（mmap 读）

### 2.1 内核调用路径

```
用户程序访问 mmap 地址 (读取)
    │
    ▼
CPU 页表查找
    │
    └─ 页不存在 → 缺页中断 (Page Fault)
        │
        ▼
handle_mm_fault()
    │
    ▼
__do_fault()
    │
    ▼
do_read_fault()
    │
    ▼
filemap_fault()           ← 🔍 追踪点
    │
    ├─ 查找页缓存
    │   ├─ 命中? → 直接返回页
    │   └─ 未命中? → 触发块 IO
    │
    ▼
返回物理页，建立页表映射
```

### 2.2 BPF 程序实现

```c
SEC("kprobe/filemap_fault")
int bpf_filemap_fault(struct pt_regs *ctx)
{
    // 步骤 1: 提取参数 (vm_fault 结构体)
    struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
    struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
    
    // 步骤 2: 提取 inode 和设备号
    struct inode *inode = BPF_CORE_READ(vma, vm_file, f_inode);
    struct io_key key = {};
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    
    // 设备过滤
    if (!should_process_device(key.dev))
        return 0;
    
    // 步骤 3: 查找或创建 io_source_map 条目
    struct io_data *entry = bpf_map_lookup_elem(&io_source_map, &key);
    struct io_data data = {};
    if (!entry)
        entry = &data;
    
    // 步骤 4: 首次访问? 初始化文件路径
    if (entry->tgid == 0) {
        struct dentry *dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
        struct dentry *root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
        init_io_data(entry, root_dentry, dentry, inode);
        entry->dev = key.dev;
        entry->inode = key.inode;
    }
    
    // 步骤 5: 累加 mmap 读取字节数 (按页统计)
    entry->fs_read_bytes += PAGE_SIZE;  // PAGE_SIZE = 4096
    
    // 步骤 6: 更新 map
    if (entry == &data)
        bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);
    
    return 0;
}
```

### 2.3 关键数据结构

#### vm_fault 结构体

```c
struct vm_fault {
    struct vm_area_struct *vma;  // 触发缺页的 VMA
    unsigned int flags;          // 缺页标志 (读/写/...)
    pgoff_t pgoff;               // 文件内偏移量 (页号)
    // ...
};
```

#### vm_area_struct (VMA)

```c
struct vm_area_struct {
    unsigned long vm_start;   // 虚拟地址起始
    unsigned long vm_end;     // 虚拟地址结束
    struct file *vm_file;     // 映射的文件 (mmap 文件)
    // ...
};
```

**数据关系**:
```
struct vm_fault
  └─ struct vm_area_struct
      └─ struct file *vm_file
          ├─ struct inode *f_inode      → 提取 inode
          └─ struct path f_path
              └─ struct dentry *dentry  → 提取文件路径
```

### 2.4 关键点解析

#### 关键点 1: 为什么统计 PAGE_SIZE？

```c
entry->fs_read_bytes += PAGE_SIZE;  // 4096 字节
```

**原因**:
- `filemap_fault` 每次缺页处理**一个页**（4KB）
- 无论用户访问 1 字节还是 4KB，都会触发整页加载
- 因此按 `PAGE_SIZE` 统计

**示例**:
```c
char *addr = mmap(NULL, 1024*1024, PROT_READ, MAP_SHARED, fd, 0);

// 场景 1: 访问 1 字节
char c = addr[0];
→ filemap_fault 触发 1 次
→ fs_read_bytes += 4096

// 场景 2: 访问 10KB (跨 3 个页)
memcpy(buf, addr, 10*1024);
→ filemap_fault 触发 3 次
→ fs_read_bytes += 12288
```

#### 关键点 2: filemap_fault 不区分缓存命中/未命中

```c
// filemap_fault 在以下情况都会触发:
// 1. 页缓存命中 (快速路径)
// 2. 页缓存未命中 (需要从磁盘读取)

→ fs_read_bytes 统计的是"逻辑读取量"
→ 如果后续触发 submit_bio，block_read_bytes 会增加
```

**区别**:
```
场景 1: 页缓存命中
  fs_read_bytes = 4096
  block_read_bytes = 0  (无块 IO)

场景 2: 页缓存未命中
  fs_read_bytes = 4096
  block_read_bytes = 4096  (触发块 IO)
```

---

## 3. page_mkwrite 追踪（mmap 写）

### 3.1 内核调用路径

```
用户程序写入 mmap 地址
    │
    ▼
CPU 页表检查
    │
    └─ 页是只读的? → 写保护异常 (Write Protection Fault)
        │
        ▼
handle_mm_fault()
    │
    ▼
do_wp_page()  (Write Protect Page)
    │
    ▼
ext4_page_mkwrite()       ← 🔍 追踪点 (ext4)
xfs_filemap_page_mkwrite() ← 🔍 追踪点 (xfs)
    │
    ├─ 标记页为"脏页" (dirty)
    ├─ 分配磁盘块 (如果需要)
    │
    ▼
修改页表权限为可写
```

### 3.2 BPF 程序实现

```c
SEC("kprobe/anyfs_filemap_page_mkwrite")
int bpf_anyfs_filemap_page_mkwrite(struct pt_regs *ctx)
{
    // 步骤 1: 提取参数
    struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
    struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
    
    // 步骤 2: 提取 inode 和设备号
    struct inode *inode = BPF_CORE_READ(vma, vm_file, f_inode);
    struct io_key key = {};
    key.inode = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    
    // 设备过滤
    if (!should_process_device(key.dev))
        return 0;
    
    // 步骤 3: 查找或创建条目
    struct io_data *entry = bpf_map_lookup_elem(&io_source_map, &key);
    struct io_data data = {};
    if (!entry)
        entry = &data;
    
    // 步骤 4: 首次访问? 初始化文件路径
    if (entry->tgid == 0) {
        struct dentry *dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
        struct dentry *root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
        init_io_data(entry, root_dentry, dentry, inode);
        entry->dev = key.dev;
        entry->inode = key.inode;
    }
    
    // 步骤 5: 累加 mmap 写入字节数
    entry->fs_write_bytes += PAGE_SIZE;
    
    // 步骤 6: 更新 map
    if (entry == &data)
        bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);
    
    return 0;
}
```

### 3.3 动态附加

```c
// iotrace.c (line 480-505)

if (has_ext4) {
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_filemap_page_mkwrite,
        false,
        "ext4_page_mkwrite"  // ext4 的函数名
    );
}

if (has_xfs) {
    link = bpf_program__attach_kprobe(
        skel->progs.bpf_anyfs_filemap_page_mkwrite,
        false,
        "xfs_filemap_page_mkwrite"  // xfs 的函数名
    );
}
```

### 3.4 关键点解析

#### 关键点 1: 为什么叫 "mkwrite"？

**mkwrite** = **M**a**k**e **Write**able

- Linux 使用 **COW** (Copy-On-Write) 机制
- mmap 的页初始是**只读**的（即使 PROT_WRITE）
- 首次写入时触发写保护异常，调用 `page_mkwrite`
- `page_mkwrite` 将页标记为可写

#### 关键点 2: 与 write() 系统调用的区别

| 方式 | 追踪点 | 触发时机 |
|------|--------|----------|
| `write()` | `ext4_file_write_iter` | 每次 write 系统调用 |
| `mmap 写入` | `ext4_page_mkwrite` | 每次写入新页（首次） |

**mmap 写入只追踪一次**:
```c
char *addr = mmap(...);

addr[0] = 'A';  // 触发 page_mkwrite (首次写入)
addr[1] = 'B';  // 不触发 (同一页，已可写)
addr[4096] = 'C';  // 触发 page_mkwrite (新页)
```

**统计偏差**:
- `fs_write_bytes` 只统计**首次写入的页**
- 同一页的多次写入不会重复统计
- 这是 **逻辑限制**，无法避免

---

## 4. 按页统计的原理

### 4.1 为什么不能精确统计？

**mmap 的特性**:
- 用户直接访问内存，**不经过内核**
- 内核只在缺页时介入（filemap_fault/page_mkwrite）
- 同一页的后续访问**完全在 CPU 硬件层面处理**

**示例**:
```c
char *addr = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd, 0);

// 首次写入: 触发 page_mkwrite
addr[0] = 'A';
→ fs_write_bytes += 4096  ✅

// 同一页后续写入: 不触发任何内核函数
addr[1] = 'B';
addr[2] = 'C';
addr[3] = 'D';
→ fs_write_bytes += 0  ❌ (无法追踪)
```

**结论**: mmap 的文件系统统计是**粗略的**，仅反映页级访问

### 4.2 块设备层可以精确统计

```c
// mmap 写入脏页后，内核回写时:
filemap_fault / page_mkwrite
    ↓
标记页为脏
    ↓
后台回写线程 (kworker)
    ↓
submit_bio()
    ↓
rq_qos_issue / rq_qos_done  ← 🔍 精确统计块设备 IO
```

**对比**:
```
fs_write_bytes:    4096  (按页估算)
block_write_bytes: 4096  (精确的块 IO)
```

---

## 5. 与文件系统层的区别

### 5.1 三种 IO 方式对比

| IO 方式 | 文件系统层追踪点 | 页缓存层追踪点 | 块设备层追踪点 |
|---------|-----------------|---------------|---------------|
| **read()** | `ext4_file_read_iter` ✅ | - | `rq_qos_issue/done` ✅ |
| **write()** | `ext4_file_write_iter` ✅ | - | `rq_qos_issue/done` ✅ |
| **mmap 读** | - | `filemap_fault` ✅ | `rq_qos_issue/done` ✅ |
| **mmap 写** | - | `ext4_page_mkwrite` ✅ | `rq_qos_issue/done` ✅ |

### 5.2 实际场景分析

#### 场景 1: 数据库使用 mmap

```c
// PostgreSQL 使用 mmap 映射数据文件
int fd = open("/var/lib/postgres/data/base.dat", O_RDWR);
char *db = mmap(NULL, 1GB, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

// 查询操作 (读取索引页)
read_index_page(db + 1024*1024);
→ 触发 filemap_fault
→ fs_read_bytes += 4096

// 更新操作 (修改数据页)
update_data_page(db + 2048*1024);
→ 触发 ext4_page_mkwrite
→ fs_write_bytes += 4096
```

**如果没有页缓存层追踪**:
- ❌ 文件系统层: 0 字节（未调用 file_read_iter/write_iter）
- ✅ 块设备层: 有数据（但无法关联到文件）

**加上页缓存层追踪后**:
- ✅ 文件系统层: 8192 字节（4KB 读 + 4KB 写）
- ✅ 块设备层: 有数据 + 可关联到 inode

#### 场景 2: 编译器使用 mmap 读取源文件

```c
// GCC 编译 C 文件
int fd = open("main.c", O_RDONLY);
char *src = mmap(NULL, 102400, PROT_READ, MAP_PRIVATE, fd, 0);

// 解析源代码
parse_source(src);
→ 触发多次 filemap_fault (每 4KB 一次)
→ fs_read_bytes += 102400
```

---

## 6. 性能考虑

### 6.1 filemap_fault 调用频率

**取决于页缓存命中率**:
```
高命中率 (90%):
  100 次访问 → 10 次 filemap_fault

低命中率 (10%):
  100 次访问 → 90 次 filemap_fault
```

**BPF 开销**:
- 每次 `filemap_fault`: ~300 ns
- 1 万次/秒 → 3 ms CPU 时间（可接受）

### 6.2 page_mkwrite 调用频率

**COW 特性** 决定了调用频率较低:
```
写入 1MB 数据 (256 页):
  首次写入 256 页 → 256 次 page_mkwrite
  后续修改同样的页 → 0 次 page_mkwrite
```

---

## 7. 限制与改进

### 7.1 当前限制

1. **mmap 统计不精确**: 只统计首次访问的页
2. **无法区分读/写热点**: 只知道页被访问，不知道访问频率
3. **私有映射 (MAP_PRIVATE) 的写入无法追踪**: 不会触发 page_mkwrite

### 7.2 可能的改进

```c
// 使用 perf_event 追踪页表访问 (需要硬件支持)
// Intel: PEBS (Precise Event-Based Sampling)
// ARM: SPE (Statistical Profiling Extension)
```

但这会显著增加开销（~10% CPU）。

---

## 下一篇

[📘 第 6 篇: 用户态数据处理与输出](./06_userspace.md)

详细讲解用户态如何读取 BPF map 并生成报告。


