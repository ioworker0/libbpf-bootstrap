# iotrace 实现详解 (2/6): 内核版本兼容性处理

## 目录
1. [BPF CO-RE 简介](#bpf-co-re-简介)
2. [vmlinux.h 的不完整性问题](#vmlinuxh-的不完整性问题)
3. [结构体定义策略](#结构体定义策略)
4. [跨版本兼容实现](#跨版本兼容实现)

---

## 1. BPF CO-RE 简介

### 什么是 BPF CO-RE？

**CO-RE** = **C**ompile **O**nce - **R**un **E**verywhere

传统 BPF 程序问题：
```
编译时内核版本: 5.4  →  只能运行在 5.4
运行时内核版本: 5.10 →  ❌ 结构体偏移不匹配，访问错误
```

BPF CO-RE 解决方案：
```
编译时: 记录字段的"访问意图"
运行时: libbpf 根据运行时内核的 BTF 重定位偏移量
```

### 核心技术

| 组件 | 作用 |
|------|------|
| **BTF** (BPF Type Format) | 内核类型信息数据库 |
| **BPF_CORE_READ()** | CO-RE 字段访问宏 |
| **bpf_core_field_exists()** | 运行时检查字段是否存在 |
| **__attribute__((preserve_access_index))** | 标记结构体需要 CO-RE 重定位 |

---

## 2. vmlinux.h 的不完整性问题

### 2.1 什么是 vmlinux.h？

```bash
# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

这个文件包含了**当前内核**的所有类型定义（几万行）。

### 2.2 不同来源的 vmlinux.h 差异

#### 📦 libbpf-bootstrap 的 vmlinux.h (我们的项目)

**特点**: 某些结构体是**前向声明**（forward declaration），不完整

```c
// 示例: 在我们的 vmlinux.h 中

// ✅ 完整定义
struct bio {
    struct block_device *bi_bdev;
    unsigned int bi_flags;
    // ... 完整字段
};

// ❌ 前向声明 (不可用)
struct request;            // 仅声明，无字段定义
struct request_queue;      // 仅声明，无字段定义
```

#### 📦 HUATUO 项目的 vmlinux_x86.h

**特点**: 所有结构体都是**完整定义**

```c
// HUATUO 的 vmlinux_x86.h (line 11754-11812)
struct request {
    struct request_queue *q;
    struct blk_mq_ctx *mq_ctx;
    unsigned int cmd_flags;
    // ... 完整的 50+ 个字段
};
```

### 2.3 如何判断结构体是否可用？

| 结构体 | 我们的 vmlinux.h | 状态 | 解决方案 |
|--------|-----------------|------|----------|
| `struct bio` | ✅ 完整定义 (line 14013) | 直接使用 | 无需自定义 |
| `struct inode` | ✅ 完整定义 (line 31489) | 直接使用 | 无需自定义 |
| `struct dentry` | ✅ 完整定义 (line 23948) | 直接使用 | 无需自定义 |
| `struct request` | ❌ 前向声明 (line 31725) | **不可用** | ✅ 自己定义 |
| `struct request_queue` | ❌ 前向声明 (line 14271) | **不可用** | ✅ 自己定义 |
| `struct hd_struct` | ❌ 前向声明 | **不可用** | ✅ 自己定义 |

---

## 3. 结构体定义策略

### 3.1 完整定义 struct request

```c
// iotrace.bpf.c (line 172-192)
struct request {
    struct request_queue *q;
    struct blk_mq_ctx *mq_ctx;
    struct blk_mq_hw_ctx *mq_hctx;
    unsigned int cmd_flags;
    __u32 rq_flags;
    int internal_tag;
    unsigned int __data_len;
    int tag;
    __u64 __sector;
    struct bio *bio;
    struct bio *biotail;
    struct list_head queuelist;
    struct gendisk *rq_disk;  // ⚠️ 老内核才有 (< 5.10)
    void *part;               // struct hd_struct * 或 struct block_device *
    __u64 alloc_time_ns;
    __u64 start_time_ns;      // ✅ 用于计算 q2c 延迟
    __u64 io_start_time_ns;   // ✅ 用于计算 d2c 延迟
} __attribute__((preserve_access_index));
//                           ↑
//                           关键！告诉编译器启用 CO-RE 重定位
```

**关键点**:
- 只需要定义**我们使用的字段**
- 字段顺序可以不完全匹配，CO-RE 会处理
- `__attribute__((preserve_access_index))` 是**必须的**

### 3.2 定义兼容性结构体（三下划线后缀）

```c
// 新内核 (5.10+) 的 request_queue
struct request_queue___new {
    struct gendisk *disk;  // 新字段
} __attribute__((preserve_access_index));

// 新内核 (5.11+) 的 block_device
struct block_device___new {
    dev_t bd_dev;  // 新字段
} __attribute__((preserve_access_index));
```

**命名规范**: 
- 结构体名 + `___` (三个下划线) + `new`/`old`
- 三下划线是 libbpf 的约定，表示"兼容性变体"

### 3.3 iov_iter 的两个版本

```c
// 老内核: 使用 'type' 字段 (union)
struct iov_iter___old {
    union {
        unsigned int type;
        int __type;
    };
    size_t iov_offset;
    size_t count;
} __attribute__((preserve_access_index));

// 新内核 (6.4+): 使用 'data_source' 字段
struct iov_iter___new {
    bool data_source;  // 替代了 type
    size_t count;
} __attribute__((preserve_access_index));
```

---

## 4. 跨版本兼容实现

### 4.1 获取 request 的磁盘信息

#### 内核演变历史
```
内核 < 5.10:
  struct request {
      struct gendisk *rq_disk;  // 直接字段
  };

内核 >= 5.10:
  struct request {
      struct gendisk *rq_disk;  // 字段被删除！
      struct request_queue *q;
  };
  
  struct request_queue {
      struct gendisk *disk;     // 磁盘信息移到这里
  };
```

#### 兼容实现

```c
static __always_inline struct gendisk *get_request_disk(struct request *req)
{
    // 运行时检查: 老内核是否有 rq_disk 字段？
    if (bpf_core_field_exists(req->rq_disk)) {
        // ✅ 老内核路径 (< 5.10)
        return BPF_CORE_READ(req, rq_disk);
    } else {
        // ✅ 新内核路径 (>= 5.10)
        struct request_queue___new *q;
        q = (struct request_queue___new *)BPF_CORE_READ(req, q);
        return BPF_CORE_READ(q, disk);
    }
}
```

**关键技术**:
1. `bpf_core_field_exists(req->rq_disk)`: 编译时记录，运行时检查
2. 根据检查结果选择不同的访问路径
3. 强制转换为兼容性结构体 `request_queue___new`

### 4.2 获取分区号

#### 内核演变历史
```
内核 < 5.11:
  struct request {
      struct hd_struct *part;  // 指向 hd_struct
  };
  
  struct hd_struct {
      int partno;  // 分区号
  };

内核 >= 5.11:
  struct request {
      struct block_device *part;  // 改为指向 block_device
  };
  
  struct block_device {
      dev_t bd_dev;  // 设备号，低 8 位是分区号
  };
```

#### 兼容实现

```c
static __always_inline int get_partition_number(struct request *req)
{
    void *part = BPF_CORE_READ(req, part);  // 读取 part 指针

    // 运行时检查: 老内核是否有 hd_struct->partno？
    if (bpf_core_field_exists(((struct hd_struct *)part)->partno)) {
        // ✅ 老内核路径 (< 5.11)
        return BPF_CORE_READ((struct hd_struct *)part, partno);
    } else {
        // ✅ 新内核路径 (>= 5.11)
        struct block_device___new *new_part;
        int partno;
        new_part = (struct block_device___new *)part;
        partno = BPF_CORE_READ(new_part, bd_dev);
        return partno & 0xff;  // 提取低 8 位
    }
}
```

### 4.3 读取 iov_iter 的 type 字段

#### 内核演变历史
```
内核 < 6.4:
  struct iov_iter {
      unsigned int type;  // 读/写方向标志
      size_t count;
  };

内核 >= 6.4:
  struct iov_iter {
      bool data_source;   // 替代 type
      size_t count;
  };
```

#### 兼容实现

```c
// 在 bpf_file_read_write() 中:
struct iov_iter *from = (struct iov_iter *)PT_REGS_PARM2(ctx);
struct iov_iter___old *from_old = (struct iov_iter___old *)from;
struct iov_iter___new *from_new = (struct iov_iter___new *)from;
unsigned int type;

if (bpf_core_field_exists(from_old->type)) {
    // ✅ 老内核路径 (< 6.4)
    type = BPF_CORE_READ(from_old, type);
} else {
    // ✅ 新内核路径 (>= 6.4)
    type = BPF_CORE_READ(from_new, data_source);
}

// 判断读写方向 (最低位: 0=读, 1=写)
type = type & 0x1;
if (type)
    entry->fs_write_bytes += count;  // 写
else
    entry->fs_read_bytes += count;   // 读
```

---

## 5. BPF_CORE_READ 宏详解

### 5.1 与普通指针访问的区别

```c
// ❌ 错误: 普通指针访问 (会编译出固定偏移量)
__u64 sector = req->__sector;

// ✅ 正确: CO-RE 访问 (会记录访问意图，运行时重定位)
__u64 sector = BPF_CORE_READ(req, __sector);
```

### 5.2 链式访问

```c
// 访问: req->bio->bi_io_vec->bv_page->mapping->host->i_ino

// ❌ 错误写法:
struct bio *bio = req->bio;
struct inode *inode = bio->bi_io_vec->bv_page->mapping->host;
__u64 ino = inode->i_ino;

// ✅ 正确写法:
struct bio *bio = BPF_CORE_READ(req, bio);
struct inode *inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
__u64 ino = BPF_CORE_READ(inode, i_ino);
```

**关键**: 每次跨结构体访问都需要 `BPF_CORE_READ()`

### 5.3 bpf_probe_read 的区别

```c
// BPF_CORE_READ: 用于结构体字段访问
__u64 sector = BPF_CORE_READ(req, __sector);

// bpf_probe_read: 用于内存块复制
char comm[16];
bpf_probe_read_str(comm, 16, BPF_CORE_READ(dentry, d_name.name));
```

---

## 6. 实战经验

### 6.1 如何调试 CO-RE 重定位？

```bash
# 查看内核 BTF 信息
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "struct request"

# 查看 BPF 程序的重定位记录
llvm-objdump -r iotrace.bpf.o
```

### 6.2 常见错误

#### 错误 1: 忘记 preserve_access_index

```c
// ❌ 错误
struct request {
    __u64 __sector;
};

// ✅ 正确
struct request {
    __u64 __sector;
} __attribute__((preserve_access_index));
```

#### 错误 2: 直接指针访问

```c
// ❌ 错误
__u64 sector = req->__sector;

// ✅ 正确
__u64 sector = BPF_CORE_READ(req, __sector);
```

#### 错误 3: 字段不存在未检查

```c
// ❌ 错误 (新内核会崩溃)
struct gendisk *disk = BPF_CORE_READ(req, rq_disk);

// ✅ 正确
if (bpf_core_field_exists(req->rq_disk)) {
    disk = BPF_CORE_READ(req, rq_disk);
} else {
    // 新内核的替代方案
}
```

---

## 7. 参考资料

- **HUATUO 项目**: https://github.com/ccfos/huatuo
  - 提供了完整的 vmlinux_x86.h
  - 兼容性处理的参考实现

- **libbpf 文档**: https://libbpf.readthedocs.io/
  - BPF CO-RE 官方文档

---

## 下一篇

[📘 第 3 篇: 块设备层追踪实现](./03_block_layer.md)

详细讲解 rq_qos_issue/done 的实现细节。
