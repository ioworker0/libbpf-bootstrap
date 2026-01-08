# iotrace 开发任务清单

**项目目标**: 实现一个基于 eBPF 的 IO 追踪工具（C 语言实现）

**参考设计文档**: `iotrace_design.md`

**预计总工作量**: ~1350 行代码，1-2 天开发周期

---

## 📋 任务总览

- **阶段 1**: BPF 端开发 (~550 行)
- **阶段 2**: 用户态开发 (~800 行)
- **阶段 3**: 测试和验证

---

## 🔧 阶段 1: BPF 端开发 (iotrace.bpf.c)

### 任务 1.1: 创建基础框架和头文件引入

**工作量**: ~30 行，10 分钟

**任务内容**:
- [ ] 创建 `iotrace.bpf.c` 文件
- [ ] 引入必要的头文件
  ```c
  #include "vmlinux.h"
  #include <bpf/bpf_helpers.h>
  #include <bpf/bpf_tracing.h>
  #include <bpf/bpf_core_read.h>
  ```
- [ ] 添加 license 声明
  ```c
  char LICENSE[] SEC("license") = "GPL";
  ```
- [ ] 定义常量
  ```c
  #define TASK_COMM_LEN 16
  #define DNAME_INLINE_LEN 64
  #define PAGE_SIZE 4096
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 1-10)
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.bpf.c` (行 1-10)

---

### 任务 1.2: 定义设备过滤器配置

**工作量**: ~20 行，15 分钟

**任务内容**:
- [ ] 定义设备过滤器数组（最多 16 个设备）
  ```c
  volatile const __u32 FILTER_DEVS[16] = {};
  volatile const __u32 FILTER_DEV_COUNT = 0;
  ```
- [ ] 实现设备过滤检查函数
  ```c
  static __always_inline int should_process_device(__u32 dev)
  {
      if (FILTER_DEV_COUNT == 0)
          return 1;  // 不过滤
      
      for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
          if (FILTER_DEVS[i] == dev)
              return 1;
      
      return 0;  // 过滤掉
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 12-34)

**测试点**:
- 验证 `FILTER_DEV_COUNT == 0` 时不过滤
- 验证白名单过滤正确

---

### 任务 1.3: 定义核心数据结构

**工作量**: ~80 行，20 分钟

**任务内容**:
- [ ] 定义 `struct latency_info` - 延迟统计
  ```c
  struct latency_info {
      __u64 cnt;       // IO 计数
      __u64 max_d2c;   // 最大设备到完成延迟
      __u64 sum_d2c;   // 累计设备到完成延迟
      __u64 max_q2c;   // 最大队列到完成延迟
      __u64 sum_q2c;   // 累计队列到完成延迟
  };
  ```
- [ ] 定义 `struct io_key` - Map 键
  ```c
  struct io_key {
      __u32 pid;      // 进程 PID
      __u32 dev;      // 设备号
      __u64 inode;    // 文件 inode
  };
  ```
- [ ] 定义 `struct hash_key` - issue/done 配对键
  ```c
  struct hash_key {
      __u32 dev;       // 设备号
      __u32 _pad;
      __u64 sector;    // 扇区号
  };
  ```
- [ ] 定义 `struct io_start_info` - issue 阶段信息
  ```c
  struct io_start_info {
      __u64 inode;
      __u32 pid;
      __u32 dev;
      __u64 data_len;
      char  comm[TASK_COMM_LEN];
  };
  ```
- [ ] 定义 `struct io_data` - 最终 IO 统计数据（最复杂）
  ```c
  struct io_data {
      __u32 pid;
      __u32 dev;
      __u64 fs_write_bytes;
      __u64 fs_read_bytes;
      __u64 block_write_bytes;
      __u64 block_read_bytes;
      __u64 inode;
      __u32 flag;  // IOCB 标志
      struct latency_info latency;
      char comm[TASK_COMM_LEN];
      char filename[DNAME_INLINE_LEN];
      char d1name[DNAME_INLINE_LEN];
      char d2name[DNAME_INLINE_LEN];
      char d3name[DNAME_INLINE_LEN];
  };
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 36-87)

**注意事项**:
- 使用 `__u32`/`__u64` 等内核类型
- 字段顺序要与用户态结构体对应（用于二进制反序列化）

---

### 任务 1.4: 定义 BPF Maps

**工作量**: ~30 行，10 分钟

**任务内容**:
- [ ] 定义 `io_source_map` - IO 统计 Map（核心）
  ```c
  struct {
      __uint(type, BPF_MAP_TYPE_HASH);
      __uint(max_entries, 512);
      __uint(key_size, sizeof(struct io_key));
      __uint(value_size, sizeof(struct io_data));
  } io_source_map SEC(".maps");
  ```
- [ ] 定义 `start_info_map` - issue/done 临时 Map
  ```c
  struct {
      __uint(type, BPF_MAP_TYPE_HASH);
      __uint(max_entries, 4096);
      __uint(key_size, sizeof(struct hash_key));
      __uint(value_size, sizeof(struct io_start_info));
  } start_info_map SEC(".maps");
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 89-103)

**Map 大小设计理由**:
- `io_source_map`: 512 = 100 进程 × 5 文件
- `start_info_map`: 4096 = 支持高并发 IO

---

### 任务 1.5: 实现内核版本兼容函数 (重要!)

**工作量**: ~80 行，30 分钟

**任务内容**:

#### 子任务 1.5.1: 定义兼容结构体
- [ ] 定义 `struct request_queue___new` (新内核)
  ```c
  struct request_queue___new {
      struct gendisk *disk;
  } __attribute__((preserve_access_index));
  ```
- [ ] 定义 `struct block_device___new` (新内核)
  ```c
  struct block_device___new {
      dev_t bd_dev;
  } __attribute__((preserve_access_index));
  ```
- [ ] 定义 `struct iov_iter___new` (新内核)
  ```c
  struct iov_iter___new {
      bool data_source;
  } __attribute__((preserve_access_index));
  ```

#### 子任务 1.5.2: 实现 get_request_disk()
- [ ] 使用 `bpf_core_field_exists()` 检查 `req->rq_disk`
- [ ] 旧内核: 直接读取 `req->rq_disk`
- [ ] 新内核: 通过 `req->q->disk` 读取
  ```c
  static __always_inline struct gendisk *get_request_disk(struct request *req)
  {
      if (bpf_core_field_exists(req->rq_disk)) {
          return BPF_CORE_READ(req, rq_disk);
      } else {
          struct request_queue___new *q;
          q = (struct request_queue___new *)BPF_CORE_READ(req, q);
          return BPF_CORE_READ(q, disk);
      }
  }
  ```

#### 子任务 1.5.3: 实现 get_partition_number()
- [ ] 使用 `bpf_core_field_exists()` 检查 `hd_struct->partno`
- [ ] 旧内核: 读取 `hd_struct->partno`
- [ ] 新内核: 从 `block_device->bd_dev` 取低 8 位
  ```c
  static __always_inline int get_partition_number(struct request *req)
  {
      void *part = BPF_CORE_READ(req, part);
      
      if (bpf_core_field_exists(((struct hd_struct *)part)->partno)) {
          return BPF_CORE_READ((struct hd_struct *)part, partno);
      } else {
          struct block_device___new *new_part;
          int partno;
          new_part = (struct block_device___new *)part;
          partno = BPF_CORE_READ(new_part, bd_dev);
          return partno & 0xff;
      }
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 123-167)

**支持内核版本**:
- Linux 4.x ~ 6.x

**测试重点**:
- 在不同内核版本上验证设备号正确

---

### 任务 1.6: 实现文件路径提取辅助函数

**工作量**: ~40 行，15 分钟

**任务内容**:
- [ ] 实现 `init_io_data()` 函数
  - 提取进程 PID 和 TGID
  - 读取进程名 (comm)
  - 提取文件名和 3 级父目录名
  ```c
  static __always_inline void init_io_data(struct io_data *entry,
                                           struct dentry *root_dentry,
                                           struct dentry *dentry,
                                           struct inode *inode)
  {
      __u64 t = bpf_get_current_pid_tgid();
      entry->pid = t >> 32;
      
      bpf_get_current_comm(entry->comm, TASK_COMM_LEN);
      
      // 文件名
      bpf_probe_read_str(entry->filename, DNAME_INLINE_LEN,
                         BPF_CORE_READ(dentry, d_name.name));
      
      // 父目录
      dentry = BPF_CORE_READ(dentry, d_parent);
      bpf_probe_read_str(entry->d1name, DNAME_INLINE_LEN,
                         BPF_CORE_READ(dentry, d_name.name));
      
      // 爷目录
      dentry = BPF_CORE_READ(dentry, d_parent);
      bpf_probe_read_str(entry->d2name, DNAME_INLINE_LEN,
                         BPF_CORE_READ(dentry, d_name.name));
      
      // 曾祖目录
      dentry = BPF_CORE_READ(dentry, d_parent);
      bpf_probe_read_str(entry->d3name, DNAME_INLINE_LEN,
                         BPF_CORE_READ(dentry, d_name.name));
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 308-337)

**注意事项**:
- 只提取 3 级目录（BPF 栈空间限制）
- 用户态拼接: `d3name/d2name/d1name/filename`

---

### 任务 1.7: 实现块层 IO 追踪钩子 (核心!)

**工作量**: ~120 行，45 分钟

**任务内容**:

#### 子任务 1.7.1: 实现 rq_qos_issue (IO 提交)
- [ ] 定义 BPF 程序入口
  ```c
  SEC("kprobe/rq_qos_issue")
  int bpf_rq_qos_issue(struct pt_regs *ctx)
  ```
- [ ] 获取 request 指针: `PT_REGS_PARM2(ctx)`
- [ ] 过滤元数据请求: `cmd_flags & REQ_META`
- [ ] 获取设备号和分区号
  - 调用 `get_request_disk()`
  - 调用 `get_partition_number()`
  - 构造设备号: `(major & 0xfff) << 20 | (minor + partno)`
- [ ] 检查设备过滤: `should_process_device()`
- [ ] 提取 inode 信息
  - 从 `req->bio->bi_io_vec->bv_page->mapping->host` 获取
  - `inode == 0` 表示 Direct IO
- [ ] 记录进程和 IO 信息
  - `info.pid = bpf_get_current_pid_tgid() >> 32`
  - `info.data_len = req->__data_len`
  - `bpf_get_current_comm(info.comm)`
- [ ] 保存到 `start_info_map[key=(dev, sector)]`
  ```c
  struct hash_key key = {.dev = dev, .sector = req->__sector};
  bpf_map_update_elem(&start_info_map, &key, &info, BPF_ANY);
  ```

#### 子任务 1.7.2: 实现 rq_qos_done (IO 完成)
- [ ] 定义 BPF 程序入口
  ```c
  SEC("kprobe/rq_qos_done")
  int bpf_rq_qos_done(struct pt_regs *ctx)
  ```
- [ ] 获取设备号和扇区号
- [ ] 从 `start_info_map` 查找 issue 信息
  ```c
  info = bpf_map_lookup_elem(&start_info_map, &info_key);
  if (!info) return 0;
  ```
- [ ] 构造 `io_source_map` 的 key
  - `io_key.dev = info->dev`
  - `io_key.inode = info->inode`
  - 如果 `inode == 0`，设置 `io_key.pid = info->pid` (Direct IO)
- [ ] 查找或创建 `io_source_map` 条目
  ```c
  entry = bpf_map_lookup_elem(&io_source_map, &io_key);
  if (!entry) entry = &data;  // 新条目
  ```
- [ ] 判断读写方向，累加字节数
  ```c
  if (is_write_request(cmd_flags)) {
      entry->block_write_bytes += info->data_len;
  } else {
      entry->block_read_bytes += info->data_len;
  }
  ```
- [ ] 计算并累加延迟（关键！）
  ```c
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
  ```
- [ ] 如果是新条目，初始化字段
  ```c
  if (entry == &data) {
      entry->pid = info->pid;
      entry->dev = info->dev;
      entry->inode = info->inode;
      bpf_probe_read_str(entry->comm, TASK_COMM_LEN, info->comm);
      bpf_map_update_elem(&io_source_map, &io_key, &data, BPF_ANY);
  }
  ```
- [ ] 删除临时记录
  ```c
  bpf_map_delete_elem(&start_info_map, &info_key);
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 171-305)

**关键技术点**:
- issue/done 配对机制
- 延迟计算（含最大值）
- Direct IO 识别

---

### 任务 1.8: 实现文件系统层 IO 追踪钩子

**工作量**: ~100 行，35 分钟

**任务内容**:

#### 子任务 1.8.1: 实现通用文件读写处理函数
- [ ] 定义 `bpf_file_read_write()` 静态内联函数
  ```c
  static __always_inline int bpf_file_read_write(struct pt_regs *ctx)
  ```
- [ ] 从 `PT_REGS_PARM1(ctx)` 获取 `kiocb` 指针
- [ ] 提取 inode 和设备号
  ```c
  inode = BPF_CORE_READ(iocb, ki_filp, f_inode);
  key.inode = BPF_CORE_READ(inode, i_ino);
  key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  ```
- [ ] 检查设备过滤
- [ ] 查找或创建 `io_source_map` 条目
- [ ] 首次访问时初始化文件路径
  ```c
  if (entry->pid == 0) {  // 新条目
      dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
      root_dentry = BPF_CORE_READ(iocb, ki_filp, f_path.mnt, mnt_root);
      init_io_data(entry, root_dentry, dentry, inode);
      entry->dev = key.dev;
      entry->inode = key.inode;
  }
  ```
- [ ] 从 `PT_REGS_PARM2(ctx)` 获取 `iov_iter` 指针
- [ ] 读取 IO 字节数: `count = iov_iter->count`
- [ ] 兼容 iov_iter 结构（关键！）
  ```c
  unsigned int type;
  if (bpf_core_field_exists(from->type)) {
      type = BPF_CORE_READ(from, type);  // 旧内核
  } else {
      struct iov_iter___new *from_new;
      from_new = (struct iov_iter___new *)from;
      type = BPF_CORE_READ(from_new, data_source);  // 新内核
  }
  ```
- [ ] 判断读写方向并累加
  ```c
  type = type & 0x1;  // 最低位: 0=read, 1=write
  if (type)
      entry->fs_write_bytes += count;
  else
      entry->fs_read_bytes += count;
  ```
- [ ] 保存 IOCB 标志
  ```c
  entry->flag = BPF_CORE_READ(iocb, ki_flags);  // 用于识别 Direct IO
  ```
- [ ] 更新到 Map
  ```c
  if (entry == &data)
      bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);
  ```

#### 子任务 1.8.2: 定义文件系统钩子
- [ ] 定义通用 read 钩子
  ```c
  SEC("kprobe/anyfs_file_read_iter")
  int bpf_anyfs_file_read_iter(struct pt_regs *ctx)
  {
      return bpf_file_read_write(ctx);
  }
  ```
- [ ] 定义通用 write 钩子
  ```c
  SEC("kprobe/anyfs_file_write_iter")
  int bpf_anyfs_file_write_iter(struct pt_regs *ctx)
  {
      return bpf_file_read_write(ctx);
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 339-420)

**注意事项**:
- 用户态动态挂载到 `ext4_file_read_iter` / `xfs_file_read_iter` 等

---

### 任务 1.9: 实现页面缓存 IO 追踪钩子

**工作量**: ~80 行，25 分钟

**任务内容**:

#### 子任务 1.9.1: 实现 filemap_fault (mmap 读)
- [ ] 定义钩子
  ```c
  SEC("kprobe/filemap_fault")
  int bpf_filemap_fault(struct pt_regs *ctx)
  ```
- [ ] 从 `PT_REGS_PARM1(ctx)` 获取 `vm_fault` 指针
- [ ] 提取 VMA: `vma = vm->vma`
- [ ] 提取 inode 和设备号
  ```c
  inode = BPF_CORE_READ(vma, vm_file, f_inode);
  key.inode = BPF_CORE_READ(inode, i_ino);
  key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  ```
- [ ] 检查设备过滤
- [ ] 查找或创建条目
- [ ] 首次访问时初始化（类似文件系统钩子）
- [ ] 累加页面大小
  ```c
  entry->fs_read_bytes += PAGE_SIZE;  // mmap 读按页计算
  ```
- [ ] 更新到 Map

#### 子任务 1.9.2: 实现 anyfs_filemap_page_mkwrite (mmap 写)
- [ ] 定义通用钩子
  ```c
  SEC("kprobe/anyfs_filemap_page_mkwrite")
  int bpf_anyfs_filemap_page_mkwrite(struct pt_regs *ctx)
  ```
- [ ] 实现逻辑（类似 filemap_fault）
- [ ] 累加页面大小
  ```c
  entry->fs_write_bytes += PAGE_SIZE;  // mmap 写按页计算
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 423-508)

**注意事项**:
- 用户态动态挂载到 `ext4_page_mkwrite` / `xfs_filemap_page_mkwrite`

---

### 任务 1.10: 定义 REQ_OP 相关常量和辅助函数

**工作量**: ~20 行，10 分钟

**任务内容**:
- [ ] 定义请求操作位掩码
  ```c
  #define REQ_OP_BITS 8
  #define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
  #define REQ_META (1ULL << __REQ_META)
  ```
- [ ] 定义操作类型
  ```c
  #define REQ_OP_READ 0
  #define REQ_OP_WRITE 1
  ```
- [ ] 实现判断写请求函数
  ```c
  static __always_inline int is_write_request(__u32 cmd_flags)
  {
      return (cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE;
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/bpf/iotracing.c` (行 113-121)

---

### 阶段 1 总结检查清单

- [ ] 所有数据结构定义完成
- [ ] 所有 BPF Maps 定义完成
- [ ] 内核兼容函数实现完成（3 个）
- [ ] 块层钩子实现完成（issue/done）
- [ ] 文件系统钩子实现完成（read/write）
- [ ] 页面缓存钩子实现完成（fault/mkwrite）
- [ ] 代码编译通过（clang -target bpf）
- [ ] 没有 verifier 错误

**预计代码行数**: ~550 行
**预计耗时**: 3-4 小时

---

## 🖥️ 阶段 2: 用户态开发 (iotrace.c)

### 任务 2.1: 创建基础框架和头文件

**工作量**: ~40 行，15 分钟

**任务内容**:
- [ ] 创建 `iotrace.c` 文件
- [ ] 引入必要的头文件
  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <errno.h>
  #include <signal.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <getopt.h>
  #include <sys/resource.h>
  #include <bpf/libbpf.h>
  #include <bpf/bpf.h>
  #include "iotrace.skel.h"  // 自动生成
  ```
- [ ] 定义全局变量
  ```c
  static volatile bool exiting = false;
  ```

**参考代码**:
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 1-20)

---

### 任务 2.2: 定义用户态数据结构

**工作量**: ~120 行，20 分钟

**任务内容**:
- [ ] 定义 `struct latency_info` (与 BPF 端对应)
  ```c
  struct latency_info {
      uint64_t cnt;
      uint64_t max_d2c;
      uint64_t sum_d2c;
      uint64_t max_q2c;
      uint64_t sum_q2c;
  };
  ```
- [ ] 定义 `struct io_data` (与 BPF 端对应)
  ```c
  struct io_data {
      uint32_t pid;
      uint32_t dev;
      uint64_t fs_write_bytes;
      uint64_t fs_read_bytes;
      uint64_t block_write_bytes;
      uint64_t block_read_bytes;
      uint64_t inode;
      uint32_t flag;
      struct latency_info latency;
      char comm[16];
      char filename[64];
      char d1name[64];
      char d2name[64];
      char d3name[64];
  };
  ```
- [ ] 定义进程聚合数据结构
  ```c
  struct process_data {
      uint32_t pid;
      char comm[256];  // 完整命令行
      uint64_t fs_read;
      uint64_t fs_write;
      uint64_t disk_read;
      uint64_t disk_write;
      uint64_t file_count;
  };
  ```
- [ ] 定义文件统计数据结构
  ```c
  struct file_stat {
      uint32_t dev;
      uint64_t fs_read;
      uint64_t fs_write;
      uint64_t disk_read;
      uint64_t disk_write;
      uint64_t q2c_avg;
      uint64_t q2c_max;
      uint64_t d2c_avg;
      uint64_t d2c_max;
      uint64_t inode;
      char filepath[256];
  };
  ```

**注意事项**:
- 字段顺序和大小必须与 BPF 端完全一致
- 用于 `binary.Read` 反序列化

---

### 任务 2.3: 实现信号处理

**工作量**: ~15 行，5 分钟

**任务内容**:
- [ ] 实现信号处理函数
  ```c
  static void handle_signal(int sig)
  {
      exiting = true;
  }
  ```
- [ ] 在 main 中注册信号
  ```c
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  ```

**参考代码**:
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 92-96)

---

### 任务 2.4: 实现文件系统检测

**工作量**: ~30 行，15 分钟

**任务内容**:
- [ ] 实现 `is_fs_supported()` 函数
  ```c
  static bool is_fs_supported(const char *fs_name)
  {
      FILE *f = fopen("/proc/filesystems", "r");
      if (!f) return false;
      
      char line[256];
      bool found = false;
      while (fgets(line, sizeof(line), f)) {
          if (strstr(line, fs_name)) {
              found = true;
              break;
          }
      }
      fclose(f);
      return found;
  }
  ```

**测试点**:
- 在只有 ext4 的系统上验证
- 在支持 xfs 的系统上验证

---

### 任务 2.5: 实现 kprobe 函数检测

**工作量**: ~40 行，20 分钟

**任务内容**:
- [ ] 实现 `check_kprobe_exists()` 函数
  ```c
  static bool check_kprobe_exists(const char *func_name)
  {
      FILE *f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
      if (!f) return false;
      
      char line[256];
      bool found = false;
      while (fgets(line, sizeof(line), f)) {
          // 函数名在空格之前
          char *space = strchr(line, ' ');
          if (space) *space = '\0';
          
          // 去除换行符
          char *newline = strchr(line, '\n');
          if (newline) *newline = '\0';
          
          if (strcmp(line, func_name) == 0) {
              found = true;
              break;
          }
      }
      fclose(f);
      return found;
  }
  ```

**测试点**:
- 检测 `rq_qos_issue` vs `__rq_qos_issue`

---

### 任务 2.6: 实现设备号解析

**工作量**: ~60 行，25 分钟

**任务内容**:
- [ ] 实现 `parse_device_numbers()` 函数
  ```c
  static int parse_device_numbers(const char *device_str, 
                                   uint32_t *devs, 
                                   uint32_t *count)
  {
      char *str_copy = strdup(device_str);
      char *token = strtok(str_copy, ",");
      *count = 0;
      
      while (token && *count < 16) {
          unsigned int major, minor;
          if (sscanf(token, "%u:%u", &major, &minor) != 2) {
              free(str_copy);
              return -1;
          }
          
          // 转换为内核格式
          devs[*count] = ((major & 0xfff) << 20) | minor;
          (*count)++;
          
          token = strtok(NULL, ",");
      }
      
      free(str_copy);
      return 0;
  }
  ```
- [ ] 实现设备号格式化函数
  ```c
  static void format_device(uint32_t dev, char *buf, size_t size)
  {
      unsigned int major = (dev >> 20) & 0xfff;
      unsigned int minor = dev & 0xfffff;
      snprintf(buf, size, "%u:%u", major, minor);
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 154-197)

---

### 任务 2.7: 实现字节格式化

**工作量**: ~30 行，10 分钟

**任务内容**:
- [ ] 实现 `format_bytes()` 函数
  ```c
  static void format_bytes(uint64_t bytes, char *buf, size_t size)
  {
      const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
      int i = 0;
      double value = (double)bytes;
      
      while (value >= 1024 && i < 5) {
          value /= 1024;
          i++;
      }
      
      if (value < 10 && i > 0)
          snprintf(buf, size, "%.1f%s", value, units[i]);
      else
          snprintf(buf, size, "%.0f%s", value, units[i]);
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 688-706)

**测试点**:
- `1536` → "1.5KB"
- `1048576` → "1.0MB"
- `1073741824` → "1GB"

---

### 任务 2.8: 实现 Skeleton 加载和初始化

**工作量**: ~100 行，35 分钟

**任务内容**:
- [ ] 提升 memlock 限制
  ```c
  struct rlimit rlim = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
      fprintf(stderr, "Warning: failed to increase RLIMIT_MEMLOCK\n");
  }
  ```
- [ ] 设置 libbpf 打印函数
  ```c
  libbpf_set_print(libbpf_print_fn);
  ```
- [ ] **处理 BTF 路径（重要！）**
  ```c
  const char *btf_path = "/plux/btf/kernel.btf";
  struct iotrace_bpf *skel;
  
  // 检查自定义 BTF 是否存在
  if (access(btf_path, R_OK) == 0) {
      fprintf(stderr, "Found custom BTF at %s, using it.\n", btf_path);
      LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
      skel = iotrace_bpf__open_opts(&opts);
  } else {
      fprintf(stderr, "Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
      skel = iotrace_bpf__open();
  }
  
  if (!skel) {
      fprintf(stderr, "Failed to open BPF skeleton\n");
      return 1;
  }
  ```
- [ ] 设置设备过滤器（如果指定）
  ```c
  if (device_count > 0) {
      for (int i = 0; i < device_count; i++) {
          skel->rodata->FILTER_DEVS[i] = devices[i];
      }
      skel->rodata->FILTER_DEV_COUNT = device_count;
  }
  ```
- [ ] 加载 BPF 程序
  ```c
  err = iotrace_bpf__load(skel);
  if (err) {
      fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
      goto cleanup;
  }
  ```

**参考代码**:
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 459-471, BTF 处理)
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 402-495, 完整流程)

**为什么需要 BTF 处理？**
- **BTF (BPF Type Format)**: 内核数据结构的类型信息
- **自定义 BTF 路径**: 在某些受限环境（如容器）中，系统 BTF 可能不可用
- **降级处理**: 如果自定义 BTF 不存在，让 libbpf 自动查找系统 BTF
- **常见 BTF 位置**:
  - `/sys/kernel/btf/vmlinux` (系统默认)
  - `/plux/btf/kernel.btf` (自定义路径)
  - `/boot/vmlinux-$(uname -r)` (某些发行版)

**BTF 相关问题排查**:
```bash
# 检查系统 BTF 是否存在
ls -lh /sys/kernel/btf/vmlinux

# 如果不存在，需要自定义 BTF
# 可以从其他机器复制或使用 pahole 生成
```

---

### 任务 2.9: 实现动态 BPF 程序挂载

**工作量**: ~100 行，40 分钟

**任务内容**:

#### 子任务 2.9.1: 挂载块层钩子
- [ ] 检测 kprobe 函数可用性
  ```c
  const char *rq_qos_issue_func, *rq_qos_done_func;
  if (check_kprobe_exists("rq_qos_issue")) {
      rq_qos_issue_func = "rq_qos_issue";
      rq_qos_done_func = "rq_qos_done";
  } else {
      rq_qos_issue_func = "__rq_qos_issue";
      rq_qos_done_func = "__rq_qos_done";
  }
  ```
- [ ] 挂载 issue 和 done
  ```c
  skel->links.bpf_rq_qos_issue = 
      bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_issue,
                                  false, rq_qos_issue_func);
  
  skel->links.bpf_rq_qos_done = 
      bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_done,
                                  false, rq_qos_done_func);
  ```

#### 子任务 2.9.2: 挂载文件系统钩子
- [ ] 检测 ext4 支持
  ```c
  if (is_fs_supported("ext4")) {
      // 挂载 ext4_file_read_iter
      bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter,
                                  false, "ext4_file_read_iter");
      // 挂载 ext4_file_write_iter
      bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_write_iter,
                                  false, "ext4_file_write_iter");
      // 挂载 ext4_page_mkwrite
      bpf_program__attach_kprobe(skel->progs.bpf_anyfs_filemap_page_mkwrite,
                                  false, "ext4_page_mkwrite");
  }
  ```
- [ ] 检测 xfs 支持（类似）
  ```c
  if (is_fs_supported("xfs")) {
      // 挂载 xfs_file_read_iter
      // 挂载 xfs_file_write_iter
      // 挂载 xfs_filemap_page_mkwrite
  }
  ```

#### 子任务 2.9.3: 挂载页面缓存钩子
- [ ] 挂载 filemap_fault
  ```c
  skel->links.bpf_filemap_fault = 
      bpf_program__attach_kprobe(skel->progs.bpf_filemap_fault,
                                  false, "filemap_fault");
  ```

**参考代码**:
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 338-422)

**注意事项**:
- 挂载失败时记录警告，但继续执行
- 至少挂载块层钩子成功

---

### 任务 2.10: 实现 Map 数据读取

**工作量**: ~60 行，25 分钟

**任务内容**:
- [ ] 获取 map fd
  ```c
  int map_fd = bpf_map__fd(skel->maps.io_source_map);
  ```
- [ ] 遍历 map
  ```c
  struct io_key key, next_key;
  struct io_data data;
  bool first = true;
  
  while (true) {
      int ret;
      if (first) {
          ret = bpf_map_get_next_key(map_fd, NULL, &next_key);
          first = false;
      } else {
          ret = bpf_map_get_next_key(map_fd, &key, &next_key);
      }
      
      if (ret != 0)
          break;
      
      key = next_key;
      
      // 读取 value
      if (bpf_map_lookup_elem(map_fd, &key, &data) == 0) {
          // 处理数据
          process_io_data(&data, duration);
      }
  }
  ```

**注意事项**:
- Little-endian 字节序（x86/ARM 都是）
- 数据已经是 C 结构体格式，无需反序列化

---

### 任务 2.11: 实现数据聚合和排序

**工作量**: ~100 行，35 分钟

**任务内容**:
- [ ] 定义进程 IO 统计数组
  ```c
  #define MAX_PROCESSES 1024
  struct process_data processes[MAX_PROCESSES];
  int process_count = 0;
  ```
- [ ] 聚合数据到进程级
  ```c
  void aggregate_io_data(struct io_data *data, uint64_t duration)
  {
      // 查找或创建进程条目
      int idx = find_or_create_process(data->pid);
      
      // 累加 IO 统计（转换为速率: bytes/duration）
      processes[idx].fs_read += data->fs_read_bytes / duration;
      processes[idx].fs_write += data->fs_write_bytes / duration;
      processes[idx].disk_read += data->block_read_bytes / duration;
      processes[idx].disk_write += data->block_write_bytes / duration;
      processes[idx].file_count++;
      
      // 保存 comm（首次）
      if (processes[idx].comm[0] == '\0') {
          strncpy(processes[idx].comm, data->comm, sizeof(processes[idx].comm));
      }
  }
  ```
- [ ] 实现排序（按 disk IO 总量）
  ```c
  int compare_processes(const void *a, const void *b)
  {
      const struct process_data *pa = a;
      const struct process_data *pb = b;
      uint64_t total_a = pa->disk_read + pa->disk_write;
      uint64_t total_b = pb->disk_read + pb->disk_write;
      return (total_b > total_a) - (total_b < total_a);  // 降序
  }
  
  qsort(processes, process_count, sizeof(struct process_data), compare_processes);
  ```

---

### 任务 2.12: 实现进程 cmdline 读取

**工作量**: ~40 行，15 分钟

**任务内容**:
- [ ] 实现 `get_proc_cmdline()` 函数
  ```c
  static bool get_proc_cmdline(pid_t pid, char *buf, size_t size)
  {
      char path[64];
      snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
      
      int fd = open(path, O_RDONLY);
      if (fd < 0)
          return false;
      
      ssize_t n = read(fd, buf, size - 1);
      close(fd);
      
      if (n <= 0)
          return false;
      
      buf[n] = '\0';
      
      // 将 \0 替换为空格
      for (ssize_t i = 0; i < n - 1; i++) {
          if (buf[i] == '\0')
              buf[i] = ' ';
      }
      
      return true;
  }
  ```

**参考代码**:
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 251-254)

---

### 任务 2.13: 实现格式化输出

**工作量**: ~150 行，45 分钟

**任务内容**:

#### 子任务 2.13.1: 实现进程级汇总表格
- [ ] 打印表头
  ```c
  printf("PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES\n");
  printf("======  ==================== ======= ======== ========= ========== =====\n");
  ```
- [ ] 遍历进程（Top N）
  ```c
  for (int i = 0; i < process_count && i < max_processes; i++) {
      struct process_data *p = &processes[i];
      
      char fs_read_str[32], fs_write_str[32];
      char disk_read_str[32], disk_write_str[32];
      
      format_bytes(p->fs_read, fs_read_str, sizeof(fs_read_str));
      format_bytes(p->fs_write, fs_write_str, sizeof(fs_write_str));
      format_bytes(p->disk_read, disk_read_str, sizeof(disk_read_str));
      format_bytes(p->disk_write, disk_write_str, sizeof(disk_write_str));
      
      // 截断或填充 comm
      char comm[21];
      snprintf(comm, sizeof(comm), "%-20s", p->comm);
      
      printf("%-6u  %s %7s %8s %9s %10s %5lu\n",
             p->pid, comm,
             fs_read_str, fs_write_str,
             disk_read_str, disk_write_str,
             p->file_count);
  }
  ```

#### 子任务 2.13.2: 实现文件级详情表格
- [ ] 再次遍历 Map，按进程分组
- [ ] 对每个进程，打印详情
  ```c
  printf("===========================================================================\n");
  printf("PID: %-6u  TOTAL_IO: R=%s W=%s  FILES: %lu\n",
         p->pid, fs_read_str, fs_write_str, p->file_count);
  printf("COMMAND: %s\n", cmdline);
  printf("-----------------------------------\n");
  printf("DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE\n");
  ```
- [ ] 打印每个文件
  ```c
  // 计算延迟
  uint64_t q2c_avg = 0, q2c_max = 0, d2c_avg = 0, d2c_max = 0;
  if (data->latency.cnt > 0) {
      q2c_avg = data->latency.sum_q2c / data->latency.cnt / 1000;  // ns->us
      d2c_avg = data->latency.sum_d2c / data->latency.cnt / 1000;
      q2c_max = data->latency.max_q2c / 1000;
      d2c_max = data->latency.max_d2c / 1000;
  }
  
  // 构建文件路径
  char filepath[256];
  if (data->inode == 0) {
      snprintf(filepath, sizeof(filepath), "[direct IO]");
  } else {
      snprintf(filepath, sizeof(filepath), "%s/%s/%s/%s",
               data->d3name, data->d2name, data->d1name, data->filename);
      // 去除前导 /
      if (filepath[0] == '/')
          memmove(filepath, filepath + 1, strlen(filepath));
      
      // 添加 Direct IO 标识
      if (data->flag & 0x4) {
          strcat(filepath, " [direct IO]");
      }
  }
  
  // 格式化设备号
  char dev_str[16];
  format_device(data->dev, dev_str, sizeof(dev_str));
  
  printf("%-7s %7s %8s %9s %9s   q2c=%lu(max %lu) d2c=%lu(max %lu)  %s\n",
         dev_str, fs_read_str, fs_write_str,
         disk_read_str, disk_write_str,
         q2c_avg, q2c_max, d2c_avg, d2c_max,
         filepath);
  ```

**参考代码**:
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 572-685)

---

### 任务 2.14: 实现命令行参数处理

**工作量**: ~80 行，25 分钟

**任务内容**:
- [ ] 定义配置结构体
  ```c
  struct config {
      uint64_t duration;           // 追踪时长（秒）
      uint32_t max_processes;      // 显示最多进程数
      uint32_t max_files_per_process;  // 每进程显示最多文件数
      char device_str[256];        // 设备过滤字符串
  };
  ```
- [ ] 实现参数解析
  ```c
  static struct option long_options[] = {
      {"duration", required_argument, 0, 'd'},
      {"device", required_argument, 0, 'D'},
      {"max-processes", required_argument, 0, 'p'},
      {"max-files", required_argument, 0, 'f'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}
  };
  
  while ((opt = getopt_long(argc, argv, "d:D:p:f:h", long_options, NULL)) != -1) {
      switch (opt) {
      case 'd':
          config.duration = atoi(optarg);
          break;
      case 'D':
          strncpy(config.device_str, optarg, sizeof(config.device_str) - 1);
          break;
      case 'p':
          config.max_processes = atoi(optarg);
          break;
      case 'f':
          config.max_files_per_process = atoi(optarg);
          break;
      case 'h':
          print_usage(argv[0]);
          return 0;
      default:
          print_usage(argv[0]);
          return 1;
      }
  }
  ```
- [ ] 实现 help 信息
  ```c
  static void print_usage(const char *prog)
  {
      printf("Usage: %s [OPTIONS]\n\n", prog);
      printf("Options:\n");
      printf("  -d, --duration SECONDS      Tracing duration (default: 8)\n");
      printf("  -D, --device DEVICE         Filter by device (e.g., 8:0 or 8:0,253:0)\n");
      printf("  -p, --max-processes NUM     Max processes to display (default: 10)\n");
      printf("  -f, --max-files NUM         Max files per process (default: 5)\n");
      printf("  -h, --help                  Show this help\n");
  }
  ```

**参考代码**:
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 384-426)
- `/Users/user/TC/huatuo/cmd/iotracing/iotracing.go` (行 709-745)

---

### 任务 2.15: 实现主循环和等待逻辑

**工作量**: ~40 行，15 分钟

**任务内容**:
- [ ] 记录开始时间
  ```c
  time_t start_time = time(NULL);
  ```
- [ ] 等待指定时长
  ```c
  printf("Tracing IO for %lu seconds... (Press Ctrl-C to stop)\n", config.duration);
  
  while (!exiting) {
      sleep(1);
      if (time(NULL) - start_time >= config.duration)
          break;
  }
  ```
- [ ] 分离 BPF 程序（停止追踪）
  ```c
  iotrace_bpf__detach(skel);
  ```
- [ ] 读取和处理数据
  ```c
  // 读取 io_source_map
  // 聚合数据
  // 排序
  // 输出
  ```
- [ ] 清理资源
  ```c
  cleanup:
      iotrace_bpf__destroy(skel);
      return err;
  ```

---

### 任务 2.16: 实现 libbpf 打印函数

**工作量**: ~15 行，5 分钟

**任务内容**:
- [ ] 实现打印回调
  ```c
  static int libbpf_print_fn(enum libbpf_print_level level,
                             const char *format, va_list args)
  {
      if (level == LIBBPF_DEBUG)
          return 0;  // 抑制 debug 输出
      
      return vfprintf(stderr, format, args);
  }
  ```

**参考代码**:
- `/Users/user/C/ebpf/libbbbbb/examples/c/captrace.c` (行 378-382)

---

### 阶段 2 总结检查清单

- [ ] BTF 路径处理正确（支持自定义和系统 BTF）
- [ ] Skeleton 加载成功
- [ ] 动态挂载所有 BPF 程序
- [ ] Map 数据正确读取
- [ ] 数据聚合正确
- [ ] 排序功能正常
- [ ] 输出格式正确美观
- [ ] 字节单位转换正确
- [ ] 延迟计算正确（avg + max）
- [ ] Direct IO 标识正确
- [ ] 命令行参数解析正常
- [ ] 信号处理正常
- [ ] 无内存泄漏

**预计代码行数**: ~820 行
**预计耗时**: 4-5 小时

---

## 🧪 阶段 3: 测试和验证

### 任务 3.1: 编译测试

**工作量**: 30 分钟

**任务内容**:
- [ ] 编译 BPF 程序
  ```bash
  clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 \
        -I/path/to/vmlinux.h \
        -c iotrace.bpf.c -o iotrace.bpf.o
  ```
- [ ] 生成 skeleton
  ```bash
  bpftool gen skeleton iotrace.bpf.o > iotrace.skel.h
  ```
- [ ] 编译用户态程序
  ```bash
  gcc -g -O2 -Wall \
      iotrace.c -o iotrace \
      -lbpf -lelf -lz
  ```
- [ ] 检查编译警告和错误

---

### 任务 3.2: 基础功能测试

**工作量**: 30 分钟

**测试场景**:
- [ ] 无参数运行（使用默认配置）
  ```bash
  sudo ./iotrace
  ```
- [ ] 指定追踪时长
  ```bash
  sudo ./iotrace --duration 5
  ```
- [ ] 设备过滤
  ```bash
  sudo ./iotrace --device 8:0
  ```
- [ ] 多设备过滤
  ```bash
  sudo ./iotrace --device 8:0,253:0
  ```
- [ ] 限制进程数
  ```bash
  sudo ./iotrace --max-processes 20
  ```

**验证点**:
- 程序正常启动
- 追踪指定时长后退出
- 有输出数据
- 无崩溃

---

### 任务 3.3: IO 负载测试

**工作量**: 45 分钟

**测试场景**:

#### 场景 1: dd 写测试
```bash
# 终端 1: 启动追踪
sudo ./iotrace --duration 10

# 终端 2: 生成写负载
dd if=/dev/zero of=/tmp/test.dat bs=1M count=1000
```

**验证点**:
- [ ] 能看到 dd 进程
- [ ] FS_WRITE ≈ DISK_WRITE (无缓存)
- [ ] 文件路径正确 (/tmp/test.dat)
- [ ] 延迟有数值

#### 场景 2: dd 读测试
```bash
# 清除缓存
sync; echo 3 > /proc/sys/vm/drop_caches

# 终端 1: 启动追踪
sudo ./iotrace --duration 10

# 终端 2: 生成读负载
dd if=/tmp/test.dat of=/dev/null bs=1M
```

**验证点**:
- [ ] 能看到 dd 进程
- [ ] FS_READ ≈ DISK_READ (冷读)
- [ ] 第二次读: FS_READ >> DISK_READ (缓存命中)

#### 场景 3: fio 随机 IO 测试
```bash
# 终端 1: 启动追踪
sudo ./iotrace --duration 30

# 终端 2: 运行 fio
fio --name=randwrite --ioengine=libaio --iodepth=16 \
    --rw=randwrite --bs=4k --direct=1 \
    --size=100M --numjobs=1 --runtime=20 \
    --group_reporting --filename=/tmp/fio_test
```

**验证点**:
- [ ] 能看到 fio 进程
- [ ] 有 [direct IO] 标识
- [ ] FS_WRITE ≈ DISK_WRITE (Direct IO)
- [ ] 延迟数值合理

---

### 任务 3.4: 内核版本兼容性测试

**工作量**: 1-2 小时

**测试环境**:
- [ ] Ubuntu 20.04 (Linux 5.4)
- [ ] Ubuntu 22.04 (Linux 5.15)
- [ ] Ubuntu 24.04 (Linux 6.8)

**测试内容**:
- [ ] 程序能正常加载
- [ ] BPF 程序能挂载
- [ ] 设备号正确获取
- [ ] 分区号正确解析
- [ ] 读写方向正确识别
- [ ] 数据统计准确

---

### 任务 3.5: 文件系统兼容性测试

**工作量**: 30 分钟

**测试场景**:
- [ ] ext4 文件系统
  - 验证能正常追踪
  - 验证文件路径正确
- [ ] xfs 文件系统
  - 验证能正常追踪
  - 验证文件路径正确
- [ ] 同时存在 ext4 和 xfs
  - 验证两者都能追踪

---

### 任务 3.6: 边界条件测试

**工作量**: 30 分钟

**测试场景**:
- [ ] 无 IO 时的输出
- [ ] 大量并发 IO (如 stress-ng)
- [ ] 大文件 IO (>1GB)
- [ ] 小文件 IO (<4KB)
- [ ] mmap IO
- [ ] Direct IO
- [ ] 进程中途退出
- [ ] Ctrl-C 中断

---

### 任务 3.7: 性能测试

**工作量**: 30 分钟

**测试内容**:
- [ ] CPU 开销 (top/htop 查看)
- [ ] 内存占用
- [ ] 对业务 IO 性能的影响
  - 运行 fio，对比开启/关闭 iotrace 的性能

**接受标准**:
- CPU 开销 < 5%
- 内存占用 < 100MB
- 对 IO 性能影响 < 5%

---

### 任务 3.8: 输出格式验证

**工作量**: 20 分钟

**验证点**:
- [ ] 表格对齐
- [ ] 字节单位正确 (B/KB/MB/GB)
- [ ] 延迟单位正确 (微秒)
- [ ] 设备号格式正确 (major:minor)
- [ ] 文件路径正确
- [ ] Direct IO 标识正确
- [ ] 数值精度合理

---

### 阶段 3 总结检查清单

- [ ] 所有测试场景通过
- [ ] 在 3 个内核版本上验证
- [ ] 在 2 种文件系统上验证
- [ ] 边界条件处理正确
- [ ] 性能满足要求
- [ ] 输出格式美观正确
- [ ] 无内存泄漏
- [ ] 无崩溃或死锁

**预计耗时**: 4-5 小时

---

## 📊 进度跟踪

### 总体进度

- [ ] 阶段 1: BPF 端开发 (0/10 任务完成)
- [ ] 阶段 2: 用户态开发 (0/16 任务完成)
- [ ] 阶段 3: 测试和验证 (0/8 任务完成)

### 预计工作量总结

| 阶段 | 任务数 | 代码行数 | 预计耗时 |
|------|--------|---------|---------|
| 阶段 1: BPF 端 | 10 | ~550 行 | 3-4 小时 |
| 阶段 2: 用户态 | 16 | ~820 行 | 4-5 小时 |
| 阶段 3: 测试 | 8 | - | 4-5 小时 |
| **总计** | **34** | **~1370 行** | **11-14 小时** |

---

## 🎯 快速开始指南

### 开发环境准备

```bash
# 1. 安装依赖
sudo apt install -y clang llvm libbpf-dev bpftool

# 2. 准备 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 3. 创建工作目录
cd /Users/user/C/ebpf/libbbbbb/examples/c/
```

### 从哪里开始

**第一步**: 任务 1.1 - 创建 iotrace.bpf.c 基础框架

```bash
# 创建文件
touch iotrace.bpf.c

# 添加头文件和 license
# 参考设计文档或任务清单
```

**第二步**: 按顺序完成阶段 1 的任务 1.1 → 1.10

**第三步**: 编译测试 BPF 程序

**第四步**: 开始阶段 2，创建 iotrace.c

---

## 📝 注意事项

1. **代码风格**: 遵循 Linux 内核代码风格
2. **错误处理**: 每个系统调用都要检查返回值
3. **资源释放**: 及时释放 fd、内存等资源
4. **调试技巧**: 
   - 使用 `bpf_printk()` 在 BPF 端调试
   - 使用 `cat /sys/kernel/debug/tracing/trace_pipe` 查看输出
5. **版本兼容**: 始终使用 `bpf_core_field_exists()` 检查字段

---

**文档版本**: v1.0  
**创建时间**: 2025-01-08  
**维护者**: AI Assistant

