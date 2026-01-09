# iotrace 实现详解 (6/6): 用户态数据处理与输出

## 目录
1. [用户态程序架构](#用户态程序架构)
2. [BPF 程序加载与附加](#bpf-程序加载与附加)
3. [Map 数据读取](#map-数据读取)
4. [数据聚合与排序](#数据聚合与排序)
5. [输出格式化](#输出格式化)
6. [完整流程示例](#完整流程示例)

---

## 1. 用户态程序架构

### 1.1 整体流程

```
main()
  │
  ├─ 1. 解析命令行参数
  │   ├─ 追踪时长 (-d)
  │   ├─ 最大进程数 (-t)
  │   ├─ 每进程最大文件数 (-f)
  │   └─ 设备过滤 (-D)
  │
  ├─ 2. 设置信号处理 (Ctrl-C)
  │
  ├─ 3. 加载 BPF skeleton
  │   ├─ 检查 BTF 路径 (/plux/btf/kernel.btf)
  │   └─ 设置设备过滤 (rodata)
  │
  ├─ 4. 动态附加 BPF 程序
  │   ├─ 块设备层: rq_qos_issue/done
  │   ├─ 文件系统层: ext4/xfs file_read/write_iter
  │   └─ 页缓存层: filemap_fault, page_mkwrite
  │
  ├─ 5. 等待追踪时长
  │   └─ sleep(duration)
  │
  ├─ 6. 读取 io_source_map
  │   ├─ 遍历所有 key-value 对
  │   └─ 按进程聚合数据
  │
  ├─ 7. 排序并输出
  │   ├─ 按 disk_io 排序
  │   ├─ 打印进程级汇总
  │   └─ 打印文件级详情
  │
  └─ 8. 清理资源
      └─ iotrace_bpf__destroy(skel)
```

### 1.2 关键数据结构

```c
// 配置
struct config {
    uint64_t duration;              // 追踪时长（秒）
    uint32_t max_processes;         // 最大进程数
    uint32_t max_files_per_process; // 每进程最大文件数
    char device_str[256];           // 设备过滤字符串 (如 "8:0,253:0")
    uint32_t devices[16];           // 解析后的设备号数组
    uint32_t device_count;          // 设备数量
};

// 进程聚合数据
struct process_data {
    uint32_t pid;           // 进程 PID
    char comm[256];         // 完整命令行
    uint64_t fs_read;       // 文件系统读取字节
    uint64_t fs_write;      // 文件系统写入字节
    uint64_t disk_read;     // 磁盘读取字节
    uint64_t disk_write;    // 磁盘写入字节
    uint64_t file_count;    // 文件数量
};
```

---

## 2. BPF 程序加载与附加

### 2.1 BTF 路径处理

```c
// iotrace.c (line 611-619)

const char *btf_path = "/plux/btf/kernel.btf";

if (access(btf_path, R_OK) == 0) {
    // 自定义 BTF 存在，使用它
    fprintf(stderr, "Found custom BTF at %s, using it.\n", btf_path);
    LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
    skel = iotrace_bpf__open_opts(&opts);
} else {
    // 自定义 BTF 不存在，让 libbpf 自动查找
    fprintf(stderr, "Custom BTF not found at %s. Letting libbpf find one automatically.\n", btf_path);
    skel = iotrace_bpf__open();
}
```

**BTF 查找顺序** (自动模式):
1. `/sys/kernel/btf/vmlinux` (内核自带)
2. `/boot/vmlinux-$(uname -r)` (发行版提供)
3. 嵌入在 BPF 程序中的 BTF

**为什么需要自定义 BTF？**
- 某些嵌入式系统没有 `/sys/kernel/btf/vmlinux`
- 内核编译时未启用 `CONFIG_DEBUG_INFO_BTF`
- 使用预编译的 BTF 文件（跨机器部署）

### 2.2 设备过滤配置

```c
// iotrace.c (line 627-637)

if (cfg.device_count > 0) {
    fprintf(stderr, "Setting device filter: ");
    for (uint32_t i = 0; i < cfg.device_count; i++) {
        char dev_str[16];
        format_device(cfg.devices[i], dev_str, sizeof(dev_str));
        fprintf(stderr, "%s ", dev_str);
        
        // 写入 BPF rodata (只读数据段)
        skel->rodata->FILTER_DEVS[i] = cfg.devices[i];
    }
    fprintf(stderr, "\n");
    skel->rodata->FILTER_DEV_COUNT = cfg.device_count;
}
```

**rodata 机制**:
```c
// BPF 端定义 (iotrace.bpf.c):
volatile const __u32 FILTER_DEVS[16] = {};
volatile const __u32 FILTER_DEV_COUNT = 0;

// 用户态访问:
skel->rodata->FILTER_DEVS[0] = 0x00800000;  // 8:0 (sda)
skel->rodata->FILTER_DEV_COUNT = 1;
```

**关键点**:
- `rodata` 在 `load` 之前设置，`load` 之后**不可修改**
- `volatile const` 防止编译器优化

### 2.3 动态附加 BPF 程序

```c
// iotrace.c (line 417-516)

static int attach_bpf_programs(struct iotrace_bpf *skel)
{
    struct bpf_link *link;
    
    // 1. 块设备层
    bool has_rq_qos_issue = check_kprobe_exists("rq_qos_issue");
    bool has___rq_qos_issue = check_kprobe_exists("__rq_qos_issue");
    
    const char *issue_symbol = NULL;
    const char *done_symbol = NULL;
    
    if (has_rq_qos_issue) {
        issue_symbol = "rq_qos_issue";
        done_symbol = "rq_qos_done";
    } else if (has___rq_qos_issue) {
        issue_symbol = "__rq_qos_issue";
        done_symbol = "__rq_qos_done";
    } else {
        fprintf(stderr, "Neither rq_qos_issue nor __rq_qos_issue found\n");
        return -ENOENT;
    }
    
    // 附加 issue
    link = bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_issue, false, issue_symbol);
    if (!link) {
        fprintf(stderr, "Failed to attach %s\n", issue_symbol);
        return -1;
    }
    
    // 附加 done
    link = bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_done, false, done_symbol);
    if (!link) {
        fprintf(stderr, "Failed to attach %s\n", done_symbol);
        return -1;
    }
    
    // 2. 文件系统层 (ext4)
    if (is_fs_supported("ext4")) {
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, false, "ext4_file_read_iter");
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_write_iter, false, "ext4_file_write_iter");
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_filemap_page_mkwrite, false, "ext4_page_mkwrite");
    }
    
    // 3. 文件系统层 (xfs)
    if (is_fs_supported("xfs")) {
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, false, "xfs_file_read_iter");
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_write_iter, false, "xfs_file_write_iter");
        bpf_program__attach_kprobe(skel->progs.bpf_anyfs_filemap_page_mkwrite, false, "xfs_filemap_page_mkwrite");
    }
    
    // 4. 页缓存层
    bpf_program__attach_kprobe(skel->progs.bpf_filemap_fault, false, "filemap_fault");
    
    return 0;
}
```

**check_kprobe_exists 实现**:
```c
static bool check_kprobe_exists(const char *func_name)
{
    FILE *f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
    if (!f)
        return false;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // 去除空格和换行
        char *space = strchr(line, ' ');
        if (space)
            *space = '\0';
        char *newline = strchr(line, '\n');
        if (newline)
            *newline = '\0';
        
        if (strcmp(line, func_name) == 0) {
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}
```

---

## 3. Map 数据读取

### 3.1 遍历 BPF Map

```c
// iotrace.c (line 663-722)

// 获取 map 的文件描述符
int map_fd = bpf_map__fd(skel->maps.io_source_map);

// 准备迭代变量
struct io_data data;
uint32_t key_pid, key_dev;
uint64_t key_inode;
int key_size = sizeof(key_pid) + sizeof(key_dev) + sizeof(key_inode);
uint8_t key[key_size];
uint8_t next_key[key_size];
bool first = true;

// 遍历 map
while (true) {
    int ret;
    if (first) {
        // 第一次迭代: 传入 NULL 获取第一个 key
        ret = bpf_map_get_next_key(map_fd, NULL, next_key);
        first = false;
    } else {
        // 后续迭代: 传入当前 key 获取下一个 key
        ret = bpf_map_get_next_key(map_fd, key, next_key);
    }
    
    if (ret != 0)
        break;  // 没有更多 key 了
    
    memcpy(key, next_key, key_size);
    
    // 读取 value
    if (bpf_map_lookup_elem(map_fd, key, &data) != 0)
        continue;  // 读取失败，跳过
    
    // 处理数据...
}
```

**关键点**:
- `bpf_map_get_next_key()`: 遍历 map 的唯一方法（hash map 无序）
- 第一次调用传 `NULL`，后续传当前 key
- 返回 -1 表示没有更多 key

### 3.2 数据聚合到进程级别

```c
struct process_data processes[1024] = {0};
int process_count = 0;

while (true) {
    // ... 读取 io_data ...
    
    // 查找对应的进程
    int proc_idx = -1;
    for (int i = 0; i < process_count; i++) {
        if (processes[i].pid == data.pid) {
            proc_idx = i;
            break;
        }
    }
    
    // 进程不存在? 创建新条目
    if (proc_idx == -1) {
        if (process_count >= 1024)
            continue;  // 进程数量超限，跳过
        
        proc_idx = process_count++;
        processes[proc_idx].pid = data.pid;
        
        // 获取完整命令行
        if (!get_proc_cmdline(data.pid, processes[proc_idx].comm, sizeof(processes[proc_idx].comm))) {
            strncpy(processes[proc_idx].comm, data.comm, sizeof(processes[proc_idx].comm) - 1);
        }
    }
    
    // 聚合数据
    processes[proc_idx].fs_read += data.fs_read_bytes;
    processes[proc_idx].fs_write += data.fs_write_bytes;
    processes[proc_idx].disk_read += data.block_read_bytes;
    processes[proc_idx].disk_write += data.block_write_bytes;
    processes[proc_idx].file_count++;
}
```

### 3.3 读取进程完整命令行

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
    
    // /proc/[pid]/cmdline 用 \0 分隔参数，替换为空格
    for (ssize_t i = 0; i < n - 1; i++) {
        if (buf[i] == '\0')
            buf[i] = ' ';
    }
    
    return true;
}
```

**示例**:
```bash
# /proc/1234/cmdline 内容:
python3\0script.py\0--input\0data.txt\0

# get_proc_cmdline 返回:
python3 script.py --input data.txt
```

---

## 4. 数据聚合与排序

### 4.1 排序函数

```c
// iotrace.c (line 398-410)

static int compare_processes(const void *a, const void *b)
{
    const struct process_data *pa = a;
    const struct process_data *pb = b;
    
    // 按总磁盘 IO (读 + 写) 降序排序
    uint64_t total_a = pa->disk_read + pa->disk_write;
    uint64_t total_b = pb->disk_read + pb->disk_write;
    
    if (total_b > total_a)
        return 1;   // b 更大，放前面
    else if (total_b < total_a)
        return -1;  // a 更大，放前面
    return 0;       // 相等
}

// 使用 qsort 排序
qsort(processes, process_count, sizeof(struct process_data), compare_processes);
```

---

## 5. 输出格式化

### 5.1 进程级汇总表格

```c
static void print_process_summary(struct process_data *processes, int count)
{
    printf("PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES\n");
    printf("======  ===================  ======= ======== ========= ========== =====\n");
    
    for (int i = 0; i < count && i < (int)cfg.max_processes; i++) {
        struct process_data *p = &processes[i];
        
        // 格式化字节数
        char fs_read_str[32], fs_write_str[32];
        char disk_read_str[32], disk_write_str[32];
        
        format_bytes(p->fs_read, fs_read_str, sizeof(fs_read_str));
        format_bytes(p->fs_write, fs_write_str, sizeof(fs_write_str));
        format_bytes(p->disk_read, disk_read_str, sizeof(disk_read_str));
        format_bytes(p->disk_write, disk_write_str, sizeof(disk_write_str));
        
        // 截断或填充命令行
        char comm[21];
        if (strlen(p->comm) > 20) {
            snprintf(comm, sizeof(comm), "%.17s...", p->comm);
        } else {
            snprintf(comm, sizeof(comm), "%-20s", p->comm);
        }
        
        printf("%-6u  %s %7s %8s %9s %10s %5lu\n",
               p->pid, comm,
               fs_read_str, fs_write_str,
               disk_read_str, disk_write_str,
               p->file_count);
    }
    printf("\n");
}
```

**输出示例**:
```
PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES
======  ===================  ======= ======== ========= ========== =====
1234    python3 script.py    10MB    5MB      8MB       4MB        3
5678    gcc main.c           2MB     0B       1MB       0B         5
```

### 5.2 字节数格式化

```c
static void format_bytes(uint64_t bytes, char *buf, size_t size)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int i = 0;
    double value = (double)bytes;
    
    // 循环除以 1024，直到 < 1024
    while (value >= 1024 && i < 5) {
        value /= 1024;
        i++;
    }
    
    // 小数点精度: 小于 10 显示 1 位小数，否则不显示
    if (value < 10 && i > 0)
        snprintf(buf, size, "%.1f%s", value, units[i]);
    else
        snprintf(buf, size, "%.0f%s", value, units[i]);
}
```

**示例**:
```
format_bytes(1024)       → "1.0KB"
format_bytes(1536)       → "1.5KB"
format_bytes(10240)      → "10KB"
format_bytes(1048576)    → "1.0MB"
format_bytes(1073741824) → "1.0GB"
```

### 5.3 文件级详情输出

```c
static void print_file_details(int map_fd, struct process_data *processes, int count, uint64_t duration)
{
    for (int i = 0; i < count && i < (int)cfg.max_processes; i++) {
        struct process_data *p = &processes[i];
        
        // 进程头部
        printf("===========================================================================\n");
        printf("PID: %-6u  TOTAL_IO: R=%s W=%s  FILES: %lu\n",
               p->pid, total_read, total_write, p->file_count);
        printf("COMMAND: %s\n", cmdline);
        printf("-----------------------------------\n");
        printf("DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE\n");
        
        // 再次遍历 map，找到属于这个进程的文件
        struct io_data data;
        uint8_t key[key_size];
        uint8_t next_key[key_size];
        bool first = true;
        int file_count = 0;
        
        while (file_count < (int)cfg.max_files_per_process) {
            // 遍历 map (同前面的逻辑)
            // ...
            
            // 只处理当前进程的文件
            if (data.pid != p->pid)
                continue;
            
            file_count++;
            
            // 计算速率 (字节/秒)
            uint64_t fs_read = data.fs_read_bytes / duration;
            uint64_t fs_write = data.fs_write_bytes / duration;
            uint64_t disk_read = data.block_read_bytes / duration;
            uint64_t disk_write = data.block_write_bytes / duration;
            
            // 计算延迟 (纳秒 → 微秒)
            uint64_t q2c_avg = 0, q2c_max = 0, d2c_avg = 0, d2c_max = 0;
            if (data.latency.cnt > 0) {
                q2c_avg = data.latency.sum_q2c / data.latency.cnt / 1000;
                d2c_avg = data.latency.sum_d2c / data.latency.cnt / 1000;
                q2c_max = data.latency.max_q2c / 1000;
                d2c_max = data.latency.max_d2c / 1000;
            }
            
            // 构建文件路径
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/%s/%s/%s",
                     data.d3name, data.d2name, data.d1name, data.filename);
            
            // 添加 Direct IO 标志
            if (data.flag & 0x4)
                strcat(filepath, " [direct IO]");
            
            // 格式化设备号
            char dev_str[16];
            format_device(data.dev, dev_str, sizeof(dev_str));
            
            // 打印文件行
            printf("%-7s %7s %8s %9s %9s   q2c=%lu(max %lu) d2c=%lu(max %lu)  %s\n",
                   dev_str, fs_r, fs_w, disk_r, disk_w,
                   q2c_avg, q2c_max, d2c_avg, d2c_max,
                   filepath);
        }
        printf("\n");
    }
}
```

**输出示例**:
```
===========================================================================
PID: 1234    TOTAL_IO: R=10MB W=5MB  FILES: 3
COMMAND: python3 /path/to/script.py --input data.txt
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     5MB     2MB      4MB       1MB          q2c=150(max 500) d2c=120(max 450)  data/input.txt
8:0     3MB     2MB      2MB       2MB          q2c=200(max 800) d2c=180(max 750)  data/output.txt
8:0     2MB     1MB      2MB       1MB          q2c=100(max 300) d2c=80(max 250)   logs/app.log
```

### 5.4 设备号格式化

```c
static void format_device(uint32_t dev, char *buf, size_t size)
{
    // 提取 major 和 minor
    unsigned int major = (dev >> 20) & 0xfff;
    unsigned int minor = dev & 0xfffff;
    snprintf(buf, size, "%u:%u", major, minor);
}
```

**示例**:
```
dev = 0x00800000  → "8:0" (sda)
dev = 0x00800001  → "8:1" (sda1)
dev = 0x0fd00000  → "253:0" (dm-0)
```

---

## 6. 完整流程示例

### 6.1 运行示例

```bash
$ sudo ./iotrace -d 5 -t 3 -f 3 -D 8:0

# 输出:
Found custom BTF at /plux/btf/kernel.btf, using it.
Setting device filter: 8:0
Attaching to rq_qos_issue...
Attaching to rq_qos_done...
Attaching ext4 file IO hooks...
Attaching filemap_fault...
Tracing IO for 5 seconds... Hit Ctrl-C to stop.

============= IO Tracing Report (Duration: 5s) =============

PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES
======  ===================  ======= ======== ========= ========== =====
1234    python3 script.py    10MB    5MB      8MB       4MB        3
5678    gcc main.c           2MB     0B       1MB       0B         5
9012    mysqld               50MB    30MB     45MB      28MB       10

===========================================================================
PID: 1234    TOTAL_IO: R=10MB W=5MB  FILES: 3
COMMAND: python3 /home/user/script.py --input data.txt
-----------------------------------
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     5MB     2MB      4MB       1MB          q2c=150(max 500) d2c=120(max 450)  home/user/data/input.txt
8:0     3MB     2MB      2MB       2MB          q2c=200(max 800) d2c=180(max 750)  home/user/data/output.txt
8:0     2MB     1MB      2MB       1MB          q2c=100(max 300) d2c=80(max 250)   var/log/app.log

...
```

### 6.2 数据解读

#### 示例 1: 页缓存命中率高

```
PID: 1234
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     10MB    0B       2MB       0B           q2c=100 d2c=80   data/cache_test.txt

解读:
- 文件系统层读取 10MB (应用请求)
- 块设备层只读取 2MB (页缓存命中 80%)
- 延迟较低 (100μs)，说明大部分来自内存
```

#### 示例 2: Direct IO

```
PID: 5678
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     100MB   0B       100MB     0B           q2c=5000 d2c=4800  data/db.bin [direct IO]

解读:
- 文件系统层 = 块设备层 (100MB)，说明没有页缓存
- 延迟高 (5ms)，说明每次都访问磁盘
- 标记 [direct IO]，确认绕过页缓存
```

#### 示例 3: 写入合并

```
PID: 9012
DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE
8:0     0B      50MB     0B        10MB         q2c=200 d2c=180   var/log/app.log

解读:
- 文件系统层写入 50MB (应用层)
- 块设备层只写入 10MB (写入合并/压缩)
- 延迟适中 (200μs)，说明有缓冲
```

---

## 7. 错误处理与调试

### 7.1 常见错误

#### 错误 1: BTF 加载失败

```
Failed to load BPF skeleton: -2
```

**解决方案**:
```bash
# 检查 BTF 是否存在
ls -l /sys/kernel/btf/vmlinux

# 如果不存在，生成自定义 BTF
bpftool btf dump file /boot/vmlinux-$(uname -r) format raw > /plux/btf/kernel.btf
```

#### 错误 2: 权限不足

```
Failed to attach rq_qos_issue
```

**解决方案**:
```bash
# 需要 root 权限
sudo ./iotrace

# 或者设置 CAP_BPF (Linux 5.8+)
sudo setcap cap_bpf,cap_perfmon=ep ./iotrace
```

#### 错误 3: Map 满了

**表现**: 某些文件的 IO 未被统计

**解决方案**: 增大 map 大小
```c
// iotrace.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);  // 512 → 1024
    // ...
} io_source_map SEC(".maps");
```

### 7.2 调试技巧

#### 技巧 1: 查看 BPF 程序是否加载成功

```bash
# 列出所有 BPF 程序
sudo bpftool prog list | grep iotrace

# 输出:
123: kprobe  name bpf_rq_qos_issue  tag 1234567890abcdef
124: kprobe  name bpf_rq_qos_done   tag abcdef1234567890
```

#### 技巧 2: 查看 Map 内容

```bash
# 列出所有 BPF map
sudo bpftool map list | grep io_source_map

# 输出:
45: hash  name io_source_map  flags 0x0
        key 16B  value 272B  max_entries 512  memlock 143360B

# 导出 map 内容
sudo bpftool map dump id 45
```

---

## 总结

至此，iotrace 的六个主要部分全部讲解完毕：

1. ✅ **架构与数据流**: 理解三层追踪的设计思想
2. ✅ **内核版本兼容**: 掌握 BPF CO-RE 的使用方法
3. ✅ **块设备层**: 学会追踪物理 IO 和计算延迟
4. ✅ **文件系统层**: 理解文件路径提取和 Direct IO 检测
5. ✅ **页缓存层**: 掌握 mmap 方式的 IO 追踪
6. ✅ **用户态处理**: 学会数据聚合和报告生成

**核心要点回顾**:
- 📌 分层追踪 (文件系统 + 页缓存 + 块设备)
- 📌 BPF CO-RE 实现跨内核兼容
- 📌 动态附加支持多种文件系统
- 📌 两个 Map 配合 (临时匹配 + 最终统计)
- 📌 tgid 判断机制保证正确的进程上下文

**进一步学习**:
- 阅读 HUATUO 项目源码: https://github.com/ccfos/huatuo
- 学习 libbpf 官方文档: https://libbpf.readthedocs.io/
- 研究 Linux 内核 IO 栈: https://www.kernel.org/doc/html/latest/block/

---

Happy BPF Hacking! 🎉


