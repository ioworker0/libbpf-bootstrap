# iotrace 测试脚本

本文档提供了在 Linux 环境下测试 `iotrace` 的详细步骤和测试脚本。

## 测试环境要求

- Linux 内核 5.4+ (推荐 5.15+)
- Root 权限
- 已编译的 `iotrace` 可执行文件

## 阶段 3.1: 编译测试

```bash
cd /path/to/libbbbbb/examples/c
make clean
make iotrace

# 验证编译成功
ls -lh iotrace iotrace.bpf.o
file iotrace
```

## 阶段 3.2: 基础功能测试

### 测试 3.2.1: 默认参数运行

```bash
sudo ./iotrace
# 预期：运行 8 秒后输出 IO 统计
```

### 测试 3.2.2: 自定义持续时间

```bash
sudo ./iotrace -d 5
# 预期：运行 5 秒后输出 IO 统计
```

### 测试 3.2.3: 限制进程数量

```bash
sudo ./iotrace -t 3
# 预期：最多显示 3 个进程
```

### 测试 3.2.4: 限制文件数量

```bash
sudo ./iotrace -f 2
# 预期：每个进程最多显示 2 个文件
```

### 测试 3.2.5: 帮助信息

```bash
./iotrace -h
# 预期：显示完整的帮助信息
```

## 阶段 3.3: IO 负载测试

### 测试 3.3.1: DD 顺序写测试

**终端 1：启动 iotrace**
```bash
sudo ./iotrace -d 10 -t 5
```

**终端 2：生成 DD 写负载**
```bash
# 创建测试目录
mkdir -p /tmp/iotest
cd /tmp/iotest

# 顺序写 1GB 数据
dd if=/dev/zero of=testfile bs=1M count=1024 oflag=direct

# 验证文件
ls -lh testfile

# 清理
rm -f testfile
```

**预期输出**：
- 应该能看到 `dd` 进程
- `DISK_WRITE` 列显示约 128MB/s (1GB / 8s)
- 文件显示为 `testfile [direct IO]`

### 测试 3.3.2: DD 顺序读测试

**终端 1：启动 iotrace**
```bash
sudo ./iotrace -d 10
```

**终端 2：生成 DD 读负载**
```bash
cd /tmp/iotest

# 创建测试文件（1GB）
dd if=/dev/zero of=testfile bs=1M count=1024

# 清理缓存
sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"

# 顺序读
dd if=testfile of=/dev/null bs=1M iflag=direct

# 清理
rm -f testfile
```

**预期输出**：
- 应该能看到 `dd` 进程
- `DISK_READ` 列显示读取速率
- 延迟统计 `q2c` 和 `d2c` 应该有合理值

### 测试 3.3.3: FIO 混合读写测试

**终端 1：启动 iotrace**
```bash
sudo ./iotrace -d 20 -t 10 -f 10
```

**终端 2：FIO 测试**
```bash
# 安装 fio (如果未安装)
# Ubuntu/Debian: sudo apt install fio
# RHEL/CentOS: sudo yum install fio

cd /tmp/iotest

# 创建 FIO 配置文件
cat > fio_test.ini << 'EOF'
[global]
ioengine=libaio
direct=1
bs=4k
size=100M
numjobs=4
runtime=15
time_based
group_reporting

[randread]
rw=randread
directory=/tmp/iotest

[randwrite]
rw=randwrite
directory=/tmp/iotest
EOF

# 运行 FIO
fio fio_test.ini

# 清理
rm -f fio_test.ini
rm -f randread.* randwrite.*
```

**预期输出**：
- 应该能看到多个 `fio` 进程（numjobs=4）
- 同时显示读和写操作
- 延迟统计 `q2c` 和 `d2c` 应该反映随机 IO 特性（高延迟）

## 阶段 3.4: 设备过滤测试

### 测试 3.4.1: 获取设备号

```bash
# 查看当前系统的块设备
lsblk -o NAME,MAJ:MIN,SIZE,MOUNTPOINT

# 或使用 df
df -h | head -5

# 示例输出：
# NAME   MAJ:MIN   SIZE MOUNTPOINT
# sda      8:0    100G
# ├─sda1   8:1     99G /
# └─sda2   8:2      1G [SWAP]
```

### 测试 3.4.2: 单设备过滤

```bash
# 假设要过滤 sda (8:0)
sudo ./iotrace -D 8:0 -d 10

# 在另一个终端生成 IO
dd if=/dev/zero of=/tmp/test bs=1M count=500 oflag=direct
rm -f /tmp/test
```

**预期输出**：
- 只显示设备 `8:0` 的 IO
- DEVICE 列应该只显示 `8:0`

### 测试 3.4.3: 多设备过滤

```bash
# 假设要过滤 sda (8:0) 和 sdb (8:16)
sudo ./iotrace -D 8:0,8:16 -d 10

# 在两个设备上生成 IO
dd if=/dev/zero of=/tmp/test1 bs=1M count=500 oflag=direct &
dd if=/dev/zero of=/mnt/sdb/test2 bs=1M count=500 oflag=direct &
wait

rm -f /tmp/test1 /mnt/sdb/test2
```

**预期输出**：
- 显示两个设备的 IO
- DEVICE 列应该包含 `8:0` 和 `8:16`

## 阶段 3.5: 文件系统兼容性测试

### 测试 3.5.1: ext4 文件系统

```bash
# 创建 ext4 文件系统（如果需要）
sudo dd if=/dev/zero of=/tmp/ext4.img bs=1M count=1024
sudo mkfs.ext4 /tmp/ext4.img
sudo mkdir -p /mnt/ext4
sudo mount /tmp/ext4.img /mnt/ext4

# 启动 iotrace
sudo ./iotrace -d 10 &

# 生成 IO
dd if=/dev/zero of=/mnt/ext4/testfile bs=1M count=500 oflag=direct
rm -f /mnt/ext4/testfile

# 等待 iotrace 完成
wait

# 清理
sudo umount /mnt/ext4
sudo rm -f /tmp/ext4.img
```

**预期输出**：
- 能看到 ext4 文件系统的 IO
- 日志显示 "Attaching ext4 file IO hooks..."

### 测试 3.5.2: xfs 文件系统

```bash
# 创建 xfs 文件系统（如果需要）
sudo dd if=/dev/zero of=/tmp/xfs.img bs=1M count=1024
sudo mkfs.xfs /tmp/xfs.img
sudo mkdir -p /mnt/xfs
sudo mount /tmp/xfs.img /mnt/xfs

# 启动 iotrace
sudo ./iotrace -d 10 &

# 生成 IO
dd if=/dev/zero of=/mnt/xfs/testfile bs=1M count=500 oflag=direct
rm -f /mnt/xfs/testfile

# 等待 iotrace 完成
wait

# 清理
sudo umount /mnt/xfs
sudo rm -f /tmp/xfs.img
```

**预期输出**：
- 能看到 xfs 文件系统的 IO
- 日志显示 "Attaching xfs file IO hooks..."

## 阶段 3.6: 边界条件测试

### 测试 3.6.1: 无 IO 负载

```bash
sudo ./iotrace -d 5
# 预期：正常退出，可能没有或只有少量系统 IO
```

### 测试 3.6.2: 高并发 IO

```bash
sudo ./iotrace -d 15 -t 20 -f 20 &

# 启动 20 个并发 DD 进程
for i in {1..20}; do
    dd if=/dev/zero of=/tmp/test_$i bs=1M count=200 oflag=direct &
done

wait

# 清理
rm -f /tmp/test_*
```

**预期输出**：
- 显示最多 20 个进程
- 每个进程最多 20 个文件
- 无崩溃或数据丢失

### 测试 3.6.3: Ctrl-C 中断

```bash
sudo ./iotrace -d 60 &
PID=$!

# 生成一些 IO
dd if=/dev/zero of=/tmp/test bs=1M count=100 oflag=direct &

# 5 秒后中断
sleep 5
sudo kill -INT $PID

wait

# 清理
rm -f /tmp/test
```

**预期输出**：
- 工具立即响应 SIGINT
- 输出当前已收集的数据
- 优雅退出

### 测试 3.6.4: 长时间运行

```bash
sudo ./iotrace -d 300  # 5 分钟

# 在另一个终端持续生成 IO
for i in {1..50}; do
    dd if=/dev/zero of=/tmp/test bs=1M count=100 oflag=direct
    rm -f /tmp/test
    sleep 5
done
```

**预期输出**：
- 工具稳定运行 5 分钟
- 无内存泄漏或性能下降

### 测试 3.6.5: 无效设备过滤

```bash
sudo ./iotrace -D 999:999 -d 5
# 预期：正常运行，但可能没有匹配的 IO
```

### 测试 3.6.6: 无效命令行参数

```bash
./iotrace -d abc
# 预期：错误提示 "Invalid duration"

./iotrace -D invalid
# 预期：错误提示 "Invalid device format"

./iotrace --unknown
# 预期：显示帮助信息
```

### 测试 3.6.7: Direct IO vs Buffered IO

**终端 1：启动 iotrace**
```bash
sudo ./iotrace -d 20
```

**终端 2：测试 Direct IO**
```bash
# Direct IO
dd if=/dev/zero of=/tmp/direct_io bs=1M count=500 oflag=direct
```

**终端 3：测试 Buffered IO**
```bash
# Buffered IO (无 oflag=direct)
dd if=/dev/zero of=/tmp/buffered_io bs=1M count=500
sync  # 确保写入磁盘
```

**预期输出**：
- Direct IO 文件应该标记 `[direct IO]`
- Buffered IO 文件不应该有标记
- 两者的延迟特性应该不同

### 测试 3.6.8: 进程退出后的 cmdline 读取

```bash
sudo ./iotrace -d 10 &

# 启动一个短生命周期进程
dd if=/dev/zero of=/tmp/test bs=1M count=100 oflag=direct
rm -f /tmp/test

# 等待 iotrace 完成
wait
```

**预期输出**：
- 即使进程已退出，应该能显示进程名
- 如果无法读取 cmdline，应该回退到 comm

## 阶段 3.7: 内核版本兼容性测试

### 测试环境准备

需要在以下内核版本上分别测试：

1. **Linux 5.4.x** (LTS)
2. **Linux 5.15.x** (LTS)
3. **Linux 6.1.x 或 6.8.x** (最新 LTS)

### 测试步骤

在每个内核版本上执行以下命令：

```bash
# 检查内核版本
uname -r

# 检查 BTF 支持
ls -lh /sys/kernel/btf/vmlinux

# 编译测试
cd /path/to/libbbbbb/examples/c
make clean
make iotrace

# 运行基础测试
sudo ./iotrace -d 5

# 生成 IO 负载
dd if=/dev/zero of=/tmp/test bs=1M count=500 oflag=direct
rm -f /tmp/test
```

**预期输出**：
- 所有内核版本都能成功编译
- 所有内核版本都能正常运行
- BPF 程序能够正确加载和附加
- 输出数据格式一致

### 内核兼容性检查点

1. **request 结构字段**:
   ```bash
   # 检查日志中是否有 "get_request_disk" 相关的错误
   sudo ./iotrace -d 5 2>&1 | grep -i disk
   ```

2. **iov_iter 结构**:
   ```bash
   # 检查是否能正确读取文件 IO 大小
   sudo ./iotrace -d 10 &
   dd if=/dev/zero of=/tmp/test bs=1M count=100
   rm -f /tmp/test
   wait
   # 输出应该显示正确的字节数（约 100MB）
   ```

3. **rq_qos 函数**:
   ```bash
   # 检查日志中挂载了哪个函数
   sudo ./iotrace -d 5 2>&1 | grep rq_qos
   # 应该看到 "Attaching to rq_qos_issue" 或 "__rq_qos_issue"
   ```

## 阶段 3.8: 性能测试

### 测试 3.8.1: 系统开销测试

```bash
# 不运行 iotrace 的基线测试
time dd if=/dev/zero of=/tmp/baseline bs=1M count=2048 oflag=direct
rm -f /tmp/baseline

# 运行 iotrace 的测试
sudo ./iotrace -d 20 &
time dd if=/dev/zero of=/tmp/with_iotrace bs=1M count=2048 oflag=direct
rm -f /tmp/with_iotrace
wait
```

**预期结果**：
- 性能差异应该 < 5%
- 无明显的吞吐量下降

### 测试 3.8.2: 内存占用测试

```bash
# 启动 iotrace
sudo ./iotrace -d 60 &
PID=$!

# 记录初始内存
ps -o pid,vsz,rss,cmd -p $PID

# 生成大量 IO
for i in {1..100}; do
    dd if=/dev/zero of=/tmp/test_$i bs=1M count=50 oflag=direct &
done
wait

# 再次检查内存
ps -o pid,vsz,rss,cmd -p $PID

# 清理
sudo kill -INT $PID
rm -f /tmp/test_*
```

**预期结果**：
- RSS (常驻内存) 应该 < 20MB
- 内存增长应该稳定，无明显泄漏

## 测试总结模板

```
==============================================
iotrace 测试报告
==============================================

测试日期: _______________
测试人员: _______________
内核版本: _______________
工具版本: _______________

阶段 3.1: 编译测试
[ ] 通过  [ ] 失败
备注: ___________________________________

阶段 3.2: 基础功能测试 (5个测试)
[ ] 通过  [ ] 失败
失败项: _________________________________

阶段 3.3: IO 负载测试 (3个测试)
[ ] 通过  [ ] 失败
失败项: _________________________________

阶段 3.4: 设备过滤测试 (3个测试)
[ ] 通过  [ ] 失败
失败项: _________________________________

阶段 3.5: 文件系统兼容性测试 (2个测试)
[ ] 通过  [ ] 失败
失败项: _________________________________

阶段 3.6: 边界条件测试 (8个测试)
[ ] 通过  [ ] 失败
失败项: _________________________________

阶段 3.7: 内核版本兼容性测试 (3个内核)
5.4.x:   [ ] 通过  [ ] 失败
5.15.x:  [ ] 通过  [ ] 失败
6.x:     [ ] 通过  [ ] 失败

阶段 3.8: 性能测试 (2个测试)
[ ] 通过  [ ] 失败
性能开销: ______%
内存占用: ______MB

总体评价: [ ] 通过所有测试  [ ] 部分通过  [ ] 失败

备注:
_____________________________________________
_____________________________________________
_____________________________________________
==============================================
```

## 故障排查清单

如果测试失败，请检查：

1. **编译失败**:
   - [ ] 检查 Clang/LLVM 版本 (>= 11)
   - [ ] 检查 libbpf 是否安装
   - [ ] 检查内核头文件是否安装

2. **加载失败**:
   - [ ] 检查是否有 root 权限
   - [ ] 检查 BTF 是否可用 (`/sys/kernel/btf/vmlinux`)
   - [ ] 检查 `CONFIG_DEBUG_INFO_BTF=y`

3. **挂载失败**:
   - [ ] 检查 kprobe 是否可用
   - [ ] 检查文件系统是否支持
   - [ ] 查看 dmesg 日志

4. **数据异常**:
   - [ ] 检查设备过滤是否正确
   - [ ] 检查 IO 是否真的发生
   - [ ] 增加追踪时间 (`-d`)

5. **性能问题**:
   - [ ] 减少显示的进程数 (`-t`)
   - [ ] 减少显示的文件数 (`-f`)
   - [ ] 检查系统负载

## 自动化测试脚本

创建 `run_all_tests.sh`:

```bash
#!/bin/bash

set -e

echo "=========================================="
echo "iotrace Automated Test Suite"
echo "=========================================="
echo ""

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

# 创建测试目录
TEST_DIR="/tmp/iotrace_test_$$"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "Test directory: $TEST_DIR"
echo ""

# 测试计数器
PASSED=0
FAILED=0

# 测试函数
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "Running: $test_name ... "
    
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo "PASS"
        ((PASSED++))
    else
        echo "FAIL"
        ((FAILED++))
    fi
}

# 阶段 3.2: 基础功能测试
echo "=== Phase 3.2: Basic Functionality ==="
run_test "Default parameters" "timeout 10 ./iotrace"
run_test "Custom duration" "timeout 7 ./iotrace -d 5"
run_test "Help message" "./iotrace -h"
echo ""

# 阶段 3.3: IO 负载测试
echo "=== Phase 3.3: IO Load Tests ==="
run_test "DD write test" "timeout 12 bash -c './iotrace -d 10 & dd if=/dev/zero of=$TEST_DIR/test bs=1M count=100 oflag=direct; wait'"
run_test "DD read test" "timeout 12 bash -c 'dd if=/dev/zero of=$TEST_DIR/test bs=1M count=100; sync; ./iotrace -d 10 & dd if=$TEST_DIR/test of=/dev/null bs=1M; wait'"
echo ""

# 清理
cd /
rm -rf "$TEST_DIR"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "=========================================="

if [ $FAILED -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
```

使用方法：

```bash
chmod +x run_all_tests.sh
sudo ./run_all_tests.sh
```

