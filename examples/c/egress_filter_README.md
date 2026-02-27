# Egress Filter - 简单的出网管控 eBPF 程序

## 功能

这是一个最简单的 TC eBPF 出网管控程序，用于阻止特定 IP 地址的出网流量。

当前配置：阻止 IP `111.63.65.103` 的出网流量

## 编译

```bash
cd /Users/user/C/ebpf/libbbbbb/examples/c
make egress_filter
```

## BTF 支持

程序会自动处理 BTF (BPF Type Format)：

1. **优先使用自定义 BTF**：`/plux/btf/kernel.btf`（如果存在）
2. **自动查找系统 BTF**：如果自定义 BTF 不存在，libbpf 会自动在以下位置查找：
   - `/sys/kernel/btf/vmlinux`
   - `/boot/vmlinux-$(uname -r)`
   - `/lib/modules/$(uname -r)/vmlinux-$(uname -r)`

如果你的系统没有 BTF 支持，你可以：

```bash
# 检查内核是否有 BTF
ls -lh /sys/kernel/btf/vmlinux

# 如果没有，可以下载预编译的 BTF
# 或者从其他机器拷贝到 /plux/btf/kernel.btf
```

## 使用方法

### 1. 运行程序

```bash
# 需要 root 权限
sudo ./egress_filter <interface_name>

# 例如：
sudo ./egress_filter calife61cb86319
```

### 2. 验证程序已加载

```bash
# 查看 TC filter（应该看到优先级为 1 的 egress_firewall）
tc filter show dev calife61cb86319 egress

# 预期输出：
# filter protocol all pref 1 bpf chain 0 handle 0x1 egress_firewall:[xxx] direct-action
# filter protocol all pref 49151 bpf chain 0 handle 0x1 cali_tc_preambl:[xxx] direct-action
```

### 3. 查看日志

```bash
# 在另一个终端查看 eBPF 程序的日志
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 当阻止流量时会看到：
# <...>-12345 [000] .... 12345.678901: 0: Blocked egress from IP: 111.63.65.103
```

### 4. 测试

```bash
# 进入容器
docker exec -it <container_id> sh

# 尝试访问被阻止的 IP（应该失败）
ping 111.63.65.103
curl http://111.63.65.103

# 尝试访问其他 IP（应该成功）
ping 8.8.8.8
```

### 5. 停止程序

按 `Ctrl+C` 停止程序，它会自动 detach eBPF 程序。

## 工作原理

1. **Hook 点**：TC egress（容器 veth 宿主机侧的出口）
2. **优先级**：1（确保在 Calico 的 49151 之前执行）
3. **匹配规则**：检查源 IP 是否为 `111.63.65.103`
4. **动作**：
   - 匹配：`TC_ACT_SHOT`（丢弃数据包）
   - 不匹配：`TC_ACT_OK`（继续传递给 Calico）

## 执行流程

```
容器发出数据包
    ↓
veth (宿主机侧) TC egress
    ↓
[优先级 1] egress_firewall ← 你的程序（先执行）
    ↓
    如果源 IP = 111.63.65.103 → TC_ACT_SHOT（丢弃）
    否则 → TC_ACT_OK（继续）
    ↓
[优先级 49151] cali_tc_preambl ← Calico（后执行）
    ↓
iptables
    ↓
路由
    ↓
物理网卡
```

## 修改阻止的 IP

编辑 `egress_filter.bpf.c` 文件：

```c
// 修改这一行，改成你要阻止的 IP
#define BLOCKED_IP 0x673F3F6F  // 111.63.65.103

// IP 地址转换：
// 111.63.65.103 → 小端字节序 → 0x673F3F6F
// 
// 计算方法：
// 103 << 0  | 65 << 8  | 63 << 16 | 111 << 24
// = 0x67    | 0x4100   | 0x3F0000 | 0x6F000000
// = 0x6F3F4167 (大端) → 0x673F416F (小端)
//
// 或使用 Python：
// import struct, socket
// struct.unpack('<I', socket.inet_aton('111.63.65.103'))[0]
```

然后重新编译：

```bash
make egress_filter
```

## 注意事项

1. **需要 root 权限**
2. **接口名称**：确保使用正确的容器 veth 接口名（如 `calife61cb86319`）
3. **优先级**：程序使用优先级 1，确保在 Calico 之前执行
4. **与 Calico 共存**：不会影响 Calico 的正常功能
5. **停止程序**：务必使用 Ctrl+C 优雅停止，以便正确 detach 程序

## 故障排查

### 问题：无法加载程序

```bash
# 检查内核是否支持 eBPF
uname -r  # 需要 >= 4.18

# 检查是否有 BTF
ls /sys/kernel/btf/vmlinux
```

### 问题：找不到接口

```bash
# 列出所有容器的 veth 接口
ip link | grep cali

# 或者找到容器的接口
docker inspect <container_id> | grep -i veth
```

### 问题：看不到日志

```bash
# 确保 debugfs 已挂载
mount | grep debugfs

# 如果没有，手动挂载
sudo mount -t debugfs none /sys/kernel/debug
```

## 扩展

如果需要支持多个 IP 或动态配置，可以修改程序使用 BPF Map：

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // IP 地址
    __type(value, __u8);   // 0=允许, 1=阻止
    __uint(max_entries, 10000);
} blocked_ips SEC(".maps");
```

然后在用户态程序中动态更新这个 Map。
