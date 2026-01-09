# iotrace 实现详解系列文档

这是一套完整的技术文档，详细讲解 iotrace 的 BPF 实现原理。

## 📚 文档列表

1. **[01_architecture.md](./01_architecture.md)** - 整体架构与数据流
   - 三层追踪设计思想
   - 数据流转过程
   - 关键数据结构（两个 BPF Map）
   - 设计思想解析

2. **[02_compatibility.md](./02_compatibility.md)** - 内核版本兼容性处理
   - BPF CO-RE 技术详解
   - vmlinux.h 的不完整性问题
   - 结构体定义策略
   - 跨版本兼容实现

3. **[03_block_layer.md](./03_block_layer.md)** - 块设备层追踪
   - rq_qos_issue/done 实现
   - 延迟计算（q2c 和 d2c）
   - 设备号处理
   - Direct IO 识别

4. **[04_filesystem_layer.md](./04_filesystem_layer.md)** - 文件系统层追踪
   - file_read_iter/write_iter 追踪
   - 动态附加机制（ext4/xfs）
   - 文件路径提取
   - Direct IO 检测

5. **[05_pagecache_layer.md](./05_pagecache_layer.md)** - 页缓存层追踪
   - mmap 机制介绍
   - filemap_fault 追踪（mmap 读）
   - page_mkwrite 追踪（mmap 写）
   - 按页统计的原理

6. **[06_userspace.md](./06_userspace.md)** - 用户态数据处理与输出
   - BPF 程序加载与附加
   - Map 数据读取
   - 数据聚合与排序
   - 输出格式化

## 🎯 阅读建议

### 快速入门路径
```
第 1 篇 (架构) → 第 3 篇 (块设备层) → 第 6 篇 (用户态)
```

### 深入学习路径
```
按顺序阅读所有文档：01 → 02 → 03 → 04 → 05 → 06
```

### 特定主题
- **内核兼容性**: 阅读第 2 篇
- **mmap 追踪**: 阅读第 5 篇
- **延迟分析**: 阅读第 3 篇
- **输出定制**: 阅读第 6 篇

## 📖 配套资源

- **源码**: `../iotrace.c` 和 `../iotrace.bpf.c`
- **设计文档**: `../iotrace_design.md`
- **任务列表**: `../iotrace_tasks.md`

## 🔗 参考资料

- **HUATUO 项目**: https://github.com/ccfos/huatuo
- **libbpf 文档**: https://libbpf.readthedocs.io/
- **Linux 内核文档**: https://www.kernel.org/doc/html/latest/

---

**创建日期**: 2026-01-09  
**作者**: AI Assistant  
**版本**: 1.0


