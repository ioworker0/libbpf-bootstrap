// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 IO Tracing Tool

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Constants
#define TASK_COMM_LEN 16
#define DNAME_INLINE_LEN 32
#define PAGE_SIZE 4096

// REQ_OP bits and masks
#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)
#define REQ_OP_READ 0
#define REQ_OP_WRITE 1

// Define __REQ_META if not present in vmlinux.h
// This is needed for filtering metadata requests
#ifndef __REQ_META
enum {
	__REQ_META = 12,  // Metadata request flag
};
#endif

#define REQ_META (1ULL << __REQ_META)

// Device filter configuration (user-space configurable)
// Maximum 16 devices can be filtered
volatile const __u32 FILTER_DEVS[16] = {};
volatile const __u32 FILTER_DEV_COUNT = 0;

// Upgrade threshold: 10MB
volatile const __u64 UPDATE_THRESHOLD = 10ULL * 1024 * 1024;

// Detail statistics map (per-process per-file)
struct io_key_detail {
	__u32 pid;
	__u32 dev;
	__u64 inode;
};

struct io_stat {
	__u64 fs_write_bytes;
	__u64 fs_read_bytes;
	__u64 block_write_bytes;
	__u64 block_read_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 40960);
	__uint(key_size, sizeof(struct io_key_detail));
	__uint(value_size, sizeof(struct io_stat));
} io_detail_map SEC(".maps");

// Check if device should be processed
// Returns 1 if device should be processed, 0 if should be filtered out
static __always_inline int should_process_device(__u32 dev)
{
	if (FILTER_DEV_COUNT == 0)
		return 1;  // No filter, process all devices

	for (int i = 0; i < FILTER_DEV_COUNT && i < 16; i++)
		if (FILTER_DEVS[i] == dev)
			return 1;  // Device in whitelist

	return 0;  // Filter out
}

// Helper function to check if request is a write operation
static __always_inline int is_write_request(__u32 cmd_flags)
{
	return (cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE;
}

// ============================================================================
// Data Structures
// ============================================================================

// Latency statistics
struct latency_info {
	__u64 cnt;       // IO count
	__u64 max_d2c;   // Maximum device-to-complete latency (nanoseconds)
	__u64 sum_d2c;   // Sum of device-to-complete latency
	__u64 max_q2c;   // Maximum queue-to-complete latency (nanoseconds)
	__u64 sum_q2c;   // Sum of queue-to-complete latency
};

// Key for io_source_map: aggregate IO by (pid, dev, inode)
struct io_key {
	__u32 pid;      // Process PID
	__u32 dev;      // Device number
	__u64 inode;    // File inode
};

// Key for start_info_map: match issue and done by (dev, sector)
struct hash_key {
	__u32 dev;       // Device number
	__u32 _pad;
	__u64 sector;    // Sector number (uniquely identifies IO request)
};

// IO start info: saved during issue phase
struct io_start_info {
	__u64 inode;                // File inode
	__u32 pid;                  // Process PID
	__u32 dev;                  // Device number
	__u64 data_len;             // IO data length
	char  comm[TASK_COMM_LEN];  // Process name
};

// IO data statistics: aggregated complete IO information
struct io_data {
	__u32 pid;                      // Process PID
	__u32 tgid;                     // Thread group ID (process group)
	__u32 dev;                      // Device number
	__u32 flag;                     // IOCB flags (for Direct IO detection)
	__u8  upgraded;                 // Whether upgraded to major contributor
	__u8  _pad[3];                  // Padding for alignment
	__u64 fs_write_bytes;           // Filesystem write bytes
	__u64 fs_read_bytes;            // Filesystem read bytes
	__u64 block_write_bytes;        // Block device write bytes
	__u64 block_read_bytes;         // Block device read bytes
	__u64 inode;                    // File inode
	struct latency_info latency;    // Latency statistics
	char comm[TASK_COMM_LEN];       // Process name (16 bytes)
	char cmdline[32];               // Command line (32 bytes, truncated if needed)
	char filename[DNAME_INLINE_LEN]; // File name
	char d1name[DNAME_INLINE_LEN];   // Parent directory name
	char d2name[DNAME_INLINE_LEN];   // Grandparent directory name
	char d3name[DNAME_INLINE_LEN];   // Great-grandparent directory name
};

// ============================================================================
// BPF Maps
// ============================================================================

// IO source map: stores aggregated IO statistics by (pid, dev, inode)
// Maximum 512 entries: ~100 processes × 5 files per process
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(struct io_key));
	__uint(value_size, sizeof(struct io_data));
} io_source_map SEC(".maps");

// Start info map: temporary storage for issue phase info
// Maximum 4096 entries to support high-concurrency IO scenarios
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(struct hash_key));
	__uint(value_size, sizeof(struct io_start_info));
} start_info_map SEC(".maps");

// ============================================================================
// Kernel Version Compatibility Structures and Functions
// ============================================================================

// IMPORTANT: Why do we need to define these structures explicitly?
//
// Reference: HUATUO project (https://github.com/ccfos/huatuo)
// - huatuo's vmlinux_x86.h: https://github.com/ccfos/huatuo/blob/main/bpf/include/vmlinux_x86.h
// - Has COMPLETE definitions for kernel structures (e.g., struct request at lines 11754-11812)
//
// Our vmlinux.h (from libbpf-bootstrap) has MIXED status:
//
// ✅ COMPLETE definitions (can use directly):
//   - struct bio          (line 14013)
//   - struct inode        (line 31489)
//   - struct dentry       (line 23948)
//   - struct kiocb        (line 33287)
//   - struct gendisk      (line 29311)
//   - struct vm_fault     (line 50205)
//   - struct vm_area_struct (line 50179)
//   - struct iov_iter     (line 31907, but OLD kernel has 'type', NEW has 'data_source')
//
// ❌ FORWARD declarations only (MUST define):
//   - struct request      (line 31725: "struct request;")
//   - struct hd_struct    (forward declaration only)
//   - struct request_queue (line 14271: "struct request_queue;")
//   - struct block_device (line 14009: "struct block_device;")
//
// 🔧 Missing enums (MUST define):
//   - __REQ_META (not present in our vmlinux.h, but in huatuo's at line 33977)
//
// To make BPF_CORE_READ() and bpf_core_field_exists() work, we must provide
// complete structure definitions with __attribute__((preserve_access_index)).
// This allows BPF CO-RE to adapt to different kernel versions at runtime.

// Complete struct request definition (for kernels where vmlinux.h has forward declaration only)
// Reference: https://github.com/ccfos/huatuo/blob/main/bpf/include/vmlinux_x86.h#L11754-L11812
// This matches the kernel's struct request layout
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
	// ... (omitting union fields not used)
	struct gendisk *rq_disk;  // Old kernel only (< 5.10)
	void *part;  // struct hd_struct * or struct block_device *
	__u64 alloc_time_ns;
	__u64 start_time_ns;
	__u64 io_start_time_ns;
	// ... (omitting remaining fields)
} __attribute__((preserve_access_index));

// Complete struct hd_struct definition (old kernels < 5.11)
struct hd_struct {
	int partno;
	// ... (omitting other fields)
} __attribute__((preserve_access_index));

// Compatibility structure for newer kernels (5.10+)
// Reference: https://github.com/ccfos/huatuo/blob/main/bpf/iotracing.c#L124-L126
// The triple underscore suffix marks this as a compatibility structure
struct request_queue___new {
	struct gendisk *disk;
} __attribute__((preserve_access_index));

// Compatibility structure for newer kernels (5.11+)
// Reference: https://github.com/ccfos/huatuo/blob/main/bpf/iotracing.c#L128-L131
struct block_device___new {
	dev_t bd_dev;
} __attribute__((preserve_access_index));

// Old kernel version: iov_iter has 'type' field (union)
// Reference: https://github.com/ccfos/huatuo/blob/main/bpf/include/vmlinux_x86.h#L8972-L8987
// huatuo's vmlinux_x86.h shows old kernel (5.4) has 'type' field
struct iov_iter___old {
	union {
		unsigned int type;
		int __type;  // Alternative field name in some kernels
	};
	size_t iov_offset;
	size_t count;
} __attribute__((preserve_access_index));

// Compatibility structure for newer kernels (6.4+)
// Reference: https://github.com/ccfos/huatuo/blob/main/bpf/iotracing.c#L383-L391
// New kernel version: iov_iter has 'data_source' field instead of 'type'
// Our vmlinux.h (line 31907) shows this newer layout
struct iov_iter___new {
	bool data_source;
	size_t count;
} __attribute__((preserve_access_index));

// Get request disk (compatible with different kernel versions)
// Older kernels (<5.10): req->rq_disk
// Newer kernels (>=5.10): req->q->disk
static __always_inline struct gendisk *get_request_disk(struct request *req)
{
	if (bpf_core_field_exists(req->rq_disk)) {
		// Old kernel: rq_disk field exists
		return BPF_CORE_READ(req, rq_disk);
	} else {
		// New kernel: access through request_queue
		struct request_queue___new *q;
		q = (struct request_queue___new *)BPF_CORE_READ(req, q);
		return BPF_CORE_READ(q, disk);
	}
}

// Get partition number (compatible with different kernel versions)
// Older kernels (<5.11): hd_struct->partno
// Newer kernels (>=5.11): block_device->bd_dev (lower 8 bits)
static __always_inline int get_partition_number(struct request *req)
{
	void *part = BPF_CORE_READ(req, part);

	if (bpf_core_field_exists(((struct hd_struct *)part)->partno)) {
		// Old kernel: use hd_struct->partno
		return BPF_CORE_READ((struct hd_struct *)part, partno);
	} else {
		// New kernel: extract from block_device->bd_dev
		struct block_device___new *new_part;
		int partno;
		new_part = (struct block_device___new *)part;
		partno = BPF_CORE_READ(new_part, bd_dev);
		return partno & 0xff;  // Lower 8 bits
	}
}

// ============================================================================
// File Path Extraction Helper
// ============================================================================

// Initialize io_data with process and file path information
// Extracts filename and up to 3 levels of parent directory names
static __always_inline void init_io_data(struct io_data *entry,
					 struct dentry *root_dentry,
					 struct dentry *dentry,
					 struct inode *inode)
{
	__u64 t = bpf_get_current_pid_tgid();

	// Extract process PID and TGID
	entry->pid = t >> 32;
	entry->tgid = t & 0xffffffff;

	// Read process name
	bpf_get_current_comm(entry->comm, TASK_COMM_LEN);

	// Extract filename and 3 levels of parent directories
	// User-space will concatenate: d3name/d2name/d1name/filename
	
	// Filename
	bpf_probe_read_str(entry->filename, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	// Parent directory (level 1)
	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d1name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	// Grandparent directory (level 2)
	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d2name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));

	// Great-grandparent directory (level 3)
	dentry = BPF_CORE_READ(dentry, d_parent);
	bpf_probe_read_str(entry->d3name, DNAME_INLINE_LEN,
			   BPF_CORE_READ(dentry, d_name.name));
}

// Try to upgrade entry to major contributor based on per-process statistics
// Returns: 1 if upgraded, 0 if not
static __always_inline int try_upgrade_contributor(struct io_data *entry,
						   __u32 dev,
						   __u64 inode,
						   __u64 count,
						   bool is_write)
{
	if (entry->upgraded)
		return 0;  // Already upgraded, skip
	
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid & 0xffffffff;  // Use TGID
	struct io_key_detail detail_key = {pid, dev, inode};
	struct io_stat *detail_stat = bpf_map_lookup_elem(&io_detail_map, &detail_key);
	struct io_stat new_stat = {};
	
	if (!detail_stat)
		detail_stat = &new_stat;
	
	if (is_write)
		detail_stat->fs_write_bytes += count;
	else
		detail_stat->fs_read_bytes += count;
	
	__u64 current_total = detail_stat->fs_write_bytes + detail_stat->fs_read_bytes;
	
	if (detail_stat == &new_stat)
		bpf_map_update_elem(&io_detail_map, &detail_key, &new_stat, BPF_ANY);
	
	// Upgrade if threshold reached
	if (current_total >= UPDATE_THRESHOLD) {
		entry->pid = pid;
		entry->tgid = pid;
		bpf_get_current_comm(entry->comm, TASK_COMM_LEN);
		
		// Try to get cmdline from current task
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		if (mm) {
			unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
			unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
			unsigned long len = arg_end - arg_start;
			if (len > 0) {
				if (len > 32)
					len = 32;  // Truncate to fit buffer
				bpf_probe_read_user(entry->cmdline, len, (void *)arg_start);
			}
		}
		
		entry->upgraded = 1;
		return 1;
	}
	
	return 0;
}

// ============================================================================
// Block Layer IO Tracing: rq_qos_issue (IO submission)
// ============================================================================

SEC("kprobe/rq_qos_issue")
int bpf_rq_qos_issue(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM2(ctx);
	struct hash_key key = {};
	struct io_start_info info = {};
	struct bio *bio;
	struct inode *inode;
	struct gendisk *disk;
	__u32 cmd_flags;
	int partno;
	int devn[2];

	bio = BPF_CORE_READ(req, bio);

	// Filter metadata requests, only track data IO
	cmd_flags = BPF_CORE_READ(req, cmd_flags);
	if (cmd_flags & REQ_META)
		return 0;

	// Get disk device and partition number
	disk = get_request_disk(req);
	// Read gendisk.major and gendisk.first_minor
	if (bpf_probe_read(devn, sizeof(devn), disk))
		return -1;

	// Construct device number: (major & 0xfff) << 20 | (minor + partno)
	partno = get_partition_number(req);
	key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
	key.sector = BPF_CORE_READ(req, __sector);

	// Check device filter
	if (!should_process_device(key.dev))
		return 0;

	// Extract inode information (to distinguish file IO and Direct IO)
	inode = BPF_CORE_READ(bio, bi_io_vec, bv_page, mapping, host);
	info.inode = BPF_CORE_READ(inode, i_ino);
	
	// Set device number based on inode
	if (info.inode == 0)
		info.dev = key.dev;  // Direct IO: use block device number
	else
		info.dev = BPF_CORE_READ(inode, i_sb, s_dev);  // File IO: use filesystem device

	// Record process and IO information
	info.pid = bpf_get_current_pid_tgid() >> 32;
	info.data_len = BPF_CORE_READ(req, __data_len);
	bpf_get_current_comm(info.comm, TASK_COMM_LEN);

	// Save to start_info_map, waiting for done to match
	bpf_map_update_elem(&start_info_map, &key, &info, BPF_ANY);

	return 0;
}

// ============================================================================
// Block Layer IO Tracing: rq_qos_done (IO completion)
// ============================================================================

SEC("kprobe/rq_qos_done")
int bpf_rq_qos_done(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM2(ctx);
	struct io_start_info *info = NULL;
	struct hash_key info_key = {};
	struct io_key io_key = {};
	struct io_data data = {};
	struct io_data *entry;
	struct gendisk *disk;
	__u32 cmd_flags;
	int partno;
	int devn[2];
	__u64 now, q2c, d2c;

	// Get device number to find corresponding record in start_info_map
	disk = get_request_disk(req);
	if (bpf_probe_read(devn, sizeof(devn), disk))
		return -1;

	partno = get_partition_number(req);
	info_key.dev = (devn[0] & 0xfff) << 20 | (devn[1] & 0xff) + partno;
	info_key.sector = BPF_CORE_READ(req, __sector);

	// Check device filter
	if (!should_process_device(info_key.dev))
		return 0;

	// Find issue phase information
	info = bpf_map_lookup_elem(&start_info_map, &info_key);
	if (!info)
		return 0;

	// Construct io_source_map key
	io_key.dev = info->dev;
	io_key.inode = info->inode;
	
	// For Direct IO, set pid value in key
	if (io_key.inode == 0)
		io_key.pid = info->pid;

	// Find or create io_source_map entry
	entry = bpf_map_lookup_elem(&io_source_map, &io_key);
	if (!entry)
		entry = &data;

	// Determine read/write direction and accumulate bytes
	cmd_flags = BPF_CORE_READ(req, cmd_flags);
	if (is_write_request(cmd_flags)) {
		entry->block_write_bytes += info->data_len;
	} else if ((cmd_flags & REQ_OP_MASK) == REQ_OP_READ) {
		entry->block_read_bytes += info->data_len;
	} else {
		// Other operations (not read/write), skip
		bpf_map_delete_elem(&start_info_map, &info_key);
		return 0;
	}

	// Calculate and accumulate latency: q2c and d2c
	now = bpf_ktime_get_ns();
	q2c = now - BPF_CORE_READ(req, start_time_ns);  // Queue to complete
	d2c = now - BPF_CORE_READ(req, io_start_time_ns);  // Device to complete

	entry->latency.sum_q2c += q2c;
	entry->latency.sum_d2c += d2c;
	entry->latency.cnt++;

	// Update maximum latency values
	if (q2c > entry->latency.max_q2c)
		entry->latency.max_q2c = q2c;
	if (d2c > entry->latency.max_d2c)
		entry->latency.max_d2c = d2c;

	// If new entry, initialize other fields and save to map
	// Note: Only initialize comm/pid for new entries to preserve the correct
	// process context from filesystem layer (which captures the real IO initiator)
	if (entry == &data) {
		entry->pid = info->pid;
		entry->dev = info->dev;
		entry->inode = info->inode;
		bpf_probe_read_str(entry->comm, TASK_COMM_LEN, info->comm);
		bpf_map_update_elem(&io_source_map, &io_key, &data, BPF_ANY);
	}

	// Delete temporary record from start_info_map
	bpf_map_delete_elem(&start_info_map, &info_key);

	return 0;
}

// ============================================================================
// Filesystem Layer IO Tracing: file read/write operations
// ============================================================================

// Common handler for file read/write operations
static __always_inline int bpf_file_read_write(struct pt_regs *ctx)
{
	struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
	struct io_data data = {};
	struct io_data *entry = NULL;
	struct dentry *dentry;
	struct dentry *root_dentry;
	struct inode *inode;
	struct io_key key = {};
	struct iov_iter *from;
	size_t count;
	unsigned int type;

	// Extract inode and device number from kiocb
	inode = BPF_CORE_READ(iocb, ki_filp, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	// Check device filter
	if (!should_process_device(key.dev))
		return 0;

	// Find or create entry in io_source_map
	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	// On first access from filesystem layer, initialize file path information
	// Use tgid == 0 to detect if entry was already initialized by filesystem layer
	// (block layer sets pid/comm but not tgid, only init_io_data() sets tgid)
	// This matches huatuo's behavior: https://github.com/ccfos/huatuo/blob/main/bpf/iotracing.c#L373
	dentry = BPF_CORE_READ(iocb, ki_filp, f_path.dentry);
	root_dentry = BPF_CORE_READ(iocb, ki_filp, f_path.mnt, mnt_root);
	if (entry->tgid == 0) {
		// First time from filesystem layer, initialize with correct process context
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
		entry->upgraded = 0;  // Initialize upgrade flag
	}

	// Get IO byte count from iov_iter
	from = (struct iov_iter *)PT_REGS_PARM2(ctx);
	count = BPF_CORE_READ(from, count);

	// Compatibility handling for different kernel versions of iov_iter structure
	// Kernel <6.4: uses 'type' field (union)
	// Kernel >=6.4: uses 'data_source' field
	struct iov_iter___old *from_old = (struct iov_iter___old *)from;
	struct iov_iter___new *from_new = (struct iov_iter___new *)from;
	
	if (bpf_core_field_exists(from_old->type)) {
		type = BPF_CORE_READ(from_old, type);
	} else {
		type = BPF_CORE_READ(from_new, data_source);
	}

	// Determine read/write direction and accumulate bytes
	// Lowest bit: 0 = read, 1 = write
	// (存在竞态，但可以接受)
	type = type & 0x1;
	if (type)
		entry->fs_write_bytes += count;  // Write
	else
		entry->fs_read_bytes += count;   // Read

	// Try to upgrade to major contributor
	try_upgrade_contributor(entry, key.dev, key.inode, count, type);

	// Save IOCB flags (for Direct IO detection)
	// 基于不存在同时 Direct + non-Direct 的假设
	entry->flag = BPF_CORE_READ(iocb, ki_flags);

	// Update map (存在竞态，但可以接受)
	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);

	return 0;
}

// Generic file read iterator hook (dynamically attached to ext4/xfs)
SEC("kprobe/anyfs_file_read_iter")
int bpf_anyfs_file_read_iter(struct pt_regs *ctx)
{
	return bpf_file_read_write(ctx);
}

// Generic file write iterator hook (dynamically attached to ext4/xfs)
SEC("kprobe/anyfs_file_write_iter")
int bpf_anyfs_file_write_iter(struct pt_regs *ctx)
{
	return bpf_file_read_write(ctx);
}

// ============================================================================
// Page Cache IO Tracing: mmap read/write operations
// ============================================================================

// Page fault handler (mmap read trigger)
SEC("kprobe/filemap_fault")
int bpf_filemap_fault(struct pt_regs *ctx)
{
	struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
	struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
	struct io_data *entry = NULL;
	struct io_data data = {};
	struct io_key key = {};
	struct inode *inode;

	// Extract inode and device number
	inode = BPF_CORE_READ(vma, vm_file, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	// Check device filter
	if (!should_process_device(key.dev))
		return 0;

	// Find or create entry
	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	// On first access, initialize file path
	if (entry->tgid == 0) {
		struct dentry *dentry;
		struct dentry *root_dentry;

		dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
		root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
		entry->upgraded = 0;  // Initialize upgrade flag
	}

	// mmap read is calculated by page, accumulate PAGE_SIZE each time
	entry->fs_read_bytes += PAGE_SIZE;

	// Try to upgrade to major contributor
	try_upgrade_contributor(entry, key.dev, key.inode, PAGE_SIZE, false);

	// Update map
	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);

	return 0;
}

// Page write-back handler (mmap write trigger)
// Generic hook, dynamically attached to ext4/xfs specific functions
SEC("kprobe/anyfs_filemap_page_mkwrite")
int bpf_anyfs_filemap_page_mkwrite(struct pt_regs *ctx)
{
	struct vm_fault *vm = (struct vm_fault *)PT_REGS_PARM1(ctx);
	struct vm_area_struct *vma = BPF_CORE_READ(vm, vma);
	struct io_data *entry = NULL;
	struct io_data data = {};
	struct io_key key = {};
	struct inode *inode;

	// Extract inode and device number
	inode = BPF_CORE_READ(vma, vm_file, f_inode);
	key.inode = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	// Check device filter
	if (!should_process_device(key.dev))
		return 0;

	// Find or create entry
	entry = bpf_map_lookup_elem(&io_source_map, &key);
	if (!entry)
		entry = &data;

	// On first access, initialize file path
	if (entry->tgid == 0) {
		struct dentry *dentry;
		struct dentry *root_dentry;

		dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
		root_dentry = BPF_CORE_READ(vma, vm_file, f_path.mnt, mnt_root);
		init_io_data(entry, root_dentry, dentry, inode);
		entry->dev = key.dev;
		entry->inode = key.inode;
		entry->upgraded = 0;  // Initialize upgrade flag
	}

	// mmap write is calculated by page, accumulate PAGE_SIZE each time
	entry->fs_write_bytes += PAGE_SIZE;

	// Try to upgrade to major contributor
	try_upgrade_contributor(entry, key.dev, key.inode, PAGE_SIZE, true);

	// Update map
	if (entry == &data)
		bpf_map_update_elem(&io_source_map, &key, &data, BPF_ANY);

	return 0;
}

// TODO: Add BPF maps
// TODO: Add helper functions
// TODO: Add BPF programs

