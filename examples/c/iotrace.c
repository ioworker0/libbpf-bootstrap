// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 IO Tracing Tool

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iotrace.skel.h"

// ============================================================================
// Data Structures (must match BPF side)
// ============================================================================

struct latency_info {
	uint64_t cnt;
	uint64_t max_d2c;
	uint64_t sum_d2c;
	uint64_t max_q2c;
	uint64_t sum_q2c;
};

struct io_data {
	uint32_t pid;
	uint32_t tgid;                   // Thread group ID (must match BPF side)
	uint32_t dev;
	uint32_t flag;
	uint8_t  upgraded;               // Whether upgraded to major contributor
	uint8_t  _pad[3];                // Padding for alignment
	uint64_t fs_write_bytes;
	uint64_t fs_read_bytes;
	uint64_t block_write_bytes;
	uint64_t block_read_bytes;
	uint64_t inode;
	struct latency_info latency;
	char comm[16];
	char cmdline[32];                // Command line (32 bytes, truncated if needed)
	char filename[32];               // File name (32 bytes)
	char d1name[32];                 // Parent directory name (32 bytes)
	char d2name[32];                 // Grandparent directory name (32 bytes)
	char d3name[32];                 // Great-grandparent directory name (32 bytes)
};

// Process aggregated data
struct process_data {
	uint32_t pid;
	char comm[16];       // Process name (short)
	char cmdline[32];    // Full command line (truncated to 32 bytes)
	uint64_t fs_read;
	uint64_t fs_write;
	uint64_t disk_read;
	uint64_t disk_write;
	uint64_t file_count;
};

// Configuration
struct config {
	uint64_t duration;           // Tracing duration (seconds)
	uint32_t max_processes;      // Max processes to display
	uint32_t max_files_per_process;  // Max files per process
	char device_str[256];        // Device filter string
	uint32_t devices[16];        // Parsed device numbers
	uint32_t device_count;       // Number of devices
};

// ============================================================================
// Global Variables
// ============================================================================

static volatile bool exiting = false;
static struct config cfg = {
	.duration = 8,
	.max_processes = 10,
	.max_files_per_process = 5,
};

// ============================================================================
// Signal Handling
// ============================================================================

static void handle_signal(int sig)
{
	exiting = true;
}

// ============================================================================
// Helper Functions
// ============================================================================

// libbpf print callback
static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;  // Suppress debug output
	
	return vfprintf(stderr, format, args);
}

// Check if filesystem is supported
static bool is_fs_supported(const char *fs_name)
{
	FILE *f = fopen("/proc/filesystems", "r");
	if (!f)
		return false;
	
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

// Check if kprobe function exists
static bool check_kprobe_exists(const char *func_name)
{
	FILE *f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
	if (!f)
		return false;
	
	char line[256];
	bool found = false;
	while (fgets(line, sizeof(line), f)) {
		// Function name is before space
		char *space = strchr(line, ' ');
		if (space)
			*space = '\0';
		
		// Remove newline
		char *newline = strchr(line, '\n');
		if (newline)
			*newline = '\0';
		
		if (strcmp(line, func_name) == 0) {
			found = true;
			break;
		}
	}
	fclose(f);
	return found;
}

// Parse device numbers from string (format: "8:0,253:0")
static int parse_device_numbers(const char *device_str, uint32_t *devs, uint32_t *count)
{
	char *str_copy = strdup(device_str);
	if (!str_copy)
		return -1;
	
	char *token = strtok(str_copy, ",");
	*count = 0;
	
	while (token && *count < 16) {
		// Trim whitespace
		while (*token == ' ')
			token++;
		
		unsigned int major, minor;
		if (sscanf(token, "%u:%u", &major, &minor) != 2) {
			fprintf(stderr, "Invalid device format: %s\n", token);
			free(str_copy);
			return -1;
		}
		
		// Convert to kernel device number format
		devs[*count] = ((major & 0xfff) << 20) | minor;
		(*count)++;
		
		token = strtok(NULL, ",");
	}
	
	free(str_copy);
	
	if (*count > 16) {
		fprintf(stderr, "Too many devices specified (max 16), got %u\n", *count);
		return -1;
	}
	
	return 0;
}

// Format device number to "major:minor" string
static void format_device(uint32_t dev, char *buf, size_t size)
{
	unsigned int major = (dev >> 20) & 0xfff;
	unsigned int minor = dev & 0xfffff;
	snprintf(buf, size, "%u:%u", major, minor);
}

// Format bytes to human-readable format
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

// Get process command line from /proc/[pid]/cmdline
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
	
	// Replace \0 separators with spaces
	for (ssize_t i = 0; i < n - 1; i++) {
		if (buf[i] == '\0')
			buf[i] = ' ';
	}
	
	return true;
}

// ============================================================================
// Data Processing and Output
// ============================================================================

// Print process-level summary table
static void print_process_summary(struct process_data *processes, int count)
{
	printf("PID     COMMAND              FS_READ FS_WRITE DISK_READ DISK_WRITE FILES\n");
	printf("======  ===================  ======= ======== ========= ========== =====\n");
	
	for (int i = 0; i < count && i < (int)cfg.max_processes; i++) {
		struct process_data *p = &processes[i];
		
		char fs_read_str[32], fs_write_str[32];
		char disk_read_str[32], disk_write_str[32];
		
		format_bytes(p->fs_read, fs_read_str, sizeof(fs_read_str));
		format_bytes(p->fs_write, fs_write_str, sizeof(fs_write_str));
		format_bytes(p->disk_read, disk_read_str, sizeof(disk_read_str));
		format_bytes(p->disk_write, disk_write_str, sizeof(disk_write_str));
		
		// Truncate or pad command
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

// Print file-level details for each process
static void print_file_details(int map_fd, struct process_data *processes, int count, uint64_t duration)
{
	for (int i = 0; i < count && i < (int)cfg.max_processes; i++) {
		struct process_data *p = &processes[i];
		
		char total_read[32], total_write[32];
		format_bytes(p->fs_read, total_read, sizeof(total_read));
		format_bytes(p->fs_write, total_write, sizeof(total_write));
		
		printf("===========================================================================\n");
		printf("PID: %-6u  TOTAL_IO: R=%s W=%s  FILES: %lu\n",
		       p->pid, total_read, total_write, p->file_count);
		
		// Re-iterate map to find files for this process
		struct io_data data;
		uint32_t key_pid, key_dev;
		uint64_t key_inode;
		int key_size = sizeof(key_pid) + sizeof(key_dev) + sizeof(key_inode);
		uint8_t key[key_size];
		uint8_t next_key[key_size];
		bool first = true;
		int file_count = 0;
		bool printed_command = false;
		
		while (file_count < (int)cfg.max_files_per_process) {
			int ret;
			if (first) {
				ret = bpf_map_get_next_key(map_fd, NULL, next_key);
				first = false;
			} else {
				ret = bpf_map_get_next_key(map_fd, key, next_key);
			}
			
			if (ret != 0)
				break;
			
			memcpy(key, next_key, key_size);
			
			// Read value
			if (bpf_map_lookup_elem(map_fd, key, &data) != 0)
				continue;
			
		// Skip if not for this process
		if (data.pid != p->pid)
			continue;
		
		// Print COMMAND header on first match
		if (!printed_command) {
			// Prefer cmdline (full command), fallback to comm (process name)
			const char *cmd = (p->cmdline[0] != '\0') ? p->cmdline : p->comm;
			printf("COMMAND: %s\n", cmd);
			printf("-----------------------------------\n");
			printf("DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE\n");
			printed_command = true;
		}
		
		file_count++;
			const char *cmd = (data.cmdline[0] != '\0') ? data.cmdline : data.comm;
			printf("COMMAND: %s\n", cmd);
			printf("-----------------------------------\n");
			printf("DEVICE  FS_READ FS_WRITE DISK_READ DISK_WRITE   LATENCY(μs)      FILE\n");
			printed_command = true;
		}
		
		file_count++;
			
			// Calculate rates (bytes/sec)
			uint64_t fs_read = data.fs_read_bytes / duration;
			uint64_t fs_write = data.fs_write_bytes / duration;
			uint64_t disk_read = data.block_read_bytes / duration;
			uint64_t disk_write = data.block_write_bytes / duration;
			
			// Calculate latency
			uint64_t q2c_avg = 0, q2c_max = 0, d2c_avg = 0, d2c_max = 0;
			if (data.latency.cnt > 0) {
				q2c_avg = data.latency.sum_q2c / data.latency.cnt / 1000;  // ns->us
				d2c_avg = data.latency.sum_d2c / data.latency.cnt / 1000;
				q2c_max = data.latency.max_q2c / 1000;
				d2c_max = data.latency.max_d2c / 1000;
			}
			
			// Build file path
			char filepath[256];
			if (data.inode == 0) {
				snprintf(filepath, sizeof(filepath), "[direct IO]");
			} else {
				// Concatenate: d3name/d2name/d1name/filename
				snprintf(filepath, sizeof(filepath), "%s/%s/%s/%s",
					 data.d3name, data.d2name, data.d1name, data.filename);
				
				// Remove leading slashes
				char *p_path = filepath;
				while (*p_path == '/')
					p_path++;
				if (p_path != filepath)
					memmove(filepath, p_path, strlen(p_path) + 1);
				
				// Add Direct IO flag if applicable
				if (data.flag & 0x4) {
					strcat(filepath, " [direct IO]");
				}
			}
			
			// Format device
			char dev_str[16];
			format_device(data.dev, dev_str, sizeof(dev_str));
			
			// Format bytes
			char fs_r[16], fs_w[16], disk_r[16], disk_w[16];
			format_bytes(fs_read, fs_r, sizeof(fs_r));
			format_bytes(fs_write, fs_w, sizeof(fs_w));
			format_bytes(disk_read, disk_r, sizeof(disk_r));
			format_bytes(disk_write, disk_w, sizeof(disk_w));
			
			printf("%-7s %7s %8s %9s %9s   q2c=%lu(max %lu) d2c=%lu(max %lu)  %s\n",
			       dev_str, fs_r, fs_w, disk_r, disk_w,
			       q2c_avg, q2c_max, d2c_avg, d2c_max,
			       filepath);
		}
		printf("\n");
	}
}

// Comparison function for sorting processes by total disk IO
static int compare_processes(const void *a, const void *b)
{
	const struct process_data *pa = a;
	const struct process_data *pb = b;
	uint64_t total_a = pa->disk_read + pa->disk_write;
	uint64_t total_b = pb->disk_read + pb->disk_write;
	
	if (total_b > total_a)
		return 1;
	else if (total_b < total_a)
		return -1;
	return 0;
}

// ============================================================================
// BPF Program Loading and Attachment
// ============================================================================

// Dynamic attachment of BPF programs based on kernel availability
static int attach_bpf_programs(struct iotrace_bpf *skel)
{
	struct bpf_link *link;
	
	// 1. Block layer hooks
	// The chosen attachment points are rq_qos_issue/rq_qos_done, which were introduced in the 4.19 kernel
	// and became __rq_qos_issue/__rq_qos_done in the 5.0 kernel.
	// Reference: https://github.com/ccfos/huatuo/blob/main/cmd/iotracing/iotracing.go#L354-L371
	
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
	
	// Attach rq_qos_issue
	fprintf(stderr, "Attaching to %s...\n", issue_symbol);
	link = bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_issue, false, issue_symbol);
	if (!link) {
		fprintf(stderr, "Failed to attach %s\n", issue_symbol);
		return -1;
	}
	
	// Attach rq_qos_done
	fprintf(stderr, "Attaching to %s...\n", done_symbol);
	link = bpf_program__attach_kprobe(skel->progs.bpf_rq_qos_done, false, done_symbol);
	if (!link) {
		fprintf(stderr, "Failed to attach %s\n", done_symbol);
		return -1;
	}
	
	// 2. Filesystem hooks - ext4 and xfs
	// Use the same anyfs BPF program but attach to different kernel symbols
	bool has_ext4 = is_fs_supported("ext4");
	bool has_xfs = is_fs_supported("xfs");
	
	if (has_ext4) {
		fprintf(stderr, "Attaching ext4 file IO hooks...\n");
		
		// Attach anyfs_file_read_iter to ext4_file_read_iter
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, false, "ext4_file_read_iter");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach ext4_file_read_iter\n");
		}
		
		// Attach anyfs_file_write_iter to ext4_file_write_iter
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_write_iter, false, "ext4_file_write_iter");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach ext4_file_write_iter\n");
		}
		
		// Attach anyfs_filemap_page_mkwrite to ext4_page_mkwrite
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_filemap_page_mkwrite, false, "ext4_page_mkwrite");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach ext4_page_mkwrite\n");
		}
	}
	
	if (has_xfs) {
		fprintf(stderr, "Attaching xfs file IO hooks...\n");
		
		// Attach anyfs_file_read_iter to xfs_file_read_iter
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_read_iter, false, "xfs_file_read_iter");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach xfs_file_read_iter\n");
		}
		
		// Attach anyfs_file_write_iter to xfs_file_write_iter
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_file_write_iter, false, "xfs_file_write_iter");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach xfs_file_write_iter\n");
		}
		
		// Attach anyfs_filemap_page_mkwrite to xfs_filemap_page_mkwrite
		link = bpf_program__attach_kprobe(skel->progs.bpf_anyfs_filemap_page_mkwrite, false, "xfs_filemap_page_mkwrite");
		if (!link) {
			fprintf(stderr, "Warning: Failed to attach xfs_filemap_page_mkwrite\n");
		}
	}
	
	// 3. Page cache hook (common)
	fprintf(stderr, "Attaching filemap_fault...\n");
	link = bpf_program__attach_kprobe(skel->progs.bpf_filemap_fault, false, "filemap_fault");
	if (!link) {
		fprintf(stderr, "Warning: Failed to attach filemap_fault\n");
	}
	
	return 0;
}

// ============================================================================
// Main Function
// ============================================================================

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("Options:\n");
	printf("  -d, --duration SECONDS    Tracing duration (default: 8)\n");
	printf("  -t, --top N               Max processes to display (default: 10)\n");
	printf("  -f, --files N             Max files per process (default: 5)\n");
	printf("  -D, --device DEVS         Filter devices (format: 8:0,253:0)\n");
	printf("  -h, --help                Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s -d 10 -t 5           # Trace for 10s, show top 5 processes\n", prog);
	printf("  %s -D 8:0,253:0         # Filter sda and dm-0\n", prog);
}

int main(int argc, char **argv)
{
	struct iotrace_bpf *skel = NULL;
	int err;
	
	// Declare variable-length arrays at the beginning to avoid goto issues
	struct io_data data;
	uint32_t key_pid, key_dev;
	uint64_t key_inode;
	int key_size = sizeof(key_pid) + sizeof(key_dev) + sizeof(key_inode);
	uint8_t key[key_size];
	uint8_t next_key[key_size];
	struct process_data processes[1024] = {0};
	int process_count = 0;
	bool first = true;
	int map_fd = -1;
	
	// Parse command line arguments (task 2.15)
	static struct option long_options[] = {
		{"duration", required_argument, NULL, 'd'},
		{"top", required_argument, NULL, 't'},
		{"files", required_argument, NULL, 'f'},
		{"device", required_argument, NULL, 'D'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	
	int opt;
	while ((opt = getopt_long(argc, argv, "d:t:f:D:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			cfg.duration = atoi(optarg);
			if (cfg.duration == 0) {
				fprintf(stderr, "Invalid duration\n");
				return 1;
			}
			break;
		case 't':
			cfg.max_processes = atoi(optarg);
			break;
		case 'f':
			cfg.max_files_per_process = atoi(optarg);
			break;
		case 'D':
			strncpy(cfg.device_str, optarg, sizeof(cfg.device_str) - 1);
			if (parse_device_numbers(cfg.device_str, cfg.devices, &cfg.device_count) != 0) {
				return 1;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}
	
	// Set up signal handlers
	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	
	// Set libbpf print callback
	libbpf_set_print(libbpf_print_fn);
	
	// Bump RLIMIT_MEMLOCK
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
		return 1;
	}
	
	// Task 2.8: Load BPF skeleton with BTF path handling
	const char *btf_path = "/plux/btf/kernel.btf";
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
	
	// Set device filter if specified (task 2.6)
	if (cfg.device_count > 0) {
		fprintf(stderr, "Setting device filter: ");
		for (uint32_t i = 0; i < cfg.device_count; i++) {
			char dev_str[16];
			format_device(cfg.devices[i], dev_str, sizeof(dev_str));
			fprintf(stderr, "%s ", dev_str);
			skel->rodata->FILTER_DEVS[i] = cfg.devices[i];
		}
		fprintf(stderr, "\n");
		skel->rodata->FILTER_DEV_COUNT = cfg.device_count;
	}
	
	// Load BPF programs
	err = iotrace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}
	
	// Task 2.9: Dynamic attachment
	err = attach_bpf_programs(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}
	
	fprintf(stderr, "Tracing IO for %lu seconds... Hit Ctrl-C to stop.\n", cfg.duration);
	
	// Task 2.16: Main loop
	uint64_t elapsed = 0;
	while (!exiting && elapsed < cfg.duration) {
		sleep(1);
		elapsed++;
	}
	
	// Task 2.10: Read map data and aggregate
	map_fd = bpf_map__fd(skel->maps.io_source_map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get io_source_map fd\n");
		err = -1;
		goto cleanup;
	}
	
	// Debug: dump io_source_map
	printf("\n========== DEBUG: io_source_map contents ==========\n");
	first = true;
	while (true) {
		int ret;
		if (first) {
			ret = bpf_map_get_next_key(map_fd, NULL, next_key);
			first = false;
		} else {
			ret = bpf_map_get_next_key(map_fd, key, next_key);
		}
		if (ret != 0)
			break;
		
		memcpy(key, next_key, key_size);
		if (bpf_map_lookup_elem(map_fd, key, &data) != 0)
			continue;
		
		memcpy(&key_pid, key, sizeof(key_pid));
		memcpy(&key_dev, key + sizeof(key_pid), sizeof(key_dev));
		memcpy(&key_inode, key + sizeof(key_pid) + sizeof(key_dev), sizeof(key_inode));
		
		printf("PID=%u DEV=%u:%u INODE=%lu UPGRADED=%u COMM='%s' CMDLINE='%s' FILE='%s'\n",
		       data.pid, key_dev >> 8, key_dev & 0xff, data.inode,
		       data.upgraded, data.comm, data.cmdline, data.filename);
		printf("  IO: fs_read=%lu fs_write=%lu block_read=%lu block_write=%lu\n",
		       data.fs_read_bytes, data.fs_write_bytes,
		       data.block_read_bytes, data.block_write_bytes);
	}
	
	// Debug: dump io_detail_map
	int detail_map_fd = bpf_map__fd(skel->maps.io_detail_map);
	if (detail_map_fd >= 0) {
		printf("\n========== DEBUG: io_detail_map contents ==========\n");
		
		struct {
			uint32_t pid;
			uint32_t dev;
			uint64_t inode;
		} detail_key;
		
		struct {
			uint64_t fs_write_bytes;
			uint64_t fs_read_bytes;
			uint64_t block_write_bytes;
			uint64_t block_read_bytes;
		} detail_stat;
		
		uint8_t detail_key_buf[sizeof(detail_key)];
		uint8_t detail_next_key[sizeof(detail_key)];
		first = true;
		
		while (true) {
			int ret;
			if (first) {
				ret = bpf_map_get_next_key(detail_map_fd, NULL, detail_next_key);
				first = false;
			} else {
				ret = bpf_map_get_next_key(detail_map_fd, detail_key_buf, detail_next_key);
			}
			if (ret != 0)
				break;
			
			memcpy(detail_key_buf, detail_next_key, sizeof(detail_key));
			if (bpf_map_lookup_elem(detail_map_fd, detail_key_buf, &detail_stat) != 0)
				continue;
			
			memcpy(&detail_key, detail_key_buf, sizeof(detail_key));
			printf("PID=%u DEV=%u:%u INODE=%lu\n",
			       detail_key.pid, detail_key.dev >> 8, detail_key.dev & 0xff, detail_key.inode);
			printf("  IO: fs_read=%lu fs_write=%lu total=%lu\n",
			       detail_stat.fs_read_bytes, detail_stat.fs_write_bytes,
			       detail_stat.fs_read_bytes + detail_stat.fs_write_bytes);
		}
	}
	printf("===================================================\n\n");
	
	// Reset variables for map iteration
	first = true;
	process_count = 0;
	
	while (true) {
		int ret;
		if (first) {
			ret = bpf_map_get_next_key(map_fd, NULL, next_key);
			first = false;
		} else {
			ret = bpf_map_get_next_key(map_fd, key, next_key);
		}
		
		if (ret != 0)
			break;
		
		memcpy(key, next_key, key_size);
		
		// Read value
		if (bpf_map_lookup_elem(map_fd, key, &data) != 0)
			continue;
		
		// Find or create process entry
		int proc_idx = -1;
		for (int i = 0; i < process_count; i++) {
			if (processes[i].pid == data.pid) {
				proc_idx = i;
				break;
			}
		}
		
		if (proc_idx == -1) {
			if (process_count >= 1024) {
				fprintf(stderr, "Too many processes, skipping some\n");
				continue;
			}
			proc_idx = process_count++;
			processes[proc_idx].pid = data.pid;
			strncpy(processes[proc_idx].comm, data.comm, sizeof(processes[proc_idx].comm) - 1);
			processes[proc_idx].cmdline[0] = '\0';  // Initialize as empty
		}
		
		// If this entry is upgraded, update comm and cmdline (overwrite previous)
		if (data.upgraded) {
			strncpy(processes[proc_idx].comm, data.comm, sizeof(processes[proc_idx].comm) - 1);
			if (data.cmdline[0] != '\0') {
				strncpy(processes[proc_idx].cmdline, data.cmdline, sizeof(processes[proc_idx].cmdline) - 1);
			}
		}
		
		// Aggregate
		processes[proc_idx].fs_read += data.fs_read_bytes;
		processes[proc_idx].fs_write += data.fs_write_bytes;
		processes[proc_idx].disk_read += data.block_read_bytes;
		processes[proc_idx].disk_write += data.block_write_bytes;
		processes[proc_idx].file_count++;
	}
	
	// Sort by total disk IO
	qsort(processes, process_count, sizeof(struct process_data), compare_processes);
	
	// Task 2.13 + 2.14: Print output
	printf("\n");
	printf("============= IO Tracing Report (Duration: %lus) =============\n\n", cfg.duration);
	print_process_summary(processes, process_count);
	print_file_details(map_fd, processes, process_count, cfg.duration);
	
cleanup:
	iotrace_bpf__destroy(skel);
	return err != 0;
}
// TODO: Add main function

