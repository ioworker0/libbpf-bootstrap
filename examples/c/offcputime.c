// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h> // Required for user-space BPF map operations like bpf_map_lookup_elem
#include "offcputime.skel.h"

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 127

/*
 * The event structure must exactly match the one in the BPF code
 * to ensure correct data parsing from the ring buffer.
 */
struct event {
	__u64 delta_us;
	__u32 pid;
	__s32 kern_stack_id;
	char comm[TASK_COMM_LEN];
};

// Global flag to indicate if the program should exit, set by the signal handler.
static volatile bool exiting = false;

/*
 * Data structures and variables for manual kernel symbol resolution.
 * This approach makes the tool independent of libbpf's symbolization features.
 */
#define MAX_SYMBOLS 500000
#define MAX_SYMBOL_NAME_LEN 128
struct kernel_symbol {
	uint64_t addr;
	char name[MAX_SYMBOL_NAME_LEN];
};
static struct kernel_symbol *symbols = NULL;
static int symbol_count = 0;
static bool stack_traces_enabled = false; // Flag controlled by the -S/--stack argument.

/**
 * @brief Signal handler for graceful exit on Ctrl+C (SIGINT) and SIGTERM.
 */
static void sig_handler(int sig)
{
	exiting = true;
}

/**
 * @brief libbpf print callback. It's called by libbpf to print error and debug messages.
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/**
 * @brief Loads kernel symbols from /proc/kallsyms into a sorted array.
 *
 * This allows for fast, manual address-to-symbol resolution later on.
 * It's only called if the user requests stack traces.
 */
static int load_kernel_symbols()
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f) {
		perror("Failed to open /proc/kallsyms");
		return -1;
	}

	symbols = malloc(MAX_SYMBOLS * sizeof(struct kernel_symbol));
	if (!symbols) {
		fprintf(stderr, "Failed to allocate memory for symbols\n");
		fclose(f);
		return -1;
	}

	char line[256];
	while (fgets(line, sizeof(line), f) && symbol_count < MAX_SYMBOLS) {
		uint64_t addr;
		char type;
		char name[MAX_SYMBOL_NAME_LEN];
		if (sscanf(line, "%" PRIx64 " %c %s", &addr, &type, name) == 3) {
			symbols[symbol_count].addr = addr;
			strncpy(symbols[symbol_count].name, name, MAX_SYMBOL_NAME_LEN - 1);
			symbols[symbol_count].name[MAX_SYMBOL_NAME_LEN - 1] = '\0';
			symbol_count++;
		}
	}

	fclose(f);
	printf("INFO: Loaded %d kernel symbols.\n", symbol_count);
	return 0;
}

/**
 * @brief Resolves a kernel address to a symbol name and offset.
 *
 * Uses a binary search on the pre-loaded symbols for efficiency.
 * @param addr The kernel address to resolve.
 * @return A string with the format "symbol+0xoffset" or an error message.
 */
const char *resolve_kernel_symbol(uint64_t addr)
{
	static char symbol_str[MAX_SYMBOL_NAME_LEN + 32];

	if (symbol_count == 0)
		return "[kallsyms not loaded]";

	int left = 0, right = symbol_count - 1;
	int match_index = -1;

	// Binary search to find the closest symbol whose address is <= the given addr.
	while (left <= right) {
		int mid = left + (right - left) / 2;
		if (symbols[mid].addr <= addr) {
			match_index = mid;
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	if (match_index != -1) {
		uint64_t offset = addr - symbols[match_index].addr;
		snprintf(symbol_str, sizeof(symbol_str), "%s+0x%lx", symbols[match_index].name,
			 (unsigned long)offset);
		return symbol_str;
	}

	return "[unresolved]";
}

/**
 * @brief Fetches and prints a kernel stack trace given a stack_id.
 *
 * @param skel The BPF skeleton object, used to access map FDs.
 * @param stack_id The ID of the stack trace to retrieve from the BPF map.
 */
static void print_stack(struct offcputime_bpf *skel, int32_t stack_id)
{
	uint64_t ips[MAX_STACK_DEPTH] = {};
	int map_fd;

	if (stack_id < 0)
		return; // The kernel failed to get a stack ID.

	// Get the file descriptor of the stack_traces map.
	map_fd = bpf_map__fd(skel->maps.stack_traces);
	if (map_fd < 0) {
		fprintf(stderr, " ERROR: Failed to get stack_traces map fd\n");
		return;
	}

	// Lookup the stack trace (an array of instruction pointers) by its ID.
	if (bpf_map_lookup_elem(map_fd, &stack_id, ips) != 0) {
		fprintf(stderr, " ERROR: Failed to lookup stack trace for id %d\n", stack_id);
		return;
	}

	printf("  Kernel Stack:\n");
	// Iterate through the instruction pointers and resolve each one to a symbol.
	for (int i = 0; i < MAX_STACK_DEPTH && ips[i]; i++) {
		printf("    #%-2d %s\n", i, resolve_kernel_symbol(ips[i]));
	}
}

/**
 * @brief Callback function for handling events from the BPF ring buffer.
 *
 * This function is called by libbpf for each event received from the kernel.
 * @param ctx The context pointer passed to ring_buffer__new (our 'skel' object).
 * @param data A pointer to the event data.
 * @param data_sz The size of the event data.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct offcputime_bpf *skel = ctx; // Retrieve the skeleton object from the context.
	struct tm *tm;
	char ts[32];
	time_t t;

	// Get the current user-space timestamp for logging.
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// Print the basic event information.
	printf("%-8s %-16s %-7d %10llu us\n", ts, e->comm, e->pid, e->delta_us);

	// If stack traces are enabled, print the kernel stack.
	if (stack_traces_enabled) {
		print_stack(skel, e->kern_stack_id);
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *btf_path = "/tmp/vmlinux.btf";
	struct offcputime_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	pid_t target_pid = 0;
	__u64 min_us = 1000;

	// Simple command-line argument parsing.
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <PID> [min_us] [-S|--stack]\n", argv[0]);
		return 1;
	}

	target_pid = atoi(argv[1]);
	if (target_pid <= 0) {
		fprintf(stderr, "Invalid PID: %s\n", argv[1]);
		return 1;
	}

	int arg_idx = 2;
	if (argc > arg_idx && strcmp(argv[arg_idx], "-S") != 0 && strcmp(argv[arg_idx], "--stack") != 0) {
		min_us = strtoull(argv[arg_idx], NULL, 10);
		arg_idx++;
	}
	if (argc > arg_idx && (strcmp(argv[arg_idx], "-S") == 0 || strcmp(argv[arg_idx], "--stack") == 0)) {
		stack_traces_enabled = true;
	}

	// Set up libbpf logging.
	libbpf_set_print(libbpf_print_fn);

	// Set up signal handlers for graceful exit.
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Conditionally load kernel symbols if stack tracing is requested.
	if (stack_traces_enabled) {
		if (load_kernel_symbols() != 0) {
			fprintf(stderr, "WARNING: Could not load kernel symbols. Stack traces will be raw addresses.\n");
		}
	}

	// Open the BPF skeleton, with a fallback to a custom BTF file.
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	if (access(btf_path, R_OK) == 0) {
		printf("INFO: Found custom BTF at %s, using it.\n", btf_path);
		open_opts.btf_custom_path = btf_path;
		skel = offcputime_bpf__open_opts(&open_opts);
	} else {
		printf("INFO: Custom BTF %s not found. Letting libbpf find one automatically.\n", btf_path);
		skel = offcputime_bpf__open();
	}

	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Pass filters from user-space to the BPF program's .rodata section.
	skel->rodata->target_pid = target_pid;
	skel->rodata->min_us = min_us;

	// Load and verify BPF programs into the kernel.
	err = offcputime_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}

	// Attach BPF programs to their target tracepoints.
	err = offcputime_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// Set up the ring buffer for receiving events from the kernel.
	// We pass 'skel' as the context pointer, so handle_event can access maps.
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Tracing Off-CPU time for PID %d longer than %llu us... Hit Ctrl-C to end.\n", target_pid, min_us);
	printf("%-8s %-16s %-7s %11s\n", "TIME", "COMM", "PID", "LATENCY");

	// Main event polling loop.
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		// Ctrl-C will cause -EINTR.
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	// Clean up all resources before exiting.
	ring_buffer__free(rb);
	offcputime_bpf__destroy(skel);
	free(symbols);
	return err < 0 ? -err : 0;
}