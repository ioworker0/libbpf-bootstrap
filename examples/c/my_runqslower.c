// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include "my_runqslower.skel.h"

#define TASK_COMM_LEN	16
#define MAX_STACK_DEPTH 127

/*
 * The event structure must exactly match the one in the BPF code
 * to ensure correct data parsing from the ring buffer.
 */
struct event {
	char task[TASK_COMM_LEN];
	char prev_task[TASK_COMM_LEN];
	__u64 delta_us;
	pid_t pid;
	pid_t prev_pid;
	int cpu;
	bool was_involuntarily_switched;
	int32_t prev_stack_id;
};

/*
 * Global structure to hold command-line arguments and settings.
 */
static struct env {
	pid_t pid;
	pid_t tid;
	char *comm;
	__u64 min_us;
	bool previous;
	bool verbose;
	bool prev_stack;
} env = {
	.min_us = 10000,
};

/*
 * Kernel symbol resolution data structures.
 */
#define MAX_SYMBOLS	    250000
#define MAX_SYMBOL_NAME_LEN 128
struct kernel_symbol {
	uint64_t addr;
	char name[MAX_SYMBOL_NAME_LEN];
};
static struct kernel_symbol *symbols = NULL;
static int symbol_count = 0;

/*
 * argp library setup for command-line parsing.
 */
static const char doc[] = "Trace high run queue latency using BPF.\n";
static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace a specific process ID (TGID)", 0 },
	{ "tid", 't', "TID", 0, "Trace a specific thread ID (PID)", 0 },
	{ "comm", 'c', "COMM", 0, "Trace a specific command name", 0 },
	{ "previous", 'P', NULL, 0, "Show previous task info", 0 },
	{ "prev-stack", 'S', NULL, 0, "Show previous task's kernel stack", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output from libbpf", 0 },
	{},
};

/*
 * Parser function for argp. It's called for each argument.
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'P':
		env.previous = true;
		break;
	case 'S':
		env.prev_stack = true;
		break;
	case 'p':
		env.pid = strtol(arg, NULL, 10);
		break;
	case 't':
		env.tid = strtol(arg, NULL, 10);
		break;
	case 'c':
		env.comm = arg;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++)
			argp_usage(state);
		env.min_us = strtoll(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/*
 * libbpf print callback. It's called by libbpf to print error and debug messages.
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

/*
 * Signal handler for graceful exit on Ctrl+C (SIGINT) and SIGTERM.
 */
static void sig_handler(int sig)
{
	exiting = true;
}

/*
 * Load kernel symbols from /proc/kallsyms into a sorted array for fast lookup.
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
	printf("Loaded %d kernel symbols.\n", symbol_count);
	return 0;
}

/*
 * Resolve a kernel address to a symbol name + offset using binary search on the loaded symbols.
 */
const char *resolve_kernel_symbol(uint64_t addr)
{
	static char symbol_str[MAX_SYMBOL_NAME_LEN + 32];

	if (symbol_count == 0)
		return "[kallsyms not loaded]";

	int left = 0, right = symbol_count - 1;
	int match_index = -1;

	// Binary search to find the closest symbol address that is less than or equal to addr
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

/*
 * Helper function to print a stack trace by looking up the stack ID in the BPF map.
 */
static void print_stack(struct my_runqslower_bpf *skel, int32_t stack_id)
{
	uint64_t ips[MAX_STACK_DEPTH] = {};
	int map_fd;

	if (stack_id <= 0)
		return;

	map_fd = bpf_map__fd(skel->maps.stack_traces);
	if (map_fd < 0) {
		fprintf(stderr, " failed to get stack_traces map fd\n");
		return;
	}

	if (bpf_map_lookup_elem(map_fd, &stack_id, ips) != 0) {
		fprintf(stderr, " failed to lookup stack trace for id %d\n", stack_id);
		return;
	}

	printf("  Kernel Stack for prev task:\n");
	for (int i = 0; i < MAX_STACK_DEPTH && ips[i]; i++) {
		printf("    #%-2d [<%016" PRIx64 ">] %s\n", i, ips[i],
		       resolve_kernel_symbol(ips[i]));
	}
}

/*
 * Callback function for handling events from the BPF ring buffer.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct my_runqslower_bpf *skel = ctx; // Retrieve the skeleton object from the context
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// Print the main event data
	if (env.previous) {
		printf("%-8s %-4d %-16s %-7d %-16s %-7d %-9s %10llu\n", ts, e->cpu, e->task, e->pid,
		       e->prev_task, e->prev_pid, e->was_involuntarily_switched ? "IVCSW" : "VCSW",
		       e->delta_us);
	} else {
		printf("%-8s %-4d %-16s %-7d %-9s %10llu\n", ts, e->cpu, e->task, e->pid,
		       e->was_involuntarily_switched ? "IVCSW" : "VCSW", e->delta_us);
	}

	// Conditionally print the stack trace
	if (env.prev_stack) {
		print_stack(skel, e->prev_stack_id);
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *btf_path = "/tmp/vmlinux.btf";
	static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = doc };
	struct ring_buffer *rb = NULL;
	struct my_runqslower_bpf *skel;
	int err;

	// Parse command-line arguments
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	// Set up libbpf logging
	libbpf_set_print(libbpf_print_fn);

	// Conditionally load kernel symbols if stack tracing is requested
	if (env.prev_stack) {
		if (load_kernel_symbols() != 0) {
			fprintf(stderr,
				"Warning: could not load kernel symbols. Stack traces will be addresses only.\n");
		}
	}

	// Open the BPF skeleton, using a custom BTF file if it exists
	if (access(btf_path, R_OK) == 0) {
		printf("Found custom BTF at %s, using it.\n", btf_path);
		LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = btf_path);
		skel = my_runqslower_bpf__open_opts(&opts);
	} else {
		printf("Custom BTF %s not found. Letting libbpf find one automatically.\n",
		       btf_path);
		skel = my_runqslower_bpf__open();
	}

	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Pass filters from user-space to the BPF program's .rodata section
	skel->rodata->min_us = env.min_us;
	skel->rodata->targ_pid = env.tid;
	skel->rodata->targ_tgid = env.pid;
	skel->rodata->targ_prev_stack = env.prev_stack;
	if (env.comm) {
		strncpy(skel->rodata->targ_comm, env.comm, TASK_COMM_LEN);
		skel->rodata->filter_comm = true;
	}

	// Load and verify BPF programs
	err = my_runqslower_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(errno));
		goto cleanup;
	}

	// Attach BPF programs to tracepoints
	err = my_runqslower_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// Set up the ring buffer for receiving events from the kernel
	// Pass 'skel' as the context, so the callback can access maps
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// Print table headers
	if (env.previous) {
		printf("%-8s %-4s %-16s %-7s %-16s %-7s %-9s %10s\n", "TIME", "CPU", "COMM", "TID",
		       "PREV_COMM", "PREV_TID", "LAST_SW", "LAT(us)");
	} else {
		printf("%-8s %-4s %-16s %-7s %-9s %10s\n", "TIME", "CPU", "COMM", "TID", "LAST_SW",
		       "LAT(us)");
	}

	// Set up signal handlers for graceful exit
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Main event polling loop
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
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
	// Clean up all resources before exiting
	ring_buffer__free(rb);
	my_runqslower_bpf__destroy(skel);
	free(symbols);
	return err < 0 ? -err : 0;
}