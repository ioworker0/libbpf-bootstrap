#!/bin/bash
# FINAL load.sh for split-object loading

set -e
set -x

# Define paths for BPF objects and pinned files
BPF_FS_PATH="/tmp1/bpf"
CGROUP_PATH="/tmp1/cgroupv2"

SOCKOPS_OBJ="examples/c/.output/loopback-sockops.bpf.o"
REDIR_OBJ="examples/c/.output/loopback-redir.bpf.o"

SOCKOPS_PIN_PATH="${BPF_FS_PATH}/bpf_sockops"
REDIR_PIN_PATH="${BPF_FS_PATH}/bpf_redir"
MAP_PIN_PATH="${BPF_FS_PATH}/sock_map"

# Cleanup function to be called on script exit
cleanup() {
    echo ">>> Cleaning up pinned BPF objects..."
    bash -c "echo 0 > /sys/kernel/debug/tracing/tracing_on"
    bpftool cgroup detach ${CGROUP_PATH} sock_ops pinned ${SOCKOPS_PIN_PATH}
    bpftool prog detach pinned ${REDIR_PIN_PATH} msg_verdict pinned ${MAP_PIN_PATH}
    unlink ${SOCKOPS_PIN_PATH}
    unlink ${REDIR_PIN_PATH}
    unlink ${MAP_PIN_PATH}
    echo ">>> Cleanup complete."
}
trap cleanup EXIT

# 1. Mount BPF filesystem
echo ">>> Mounting BPF filesystem..."
ls ${BPF_FS_PATH} || mkdir -p ${BPF_FS_PATH}
mount -t bpf bpf ${BPF_FS_PATH} || echo "BPF FS already mounted."

echo ">>> Mounting Cgroup v2 filesystem..."
ls ${CGROUP_PATH} || mkdir -p ${CGROUP_PATH}
mount -t cgroup2 none ${CGROUP_PATH} || echo "Cgroup v2 already mounted."

# 2. Load the sockops program and its map
echo ">>> Loading sockops program and creating the master sock_map..."
# This command loads the program, and `pinmaps` creates and pins the map.
bpftool prog load ${SOCKOPS_OBJ} ${SOCKOPS_PIN_PATH} type sockops pinmaps ${BPF_FS_PATH}

# 3. Attach the sockops program to the cgroup
echo ">>> Attaching sockops program to cgroup..."
bpftool cgroup attach ${CGROUP_PATH} sock_ops pinned ${SOCKOPS_PIN_PATH}

# 4. Load the redirect program, REUSING the pinned map
echo ">>> Loading redirect program and reusing the master sock_map..."
# This is the key: we point `map name sock_map` to the `pinned` path of the existing map.
bpftool prog load ${REDIR_OBJ} ${REDIR_PIN_PATH} map name sock_map pinned ${MAP_PIN_PATH}

# 5. Attach the redirect program to the pinned map
echo ">>> Attaching redirect program to the master sock_map..."
bpftool prog attach pinned ${REDIR_PIN_PATH} msg_verdict pinned ${MAP_PIN_PATH}

echo ">>> BPF programs loaded and attached successfully!"
echo ">>> Clearing trace buffer and tailing kernel trace pipe for output. Press Ctrl+C to exit."
echo "--------------------------------------------------------"

# 6. Clear the main kernel trace buffer
bash -c "echo > /sys/kernel/debug/tracing/trace"
bash -c "echo 1 > /sys/kernel/debug/tracing/tracing_on"

# 7. Tail the trace pipe to see output
cat /sys/kernel/debug/tracing/trace_pipe
