#!/usr/bin/env bash
# Regenerate profiler-bpf/include/vmlinux.h from the running kernel's BTF.
#
# Not required by the current on-CPU sampling program (it only calls stable
# BPF helpers with primitive-typed arguments, so it needs no kernel struct
# definitions). This becomes necessary once code that reads kernel struct
# fields is added - e.g. an off-CPU profiler reading task_struct fields off
# the sched:sched_switch tracepoint via BPF_CORE_READ. Must run on Linux.
set -euo pipefail

OUT="$(cd "$(dirname "$0")/.." && pwd)/profiler-bpf/include/vmlinux.h"

command -v bpftool >/dev/null || {
	echo "bpftool not found; install linux-tools-\$(uname -r) or the bpftool package" >&2
	exit 1
}

test -r /sys/kernel/btf/vmlinux || {
	echo "/sys/kernel/btf/vmlinux not readable; kernel needs CONFIG_DEBUG_INFO_BTF=y" >&2
	exit 1
}

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
echo "wrote $OUT"
