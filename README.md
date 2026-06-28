# eBPF Flame Graph Profiler

![Language](https://img.shields.io/badge/language-C%20%2B%20eBPF-blue)
![Kernel](https://img.shields.io/badge/Linux%20kernel-5.8%2B-orange?logo=linux&logoColor=white)
![Toolchain](https://img.shields.io/badge/toolchain-clang%20%2B%20libbpf-blueviolet)
![CO--RE](https://img.shields.io/badge/CO--RE-BTF--enabled-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

A low-overhead, system-wide CPU profiler that uses eBPF to sample call stacks across all processes at configurable frequency, resolves instruction pointers to human-readable symbols, and renders interactive SVG flame graphs — with no instrumentation of target programs, no kernel module, and no dependency on `perf` or BCC.

Architecturally: an eBPF program attached to `perf_event_open` hardware cycle events captures kernel and user-space stacks on every CPU at each sample. A user-space daemon reads the BPF maps, resolves symbols from `/proc/kallsyms`, ELF symbol tables, DWARF unwind info, and JIT perf-map files, then emits folded stacks that are either piped into Brendan Gregg's `flamegraph.pl` or rendered natively to a self-contained, interactive SVG with no external dependencies.

The profiler supports both **frame-pointer unwinding** (fast, requires `-fno-omit-frame-pointer`) and **DWARF-based unwinding** (works on any binary, reads unwind tables from the process's ELF files in user space), **off-CPU profiling** (scheduler blocking latency, not just on-CPU time), and **differential flame graphs** (visualizing regressions between two profiles).

## Table of Contents

- [How It Works](#how-it-works)
  - [eBPF Sampling Program](#ebpf-sampling-program)
  - [BPF Map Design](#bpf-map-design)
  - [Symbol Resolution](#symbol-resolution)
  - [Stack Unwinding](#stack-unwinding)
  - [Flame Graph Rendering](#flame-graph-rendering)
- [Off-CPU Profiling](#off-cpu-profiling)
- [Differential Flame Graphs](#differential-flame-graphs)
- [Repository Layout](#repository-layout)
- [Building](#building)
- [Usage](#usage)
- [Testing](#testing)
- [Overhead](#overhead)
- [Design Decisions](#design-decisions)
- [Non-Goals and Known Limitations](#non-goals-and-known-limitations)
- [References](#references)

## How It Works

```text
  CPU hardware cycle event (every N cycles, or every M Hz)
         │
         ▼  (perf_event_open, attached per-CPU)
  ┌──────────────────────────────────────────┐
  │         eBPF sampling program            │
  │  (runs in kernel context, < 1 µs)        │
  │                                          │
  │  bpf_get_current_pid_tgid()              │
  │  bpf_get_stackid() → kernel stack ID     │
  │  bpf_get_stackid() → user stack ID       │
  │  increment counts[pid, kstack, ustack]++ │
  └────────────┬─────────────────────────────┘
               │  BPF maps (in kernel memory)
               │  ┌──────────────────────────────┐
               │  │ BPF_MAP_TYPE_STACK_TRACE      │
               │  │  stack_id → [ip0, ip1, ...]   │
               │  │                               │
               │  │ BPF_MAP_TYPE_HASH             │
               │  │  (pid, kstack_id, ustack_id)  │
               │  │  → sample count               │
               │  └──────────────────────────────┘
               │
               ▼  (read periodically by user-space daemon)
  ┌──────────────────────────────────────────┐
  │         User-space daemon (C/libbpf)     │
  │                                          │
  │  drain BPF maps                          │
  │  resolve IPs → symbols                   │
  │   kernel: /proc/kallsyms                 │
  │   user:   /proc/<pid>/maps + ELF         │
  │           DWARF CFI (if no frame ptr)    │
  │           /tmp/perf-<pid>.map (JIT)      │
  │  fold stacks into "a;b;c count" lines    │
  └────────────────┬─────────────────────────┘
                   │
                   ▼
  ┌──────────────────────────────────────────┐
  │  SVG Flame Graph (self-contained)        │
  │  or speedscope JSON                      │
  │  or folded text (for flamegraph.pl)      │
  └──────────────────────────────────────────┘
```

### eBPF Sampling Program

The BPF program is a `BPF_PROG_TYPE_PERF_EVENT` program attached to a `perf_event_open(2)` event opened with:

```c
struct perf_event_attr attr = {
    .type        = PERF_TYPE_SOFTWARE,
    .config      = PERF_COUNT_SW_CPU_CLOCK,
    .freq        = 1,          // use .sample_freq, not .sample_period
    .sample_freq = 99,         // 99 Hz — avoids lock-step with 100 Hz kernel timer
    .sample_type = PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER,
};
```

99 Hz rather than 100 Hz is deliberate: a 100 Hz profiler sampling in lock-step with the kernel's 100 Hz jiffy timer systematically over- or under-samples code that runs in sync with timer interrupts (periodic housekeeping, `sleep(10ms)` loops). A prime-ish frequency breaks that synchronization.

One `perf_event_open` file descriptor is opened per online CPU and the same BPF program is attached to each, so every CPU is sampled independently. The BPF program runs with interrupts disabled in a non-preemptible context; it must complete quickly and may not sleep or allocate memory.

### BPF Map Design

Three maps, all created with `bpf_map_create`:

**`stack_traces` (`BPF_MAP_TYPE_STACK_TRACE`).**
The kernel's built-in stack-trace map: `bpf_get_stackid(ctx, &stack_traces, flags)` walks the call stack, stores the array of instruction pointers as a value, and returns an integer stack ID as the key. Two separate calls — one with `BPF_F_USER_STACK` for the user-space stack, one without for the kernel stack — give independent IDs. The map's value size is `max_stack_depth * sizeof(u64)` (default: 127 frames × 8 bytes = 1016 bytes per entry).

**`counts` (`BPF_MAP_TYPE_HASH`).**
Maps `struct sample_key { u32 pid; u32 tgid; s32 kern_stack_id; s32 user_stack_id; }` to a `u64` sample count, updated with `bpf_map_update_elem` using `BPF_ANY`. The user-space daemon drains this map once per output interval, aggregating all samples seen since the last drain into folded stack strings.

**`targets` (`BPF_MAP_TYPE_HASH`).**
Optional: maps `u32 pid → u8 1` for targeted profiling (profile only listed PIDs). If the map is empty, all processes are profiled. The BPF program does a single `bpf_map_lookup_elem` on `targets` and returns early if the current PID is absent. This keeps the BPF hot path O(1) and avoids filtering overhead in user space.

### Symbol Resolution

Symbol resolution maps raw instruction pointers back to `function_name+offset (file:line)` strings. It happens entirely in user space; the BPF program only captures raw `u64` addresses.

**Kernel symbols.** `/proc/kallsyms` lists every kernel and module symbol with its virtual address. The daemon reads this file once at startup into a sorted array and binary-searches it per IP. Addresses between two consecutive entries are attributed to the lower symbol at `symbol+offset`. Kernel ASLR (`CONFIG_RANDOMIZE_BASE`) is transparent because `/proc/kallsyms` always reflects the current runtime addresses, not link-time addresses.

**User-space symbols.** For each unique PID seen in a drain cycle the daemon reads `/proc/<pid>/maps` to find which ELF file and load offset back each virtual address. It then opens the ELF binary (or shared library), parses the `.symtab` or `.dynsym` section (preferring `.symtab` for full non-exported symbols), and binary-searches the sorted symbol table. The resolved name is cached in a per-binary symbol cache keyed by `(device, inode)` so the same library shared across hundreds of processes is parsed only once.

**JIT-compiled code.** The JVM, V8, and similar runtimes write symbol maps to `/tmp/perf-<pid>.map` (one `addr size name` line per JIT-compiled method). The daemon watches for these files at startup and reloads them every drain cycle, since the JIT continuously emits new methods. Stacks landing inside a JIT region are resolved via these maps; unresolved regions fall back to `[unknown]`.

**Inlined functions.** When the target binary retains DWARF debug info, the daemon optionally walks the DWARF `.debug_info` and `.debug_line` sections to expand inlined frames — a single instruction pointer can expand to a chain of inlined call sites. This is opt-in (`--inline`) because it is significantly slower and requires `libdw` or a bundled DWARF parser.

### Stack Unwinding

There are two strategies for recovering the call stack from an instruction pointer:

**Frame-pointer unwinding (default).** On x86-64, the System V ABI convention reserves `rbp` as the frame pointer — a linked list through the stack where each frame's `rbp` points to the caller's saved `rbp` at `[rbp+0]` and the return address is at `[rbp+8]`. Walking this chain gives the call stack in O(depth) pointer dereferences. The BPF helper `bpf_get_stackid` uses exactly this mechanism. The catch: `gcc` and `clang` both omit frame pointers by default (`-fomit-frame-pointer`) as an optimization. Code compiled without frame pointers produces incomplete or incorrect stacks.

**DWARF CFI unwinding (user space, `--dwarf`).** DWARF Call Frame Information (`.eh_frame` / `.debug_frame`) encodes, for every instruction in a function, a table of rules describing how to recover each callee-saved register and the return address from the current stack state — no frame pointer required. The daemon implements a DWARF CFI interpreter that reads these tables from the target's ELF and shared libraries via `/proc/<pid>/mem` (accessing the target's memory without `ptrace`), reconstructing each frame in the call chain. This is slower than frame-pointer unwinding (requires parsing CFI tables and reading remote memory per frame) but works on any production binary compiled with `-O2 -g` or even with just `.eh_frame` for C++ exception handling.

**ORC (kernel only).** For kernel stacks the profiler uses the kernel's own ORC (Oops Rewind Capability) unwinder metadata, exposed through the BPF stack-trace map; `bpf_get_stackid` invokes it automatically for kernel frames.

### Flame Graph Rendering

The daemon produces **folded stacks** — one line per unique call path seen during the interval:

```
main;__libc_start_main;work;compute;fft_radix2 412
main;__libc_start_main;work;io_wait;epoll_wait 87
swapper/0;[kernel];do_idle;cpuidle_enter 203
```

Each line is a semicolon-separated call chain (outermost frame first) followed by the sample count. This format is the canonical input for Brendan Gregg's `flamegraph.pl`, but the profiler also includes a native SVG renderer so there is no Perl dependency. The SVG renderer:

- Sorts frames by total sample count for stable left-to-right ordering across profiles of the same workload.
- Embeds JavaScript for interactive zoom (click a frame to zoom), search (highlight frames matching a regex), and tooltip display (count and percentage of total samples).
- Color-codes frames by layer: kernel frames in orange, user frames in blue, JIT frames in green, unknown frames in grey.

A second output mode is **speedscope JSON** (`--format=speedscope`), loadable at `speedscope.app` for a richer timeline-based view.

## Off-CPU Profiling

On-CPU profiling captures where the CPU *is* spending time. Off-CPU profiling captures where threads *are not* running — time spent blocked in the kernel scheduler waiting for I/O, a mutex, a futex, or a sleep. These are often the source of latency problems that on-CPU profiles miss entirely.

The off-CPU profiler attaches a `BPF_PROG_TYPE_TRACEPOINT` program to the `sched:sched_switch` tracepoint. On each context switch it records the timestamp and user+kernel stack of the outgoing thread in a `BPF_MAP_TYPE_HASH` keyed by thread ID. When that thread is switched back in (a second `sched_switch` fires with this thread as the incoming task), the BPF program computes the off-CPU duration and emits a `(stack, duration_ns)` record to a `BPF_MAP_TYPE_RINGBUF`. The user-space daemon reads the ring buffer, aggregates by folded stack weighted by duration (not sample count), and produces an off-CPU flame graph.

On-CPU and off-CPU profiles can be merged into a single **CPU time flame graph** that shows both active and blocked time, making latency sources visible alongside CPU consumption.

## Differential Flame Graphs

A differential flame graph subtracts one profile from another to highlight regressions. The profiler produces a differential output by reading two folded-stack files (a "before" and an "after" profile) and computing the signed difference in sample counts per unique call path. Frames that grew are colored red (proportional to growth), frames that shrank are colored blue, and unchanged frames are grey. This is the standard technique for visualizing the effect of a code change on CPU usage.

```sh
flamegraph-profiler record -p <pid> -d 30 -o before.folded
# deploy new code
flamegraph-profiler record -p <pid> -d 30 -o after.folded
flamegraph-profiler diff before.folded after.folded -o diff.svg
```

## Repository Layout

```text
.
├── src/
│   ├── bpf/
│   │   ├── profiler.bpf.c        # eBPF sampling program (compiled to BPF bytecode)
│   │   └── offcpu.bpf.c          # eBPF off-CPU tracepoint program
│   ├── profiler.c                # User-space daemon: map drain, perf event setup
│   ├── symbols.c / symbols.h     # Symbol resolution: kallsyms, ELF, DWARF, perf-map
│   ├── unwind.c / unwind.h       # DWARF CFI interpreter for --dwarf mode
│   ├── folded.c / folded.h       # Folded-stack aggregation and emission
│   ├── svg.c / svg.h             # Native SVG flame graph renderer
│   ├── speedscope.c              # Speedscope JSON serializer
│   └── diff.c                    # Differential flame graph computation
├── include/
│   ├── profiler.h                # Shared kernel/user structs (BPF map key types)
│   └── vmlinux.h                 # CO-RE: full kernel type definitions (BTF-generated)
├── tests/
│   ├── unit/                     # Symbol resolver, SVG renderer, folded-stack parser
│   └── integration/              # End-to-end: profile a known workload, assert output
├── tools/
│   └── gen-vmlinux.sh            # Regenerate vmlinux.h from a running kernel's BTF
├── examples/
│   ├── cpu-bound.c               # Sample workload: recursive Fibonacci
│   ├── io-bound.c                # Sample workload: epoll + file I/O
│   └── sample.svg                # Example flame graph output
├── CMakeLists.txt
├── Makefile
└── README.md
```

## Building

Dependencies: `clang` ≥ 14, `libbpf` ≥ 1.0, `libelf`, `linux-headers`. Optional: `libdw` for `--inline` DWARF inlining support.

```sh
# Ubuntu / Debian
apt-get install clang llvm libbpf-dev libelf-dev linux-headers-$(uname -r)

make           # builds BPF bytecode with clang + user-space daemon with gcc/clang
make install   # installs flamegraph-profiler to /usr/local/bin
```

The BPF program is compiled with:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I include/ \
      -c src/bpf/profiler.bpf.c \
      -o profiler.bpf.o
```

CO-RE (Compile Once, Run Everywhere) is enabled via `vmlinux.h` — a single header generated from the running kernel's BTF (BPF Type Format) metadata that contains all kernel struct definitions. The BPF program uses `BPF_CORE_READ()` macros to read kernel structs portably; the BPF verifier rewrites field offsets at load time to match the target kernel's actual layout. This means the compiled `.bpf.o` runs on any kernel ≥ 5.8 that has BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`), without recompilation per kernel version.

## Usage

Profile all processes system-wide for 30 seconds at 99 Hz:

```sh
sudo flamegraph-profiler record -d 30 -o profile.svg
# opens profile.svg in browser, or:
sudo flamegraph-profiler record -d 30 --format=folded | flamegraph.pl > profile.svg
```

Profile a single process by PID:

```sh
sudo flamegraph-profiler record -p $(pgrep postgres) -d 10 -o postgres.svg
```

Profile with DWARF unwinding (no frame pointers required):

```sh
sudo flamegraph-profiler record -p <pid> --dwarf -d 10 -o profile.svg
```

Off-CPU profiling (blocked time):

```sh
sudo flamegraph-profiler record -p <pid> --offcpu -d 10 -o offcpu.svg
```

Combined on-CPU + off-CPU:

```sh
sudo flamegraph-profiler record -p <pid> --oncpu --offcpu -d 10 -o combined.svg
```

Differential flame graph:

```sh
sudo flamegraph-profiler diff before.folded after.folded -o diff.svg
```

List all sampled processes with their total sample count from the last run:

```sh
flamegraph-profiler report --summary profile.folded
# PID    COMM           SAMPLES  %
# 1234   postgres       4821     38.4%
# 5678   nginx          2103     16.7%
# ...
```

## Testing

```sh
make test          # unit + integration tests
make test-valgrind # user-space components under valgrind
```

**Unit tests** cover the symbol resolver (kallsyms binary search, ELF `.symtab` parsing, perf-map lookup, cache correctness after binary reload), the DWARF CFI interpreter (hand-crafted `.eh_frame` fixtures covering common CFA rules: `DW_CFA_def_cfa`, `DW_CFA_offset`, `DW_CFA_register`, `DW_CFA_remember_state`), the SVG renderer (frame geometry, color assignment, JS embedding), and the differential computation (sign, proportional coloring, zero-count pruning).

**Integration tests** compile `examples/cpu-bound.c` with known call depth and symbol names, profile it for 5 seconds, parse the resulting folded stacks, and assert that:
- The expected call chain appears in the top-N stacks.
- The sample count is within ±15% of the expected proportion at 99 Hz over 5 seconds.
- Every sampled IP resolves to a non-`[unknown]` symbol (frame-pointer mode; the binary is compiled with `-fno-omit-frame-pointer`).
- The SVG is valid XML and contains the expected function name strings.

A separate integration test runs the off-CPU profiler against `examples/io-bound.c` (which spends most of its time blocked in `epoll_wait`) and asserts that `epoll_wait` appears prominently in the off-CPU flame graph rather than the on-CPU one.

## Overhead

The profiler's overhead comes from two sources: the BPF program running on every sample (in-kernel, nanosecond-range), and the user-space daemon draining and symbolizing maps (once per output interval, off the hot path).

At 99 Hz across 8 CPUs, the BPF program fires ≈ 792 times per second. Each invocation executes `bpf_get_stackid` twice plus a hash map update — roughly 500–800 ns of kernel time per sample. At 8 CPUs this adds up to < 0.1% CPU overhead for the BPF program itself.

The user-space daemon drains maps once per second by default. Symbol resolution is cached per binary; after warm-up (all binaries seen at least once), each drain cycle resolves symbols from the cache in < 5 ms. The SVG render adds another 5–20 ms for typical profiles (< 50k unique stacks). The daemon's own CPU consumption is < 0.5% of one core during a 1-second drain.

| Mode | BPF overhead | Daemon overhead | Total |
|---|---|---|---|
| 99 Hz, 8 CPUs, frame-pointer | ~0.07% CPU | < 0.5% CPU | **< 0.6%** |
| 99 Hz, 8 CPUs, DWARF unwinding | ~0.07% CPU | 1–3% CPU | **< 3.1%** |
| Off-CPU (`sched_switch`) | < 0.1% CPU | < 0.5% CPU | **< 0.6%** |

DWARF unwinding is more expensive in the daemon because it must read `/proc/<pid>/mem` for each unique frame in each unique stack — memory reads that bypass the cache on cold stacks. Frame-pointer mode is recommended for continuous production profiling; DWARF mode for targeted investigations of binaries without frame pointers.

These numbers compare favorably with `perf record` at the same frequency, which has higher user-space overhead due to mmap ring buffer I/O and copying raw `PERF_RECORD_SAMPLE` events. The BPF aggregation model does the stack de-duplication in kernel space, so the user-space daemon processes unique stacks rather than every raw sample.

## Design Decisions

**Aggregate in the kernel, not user space.** An alternative design streams every raw sample to user space via a perf ring buffer and aggregates there. This is simpler but transmits O(samples × stack_depth × 8) bytes per second. At 99 Hz × 8 CPUs × 64 frames × 8 bytes, that is ≈ 4 MB/s of raw data — and de-duplication in user space requires building the same hash map that the BPF map already provides. Aggregating counts in a `BPF_MAP_TYPE_HASH` in the kernel transmits only unique stacks × 8 bytes per drain cycle, which for a typical server is orders of magnitude less data. The trade-off is that the BPF map has a fixed max-entries limit; an unusually diverse workload with millions of unique stacks can fill it. The daemon detects map-full conditions and reports them.

**99 Hz over higher frequencies.** Higher sampling frequencies (999 Hz, 9999 Hz) reduce statistical noise but increase overhead super-linearly: both the BPF program fires more often and the drain cycle must process more accumulated samples. At 99 Hz, 30-second profiles reliably surface any function consuming ≥ 0.3% of CPU time. 999 Hz would surface 0.03%, but the overhead cost is 10× higher. Brendan Gregg's original CPU profiling work established 99 Hz as the practical sweet spot, and this profiler's default follows that reasoning.

**CO-RE over BCC.** BCC (BPF Compiler Collection) compiles BPF programs at runtime using LLVM as a library, which requires Python, LLVM headers, and kernel headers on the target machine, and adds 100–500 ms of startup latency. CO-RE with libbpf compiles the BPF program once at build time; the `.bpf.o` is embedded in the binary and loaded in < 10 ms at runtime. The target machine needs only a BTF-enabled kernel — no compiler, no headers, no Python.

**Frame-pointer unwinding as default, DWARF as opt-in.** DWARF unwinding is correct on more binaries but is substantially more expensive (remote memory reads). Frame-pointer mode works reliably on any binary compiled with `-fno-omit-frame-pointer`, which includes the Linux kernel itself, most Go binaries (Go 1.12+ re-enables frame pointers by default), and any C/C++ binary built with the flag. It fails silently on `-fomit-frame-pointer` binaries, producing truncated stacks rather than an error. DWARF mode is exposed as an explicit opt-in so users can choose the trade-off consciously.

**Native SVG over `flamegraph.pl` dependency.** Requiring Perl to render output adds a dependency that is absent on many production hosts and containers. The native SVG renderer is ~400 lines of C that produces functionally equivalent output and eliminates the dependency entirely. The flamegraph.pl-compatible folded-stack output is still available for users who prefer the Perl tool or want to use alternative renderers.

## Non-Goals and Known Limitations

- **No support for kernels < 5.8.** `BPF_MAP_TYPE_RINGBUF` (used by the off-CPU profiler) requires 5.8+. CO-RE requires BTF, available since 5.2 but commonly enabled in distributions only from 5.8 onward. Pre-BTF kernels would need a different portability approach (kernel headers at build time), which is out of scope.
- **No allocation profiling.** This profiler captures CPU time and scheduler blocking time but not heap allocation frequency or size. An allocation profiler would attach to `malloc`/`free` via uprobes or use `bpf_override_return` to intercept allocator paths — a separate, higher-overhead mechanism.
- **No cross-machine aggregation.** Each invocation profiles one host. Aggregating profiles across a fleet (for distributed flame graphs) requires a separate collection layer (pushing folded-stack files to a central store and merging them), which is out of scope.
- **DWARF unwinding reads `/proc/<pid>/mem` without `ptrace`.** This works when the profiler runs as root (the typical case). It does not work on kernels where `/proc/<pid>/mem` is restricted to `ptrace`-attached processes (`kernel.yama.ptrace_scope = 2` or higher).
- **JIT symbol files must pre-exist.** The profiler reads `/tmp/perf-<pid>.map` at daemon startup and refreshes it every drain cycle. JIT methods compiled after the last refresh appear as `[unknown]` until the next refresh. This is an inherent limitation of the perf-map protocol: the JVM/V8 writes symbols asynchronously.
- **No Windows or macOS support.** eBPF on Linux is the only supported platform. macOS's DTrace-based `dtrace` and Windows's ETW are different subsystems requiring entirely different implementations.

## References

- Brendan Gregg. [Flame Graphs](https://www.brendangregg.com/flamegraphs.html). — the original flame graph methodology, folded-stack format, and `flamegraph.pl`.
- Brendan Gregg. [Systems Performance: Enterprise and the Cloud](https://www.brendangregg.com/systems-performance-2nd-edition-book.html). Addison-Wesley, 2020. — eBPF profiling, off-CPU analysis, and USE methodology.
- Brendan Gregg. [BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html). Addison-Wesley, 2019. — comprehensive reference for BPF-based observability tools.
- Andrii Nakryiko. [BPF CO-RE (Compile Once, Run Everywhere)](https://nakryiko.com/posts/bpf-core-reference-guide/). — BTF-based portability, `BPF_CORE_READ`, and `vmlinux.h`.
- Andrii Nakryiko. [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap). — minimal CO-RE skeleton used as the structural starting point for this project.
- Linux kernel. [`kernel/bpf/stackmap.c`](https://github.com/torvalds/linux/blob/master/kernel/bpf/stackmap.c). — `BPF_MAP_TYPE_STACK_TRACE` implementation and `bpf_get_stackid` helper.
- DWARF Standards Committee. [DWARF Debugging Information Format, Version 5](https://dwarfstd.org/doc/DWARF5.pdf). — Call Frame Information (§6.4) used by the DWARF unwinder.
- Josh Stone. [ORC Unwinder](https://www.kernel.org/doc/html/latest/arch/x86/orc-unwinder.html). Linux kernel documentation. — kernel ORC unwind tables used for kernel stack unwinding.
- Meta. [Katran](https://github.com/facebookincubator/katran). — production XDP-based load balancer; illustrates the eBPF ecosystem this profiler sits alongside.

## License

MIT License. See [LICENSE](LICENSE) for details.
