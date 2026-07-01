#ifndef PROFILER_BPF_HELPERS_H
#define PROFILER_BPF_HELPERS_H

/*
 * Minimal, vendored subset of libbpf-style BPF C conventions: the SEC()
 * section-naming convention, the BTF-based declarative map-definition
 * macros, and the handful of helper-function declarations this profiler
 * needs. Kept local and small so the BPF program has no dependency on a
 * system libbpf/libelf install - only clang with the `bpf` target.
 *
 * Helper ids below are the stable numeric ids from the kernel's UAPI
 * `enum bpf_func_id` (include/uapi/linux/bpf.h) - not toolchain-specific.
 *
 * Deliberately no `<stdint.h>` include: freestanding `clang -target bpf`
 * builds can end up chaining into glibc headers that don't resolve in
 * freestanding mode, depending on the host's clang install. `unsigned
 * int`/`unsigned long long` are exactly 32/64 bits on every target this
 * project builds for.
 */

#define SEC(name) __attribute__((section(name), used))

/* BTF-based map definition helpers: the pointee type/value is never
 * dereferenced, only its *type* is recorded via debug info and read by
 * the loader (aya/libbpf) at load time to construct the real map. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* enum bpf_map_type (subset used by this profiler) */
#define BPF_MAP_TYPE_HASH        1
#define BPF_MAP_TYPE_ARRAY       2
#define BPF_MAP_TYPE_STACK_TRACE 7

/* bpf_map_update_elem flags */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* bpf_get_stackid flags */
#define BPF_F_USER_STACK ((unsigned long long)1 << 8)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) =
	(void *) 2;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) 14;
static long (*bpf_get_stackid)(void *ctx, void *map, unsigned long long flags) =
	(void *) 27;

#endif
