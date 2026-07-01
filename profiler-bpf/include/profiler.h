#ifndef PROFILER_H
#define PROFILER_H

/*
 * Deliberately no `<stdint.h>` include: this header is compiled both by a
 * freestanding `clang -target bpf` (which, depending on the host's clang
 * install, can end up chaining into glibc's `<bits/libc-header-start.h>`
 * and failing to resolve it - freestanding BPF programs conventionally
 * avoid any libc header entirely) and by `bindgen` on the Rust side.
 * `unsigned int`/`int` are exactly 32 bits on every target this project
 * builds for, so plain C types are used instead of fixed-width typedefs.
 */

#define PROFILER_MAX_STACK_DEPTH 127

struct sample_key {
	unsigned int pid;  /* thread id (what the kernel calls pid) */
	unsigned int tgid; /* thread group id (what userspace calls pid) */
	int kern_stack_id;
	int user_stack_id;
};

#endif
