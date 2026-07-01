#include "bpf_helpers.h"
#include "profiler.h"

#define MAX_ENTRIES 10240
#define MAX_STACKS  10240

/* Raw instruction-pointer arrays, keyed by an id returned from
 * bpf_get_stackid(). Two calls per sample write into this same map: one
 * for the kernel stack, one (BPF_F_USER_STACK) for the user stack. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, PROFILER_MAX_STACK_DEPTH * sizeof(unsigned long long));
	__uint(max_entries, MAX_STACKS);
} stack_traces SEC(".maps");

/* sample_key -> sample count, drained and cleared by userspace once per
 * output interval. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sample_key);
	__type(value, unsigned long long);
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

/* Optional PID allowlist: tgid -> 1. Only consulted when `config`'s
 * filter_enabled flag is set (see below) - an empty map does not by
 * itself mean "profile everything", since a plain lookup miss can't
 * distinguish "map is empty" from "this tgid isn't targeted". */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned int);
	__type(value, unsigned char);
	__uint(max_entries, 1024);
} targets SEC(".maps");

/* Single-entry config: index 0 holds filter_enabled (0/1), written once
 * by userspace at startup depending on whether -p/--pid was passed. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, unsigned int);
	__type(value, unsigned int);
	__uint(max_entries, 1);
} config SEC(".maps");

SEC("perf_event")
int profile_cpu(void *ctx)
{
	unsigned long long pid_tgid = bpf_get_current_pid_tgid();
	unsigned int pid = (unsigned int)pid_tgid;
	unsigned int tgid = (unsigned int)(pid_tgid >> 32);

	unsigned int config_key = 0;
	unsigned int *filter_enabled = bpf_map_lookup_elem(&config, &config_key);
	if (filter_enabled && *filter_enabled) {
		if (!bpf_map_lookup_elem(&targets, &tgid))
			return 0;
	}

	struct sample_key key = {};
	key.pid = pid;
	key.tgid = tgid;
	key.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
	key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

	unsigned long long *count = bpf_map_lookup_elem(&counts, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		unsigned long long one = 1;
		bpf_map_update_elem(&counts, &key, &one, BPF_ANY);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
