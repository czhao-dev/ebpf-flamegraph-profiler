/*
 * A deliberately recursive, CPU-bound workload for exercising the profiler.
 * Build with frame pointers so frame-pointer stack unwinding can recover the
 * full call chain:
 *
 *   cc -O2 -fno-omit-frame-pointer -o cpu_bound cpu_bound.c
 *
 * Then, in another terminal:
 *
 *   sudo flamegraph-profiler record -p $(pgrep cpu_bound) -d 5 --format=folded
 */
#include <stdio.h>

static long long fib(int n)
{
	if (n < 2)
		return n;
	return fib(n - 1) + fib(n - 2);
}

int main(void)
{
	for (;;) {
		volatile long long result = fib(30);
		(void)result;
	}
	return 0;
}
