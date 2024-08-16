/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LANDLOCK_BENCH_TRACER_COMMON_H
#define LANDLOCK_BENCH_TRACER_COMMON_H

#define NR_SYSCALLS 1024
#define MAX_TASKS 100000

struct tracer_stat_data {
	long long M2;
	long long mean;
	unsigned long long duration;
	unsigned int samples;
};

#endif
