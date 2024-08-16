// SPDX-License-Identifier: GPL-2.0
/*
 * BPF programs for benchmarking data collection.
 *
 * Copyright © 2024 Huawei Tech. Co., Ltd.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../tracer_common.h"

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

char _license[] SEC("license") = "GPL";

struct syscall_enter_args {
	unsigned long long common_tp_fields;
	long syscall_nr;
	unsigned long args[6];
};

struct syscall_exit_args {
	unsigned long long common_tp_fields;
	long syscall_nr;
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct tracer_stat_data);
	__uint(max_entries, NR_SYSCALLS);
} sys_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, unsigned long long);
	__uint(max_entries, MAX_TASKS);
} sys_enter_timestamp SEC(".maps");

int target_pid;

static inline bool is_target(struct task_struct *task)
{
	bool res = false;

	bpf_rcu_read_lock();

	/* Accumulates data only for target process or it's child. */
	while (task && task->pid != target_pid)
		task = task->real_parent;
	if (task)
		res = true;

	bpf_rcu_read_unlock();
	return res;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct syscall_enter_args *args)
{
	pid_t pid;
	unsigned long long timestamp;
	struct task_struct *task;

	task = bpf_get_current_task_btf();

	if (!is_target(task))
		return 0;

	pid = task->pid;
	timestamp = bpf_ktime_get_ns();
	bpf_map_update_elem(&sys_enter_timestamp, &pid, &timestamp, 0);
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct syscall_exit_args *args)
{
	pid_t pid;
	struct tracer_stat_data *stat;
	unsigned long long *enter_timestamp, exit_timestamp, duration;
	long long delta;
	long syscall_nr;
	struct task_struct *task;

	exit_timestamp = bpf_ktime_get_ns();

	task = bpf_get_current_task_btf();
	if (!is_target(task))
		return 0;

	pid = task->pid;
	enter_timestamp = bpf_map_lookup_elem(&sys_enter_timestamp, &pid);
	if (!enter_timestamp)
		return 0;

	syscall_nr = args->syscall_nr;

	stat = bpf_map_lookup_elem(&sys_stats, &syscall_nr);
	if (stat) {
		duration = exit_timestamp - *enter_timestamp;

		/* Cf. tools/perf/util/stat.c */
		stat->samples++;

		delta = (long long)duration - stat->mean;

		stat->duration += duration;

		/* EBPF doesn't support signed division */
		if (delta > 0)
			stat->mean += (unsigned long long)delta / stat->samples;
		else
			stat->mean -= (unsigned long long)(-delta) / stat->samples;

		stat->M2 += delta * (duration - stat->mean);
		bpf_map_update_elem(&sys_stats, &syscall_nr, stat, 0);
	}
	return 0;
}
