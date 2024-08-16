// SPDX-License-Identifier: GPL-2.0-only
/*
 * Attach BPF programs to syscall tracepoints, launch workload and show
 * gathered statistics.
 *
 * Copyright © 2024 Huawei Tech. Co., Ltd.
 */

#include <bpf/libbpf.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <time.h>
#include <linux/bpf.h>
#include <math.h>

#include "tracer.skel.h"
#include "common.h"
#include "tracer_common.h"

#define ARG_MAX 32

#define max(x, y) ((x) > (y) ? (x) : (y))
#define ns2ms(ns) ((long double)(ns) / (1000 * 1000))

#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define SYS_ENTER_PREFIX "sys_enter_"
#define SYS_EXIT_PREFIX "sys_exit_"
#define SYS_PREFIX_MAXLEN sizeof(SYS_ENTER_PREFIX)

#define SYS_DELIM ","

static int attach_bpf_progs(struct tracer *skel, const char *strsys)
{
	struct bpf_link *bpf_link;
	char strsys_buf[STRBUF_MAXLEN], *strsys_parsed, *strsys_next;
	char str_tracepoint[STRBUF_MAXLEN + SYS_PREFIX_MAXLEN];

	assert(strlen(strsys) < STRBUF_MAXLEN);
	strcpy(strsys_buf, strsys);
	strsys_parsed = strsys_buf;

	while ((strsys_next = strsep(&strsys_parsed, SYS_DELIM))) {
		strcpy(str_tracepoint, SYS_ENTER_PREFIX);
		strcat(str_tracepoint, strsys_next);
		bpf_link = bpf_program__attach_tracepoint(
			skel->progs.sys_enter, "syscalls", str_tracepoint);
		if (!bpf_link) {
			pr_warn("BPF attaching failed for syscall \"%s\": %s\n",
				strsys_next, strerror(errno));
			goto err_out;
		}

		strcpy(str_tracepoint, SYS_EXIT_PREFIX);
		strcat(str_tracepoint, strsys_next);
		bpf_link = bpf_program__attach_tracepoint(
			skel->progs.sys_exit, "syscalls", str_tracepoint);
		if (!bpf_link) {
			pr_warn("BPF attaching failed for syscall \"%s\": %s\n",
				strsys_next, strerror(errno));
			goto err_out;
		}
	}

	return 0;

err_out:
	return 1;
}

static const char col_entity_name[] = "";
static const char col_samples_name[] = "samples";
static const char col_duration_avg_name[] = "duration AVG(ns)";
static const char col_duration_name[] = "duration(ms)";
static const char col_stddev_name[] = "stddev(%)";

static const int col_entity_pad = 35;
static const int col_samples_pad = max(14, sizeof(col_samples_name));
static const int col_duration_avg_pad = max(12, sizeof(col_duration_avg_name));
static const int col_duration_pad = max(13, sizeof(col_duration_name));
static const int col_stddev_pad = max(10, sizeof(col_duration_name));

void show_stat_header(FILE *output)
{
	fprintf(output, "%*s %*s %*s %*s %*s\n", col_entity_pad,
		col_entity_name, col_samples_pad, col_samples_name,
		col_duration_avg_pad, col_duration_avg_name, col_duration_pad,
		col_duration_name, col_stddev_pad, col_stddev_name);
}

void show_syscall_stat(FILE *output, long syscall_nr,
		       struct tracer_stat_data *stat)
{
	char name[STRBUF_MAXLEN];
	double variance, variance_mean;
	double stddev = 0;

	assert(snprintf(name, sizeof(name), "syscall-%ld", syscall_nr) >= 0);

	/* Cf. tools/perf/util/stat.c */
	if (stat->samples >= 2 && stat->mean) {
		variance = (double)stat->M2 / (stat->samples - 1);
		variance_mean = variance / stat->samples;

		stddev = 100.0 * sqrt(variance_mean) / stat->mean;
	}

	fprintf(output, "%-*s %*u %*llu %*.3Lf %*.2lf%%\n", col_entity_pad,
		name, col_samples_pad, stat->samples, col_duration_avg_pad,
		stat->mean, col_duration_pad - 1, ns2ms(stat->duration),
		col_stddev_pad, stddev);
}

static int dump_bench_results(struct tracer *skel, const char *output)
{
	int err = 1;
	int sys_map_fd;
	struct tracer_stat_data sys_stat;
	FILE *output_file;

	if (!output)
		output_file = stderr;
	else {
		output_file = fopen(output, "w");
		if (!output_file) {
			pr_warn("Failed to open output file \"%s\": %s\n",
				output, strerror(errno));
			goto out;
		}
	}

	sys_map_fd = bpf_map__fd(skel->maps.sys_stats);
	if (sys_map_fd < 0) {
		pr_warn("Failed to get fd from BPF map \"sys_stats\"\n");
		goto out;
	}

	show_stat_header(output_file);
	for (int syscall_nr = 0; syscall_nr < NR_SYSCALLS; syscall_nr++) {
		err = bpf_map__lookup_elem(skel->maps.sys_stats, &syscall_nr,
					   sizeof(syscall_nr), &sys_stat,
					   sizeof(sys_stat), 0);
		if (err) {
			pr_warn("Failed to extract stat from BPF map \"sys_stat\" for syscall[%d]\n",
				syscall_nr);
			goto out;
		}
		if (!sys_stat.samples)
			continue;

		show_syscall_stat(output_file, syscall_nr, &sys_stat);
	}
	err = 0;
out:
	if (output_file && output_file != stderr)
		fclose(output_file);
	return err;
}

int msleep(int msec)
{
	int err;
	struct timespec ts;

	ts.tv_sec = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;

	do {
		err = nanosleep(&ts, &ts);
	} while (err && errno == EINTR);

	if (err)
		pr_warn("nanosleep failed: %s\n", strerror(errno));
	return err;
}

// TODO: syscalls to string

int main(const int argc, char *const argv[])
{
	int c, child, status;
	const char *strsys = NULL, *output = NULL, *cmd;
	struct tracer *skel = NULL;
	int init_duration = 0;

	while ((c = getopt(argc, argv, "e:o:D:h")) != -1) {
		switch (c) {
		case 'e':
			strsys = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'D':
			errno = 0;
			init_duration = atoi(optarg);
			if (errno) {
				pr_warn("atoi() failed on %s\n", optarg);
				goto cleanup;
			}
			break;
		case 'h':
			pr_warn("Usage: %s [OPTIONS] [WORKLOAD_CMD]\n"
				"Run WORKLOAD_CMD and trace number and duration of syscalls\n"
				"\n"
				"Options:\n"
				"  -e TRACED_SYSCALLS  specify syscalls which would be traced while benchmarking\n"
				"  -o FILE             redirect result output into FILE\n"
				"  -D MSECS            wait MSECS msecs before tracing sandboxed workload\n",
				argv[0]);
			break;
		}

		/* Next argument is workload. */
		if (optind < argc && *argv[optind] != '-')
			break;
	}

	if (optind >= argc) {
		pr_warn("Command is not specified\n");
		goto cleanup;
	}

	if (!strsys) {
		pr_warn("Syscall list is not specified\n");
		goto cleanup;
	}

	skel = tracer__open_and_load();
	if (!skel) {
		pr_warn("BPF skeleton loading failed: %s\n", strerror(errno));
		goto cleanup;
	}

	cmd = argv[optind];

	child = fork();
	if (child < 0) {
		pr_warn("Failed to fork child workload process: \"%s\"\n",
			strerror(errno));
		goto cleanup;
	}

	if (child == 0) {
		skel->bss->target_pid = getpid();

		execv(cmd, argv + optind);

		pr_warn("Failed to execute \"%s\": %s\n", cmd, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	if (msleep(init_duration))
		goto cleanup;

	if (attach_bpf_progs(skel, strsys))
		goto cleanup;

	if (waitpid(child, &status, 0) != child)
		pr_warn("\"%s\" execution failed: %s\n", cmd, strerror(errno));

	if (dump_bench_results(skel, output))
		goto cleanup;
	return 0;
cleanup:
	tracer__destroy(skel);
	return 1;
}
