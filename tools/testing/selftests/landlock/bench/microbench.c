// SPDX-License-Identifier: GPL-2.0-only
/*
 * Microbenchmark syscall workload.
 *
 * Copyright © 2024 Huawei Tech. Co., Ltd.
 */

#include <time.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/landlock.h>
#include <assert.h>

#include "common.h"

#define SYS_DELIM ","

static const char topology_file[] = ".topology";

static void run_openat(int samples)
{
	int fd;

	while (samples--) {
		fd = open("/dev/zero", O_RDONLY);
		close(fd);
	}
}

static const struct {
	const char name[STRBUF_MAXLEN];
	const char descr[STRBUF_MAXLEN];
	enum landlock_rule_type rule_type;
	unsigned long long access;
	const char landlock_topology[10 * STRBUF_MAXLEN];
	void (*run)(int samples);
} workload_protos[] = {
	{
		.name = "openat",
		.descr =
			"open /dev/zero file with O_RDONLY and immediately close it",
		.rule_type = LANDLOCK_RULE_PATH_BENEATH,
		.access = LANDLOCK_ACCESS_FS_READ_FILE,
		.landlock_topology = "1 /dev/zero\n",
		.run = run_openat,
	},
};

static const int n_workload_protos =
	sizeof(workload_protos) / sizeof(*workload_protos);

static int dump_topology(int n_proto)
{
	int err = 0;
	FILE *fp = NULL;
	const char *topology;
	size_t bytes_to_write;

	fp = fopen(topology_file, "w");

	if (!fp) {
		pr_warn("Unable to open file %s\n", topology_file);
		goto out;
	}

	topology = workload_protos[n_proto].landlock_topology;
	bytes_to_write = strlen(topology);

	if (bytes_to_write !=
	    fwrite(topology, sizeof(char), bytes_to_write, fp)) {
		pr_warn("Failed to dump topology into %s\n", topology_file);
		goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

static int sandbox_proto(int n_proto)
{
	int err = 1;

	err = dump_topology(n_proto);
	if (err)
		goto out;

	set_ruleset_config(workload_protos[n_proto].rule_type, topology_file,
			   workload_protos[n_proto].access);

	err = landlock_do_sandboxing();
	if (err)
		goto out;

	err = 0;
out:
	return err;
}

int main(const int argc, char *const argv[])
{
	int c, samples = -1, err = 1;
	int is_sandbox = 0;
	const char *strsys = NULL;
	struct timespec start, finish;
	unsigned long long duration, sample_duration;

	while ((c = getopt(argc, argv, "n:e:sh")) != -1) {
		switch (c) {
		case 'n':
			/* errno is set in atoi() on error. */
			errno = 0;
			samples = atoi(optarg);
			if (errno) {
				pr_warn("atoi() failed on %s\n", optarg);
				goto out;
			}
			break;
		case 'e':
			strsys = optarg;
			break;
		case 's':
			is_sandbox = 1;
			break;
		case 'h':
			pr_warn("Usage: %s [OPTIONS]\n"
				"\n"
				"Options:\n"
				"  -n SAMPLES            number of syscall samples to execute\n"
				"  -e SYSCALL_LIST       specify syscalls which would be used as workload\n"
				"\n"
				"Following cases are implemented:\n",
				argv[0]);

			for (int i = 0; i < n_workload_protos; i++) {
				pr_warn("* %s\t%s\n", workload_protos[i].name,
					workload_protos[i].descr);
			}
			pr_warn("\n");
			goto out;
		}
	}

	if (!strsys) {
		pr_warn("Syscalls are not specified\n");
		goto out;
	}

	if (samples < 1) {
		pr_warn("Samples are not specified\n");
		goto out;
	}

	for (int i = 0; i < n_workload_protos; i++) {
		if (strcmp(strsys, workload_protos[i].name) == 0) {

			if (is_sandbox) {
				if (sandbox_proto(i))
					goto out;
			}

			assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,
					     &start) == 0);
			workload_protos[i].run(samples);
			assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,
					     &finish) == 0);

			duration = finish.tv_sec - start.tv_sec;
			duration *= 1000000000ULL;
			duration += finish.tv_nsec - start.tv_nsec;

			sample_duration = duration / samples;

			pr_warn("%llu ns/sample\n", sample_duration);
			break;
		}
	}

	err = 0;
out:
	return err;
}
