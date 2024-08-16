// SPDX-License-Identifier: GPL-2.0-only
/*
 * Restrict and execute specified command.
 * Run with -h flag to see sandboxer rules insertion format and supported
 * rule types.
 *
 * Copyright © 2024 Huawei Tech. Co., Ltd.
 */
#define _GNU_SOURCE

#include <linux/landlock.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <getopt.h>

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ACCESS_FILE                                                   \
	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
	 LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE | \
	 LANDLOCK_ACCESS_FS_IOCTL_DEV)

/* Cf. security/landlock/limits.h */
#define LANDLOCK_MAX_NUM_LAYERS 16
#define LANDLOCK_MAX_RULE (LANDLOCK_RULE_NET_PORT + 1)

#define STRTOPOLOGY_DELIM ":"

#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define STRBUF_MAXLEN 128

static struct {
	char path[STRBUF_MAXLEN];
	unsigned long long handled_access;
} landlock_topologies[LANDLOCK_MAX_RULE] = {};

static int get_ruleset_data_source(enum landlock_rule_type rule_type,
				   const char *strtopology)
{
	unsigned long long handled_access;
	char strtopology_buf[STRBUF_MAXLEN], *str_access, *str_file;

	assert(strlen(strtopology) < STRBUF_MAXLEN);

	strcpy(strtopology_buf, strtopology);
	str_access = strtopology_buf;
	str_file = strsep(&str_access, STRTOPOLOGY_DELIM);

	if (!str_file) {
		pr_warn("Landlock topology is partially specified\n");
		goto out;
	}

	strncpy(landlock_topologies[rule_type].path, str_file,
		sizeof(landlock_topologies[rule_type].path));

	/* errno is set in strtol() on error. */
	errno = 0;
	handled_access = (unsigned long long)strtol(str_access, NULL, 16);
	if (errno) {
		pr_warn("Failed trying to parse handled_access: %s\n",
			str_access);
		goto out;
	}
	landlock_topologies[rule_type].handled_access = handled_access;

	return 0;
out:
	return 1;
}

static int add_rule_from_str_fs(const char *strkey, const int ruleset_fd)
{
	int err = 1;
	struct stat statbuf;
	struct landlock_path_beneath_attr path_beneath;

	path_beneath.parent_fd = open(strkey, O_PATH | O_CLOEXEC);

	if (path_beneath.parent_fd < 0) {
		pr_warn("Failed to open \"%s\": %s\n", strkey, strerror(errno));
		goto cleanup;
	}
	if (fstat(path_beneath.parent_fd, &statbuf)) {
		pr_warn("Failed to stat \"%s\": %s\n", strkey, strerror(errno));
		goto cleanup;
	}
	path_beneath.allowed_access =
		landlock_topologies[LANDLOCK_RULE_PATH_BENEATH].handled_access;

	if (!S_ISDIR(statbuf.st_mode))
		path_beneath.allowed_access &= ACCESS_FILE;

	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
			      &path_beneath, 0)) {
		pr_warn("Failed to update the ruleset with \"%s\": %s\n",
			strkey, strerror(errno));
		goto cleanup;
	}
	err = 0;
cleanup:
	close(path_beneath.parent_fd);
	return err;
}

static int add_rule_from_str_net(const char *strkey, const int ruleset_fd)
{
	struct landlock_net_port_attr net_port;
	int port;

	/* errno is set in atoi() on error. */
	errno = 0;
	port = atoi(strkey);
	if (errno) {
		pr_warn("atoi() failed on %s\n", strkey);
		goto out;
	}

	net_port.port = port;
	net_port.allowed_access =
		landlock_topologies[LANDLOCK_RULE_NET_PORT].handled_access;

	if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_port,
			      0)) {
		pr_warn("Failed to update the ruleset with \"%s\": %s\n",
			strkey, strerror(errno));
		goto out;
	}
	return 0;
out:
	return 1;
}

static int landlock_init_topology_layer(const int ruleset_fd,
					enum landlock_rule_type rule_type,
					FILE *topology_fp, unsigned int n_layer,
					bool *changed)
{
	int err = 1;
	char *strrule = NULL, *strrule_parsed, *strrule_next;
	char *newline;
	size_t file_pos = 0;
	int n_rule_layer;
	int (*add_rule_from_str)(const char *strkey, const int ruleset_fd);

	switch (rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH:
		add_rule_from_str = add_rule_from_str_fs;
		break;
	case LANDLOCK_RULE_NET_PORT:
		add_rule_from_str = add_rule_from_str_net;
		break;
	default:
		assert(0 && "Incorrect rule_type");
	}

	fseek(topology_fp, 0, SEEK_SET);

	while (getline(&strrule, &file_pos, topology_fp) != -1) {
		strrule_parsed = strrule;

		newline = strchr(strrule_parsed, '\n');
		if (newline)
			*newline = 0;

		strrule_next = strsep(&strrule_parsed, " ");
		if (!strrule_next) {
			pr_warn("Failed to parse rule: \"%s\"\n", strrule);
			goto cleanup;
		}

		/* errno is set in atoi() on error. */
		errno = 0;
		n_rule_layer = atoi(strrule_next);
		if (errno) {
			pr_warn("atoi() failed on %s\n", strrule_next);
			goto cleanup;
		}

		if (n_rule_layer != n_layer)
			continue;
		if (n_rule_layer >= LANDLOCK_MAX_NUM_LAYERS) {
			pr_warn("Layer number exceeds the allowed value for the key: %s\n",
				strrule_next);
			goto cleanup;
		}

		if (add_rule_from_str(strrule_parsed, ruleset_fd))
			goto cleanup;

		*changed = true;
	}

	if (!feof(topology_fp)) {
		pr_warn("Failed to read lines from \"%s\"\n",
			landlock_topologies[rule_type].path);
		goto cleanup;
	}

	err = 0;
cleanup:
	free(strrule);
	return err;
}

static int landlock_do_sandboxing(void)
{
	int err = 1;
	int ruleset_fd;
	FILE *fp[LANDLOCK_MAX_RULE] = {};
	const char *path;
	unsigned int n_layer = 1;
	bool changed = true;

	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs =
			landlock_topologies[LANDLOCK_RULE_PATH_BENEATH]
				.handled_access,
		.handled_access_net =
			landlock_topologies[LANDLOCK_RULE_NET_PORT]
				.handled_access,
	};

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		pr_warn("Failed to create a ruleset: %s\n", strerror(errno));
		return 1;
	}

	for (int rule_type = 0; rule_type < LANDLOCK_MAX_RULE; rule_type++) {
		if (!landlock_topologies[rule_type].handled_access)
			continue;
		path = landlock_topologies[rule_type].path;
		fp[rule_type] = fopen(path, "r");
		if (!fp[rule_type]) {
			fprintf(stderr,
				"Failed to open topology fp \"%s\": %s\n", path,
				strerror(errno));
			goto cleanup;
		}
	}

	while (changed) {
		changed = false;

		for (int rule_type = 0; rule_type < LANDLOCK_MAX_RULE;
		     rule_type++) {
			if (!landlock_topologies[rule_type].handled_access)
				continue;
			if (landlock_init_topology_layer(ruleset_fd, rule_type,
							 fp[rule_type], n_layer,
							 &changed))
				goto cleanup;
		}

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			pr_warn("Failed to restrict privileges: %s\n",
				strerror(errno));
			goto cleanup;
		}
		if (landlock_restrict_self(ruleset_fd, 0)) {
			pr_warn("Failed to enforce ruleset\n");
			goto cleanup;
		}
		n_layer++;
	}

	err = 0;
cleanup:
	for (int rule_type = 0; rule_type < LANDLOCK_MAX_RULE; rule_type++) {
		if (fp[rule_type])
			fclose(fp[rule_type]);
	}

	close(ruleset_fd);
	return err;
}

int main(const int argc, char *const argv[])
{
	int c, longind = -1;
	const char *cmd = NULL;
	enum landlock_rule_type rule_type;

	static struct option options[] = {
		{ "fs", required_argument, NULL, 'f' },
		{ "net", required_argument, NULL, 'n' },
		{ "help", optional_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((c = getopt_long(argc, argv, "f:n:h", options, &longind)) !=
	       -1) {
		if (longind == -1) {
			pr_warn("%s: invalid option -- \'%s\'\n", argv[0],
				argv[optind - 1]);
			goto out;
		}
		switch (c) {
		case 'f':
			rule_type = LANDLOCK_RULE_PATH_BENEATH;
			get_ruleset_data_source(rule_type, optarg);
			break;
		case 'n':
			rule_type = LANDLOCK_RULE_NET_PORT;
			get_ruleset_data_source(rule_type, optarg);
			break;
		case 'h':
			pr_warn("Usage: %s [-{fs|net} FILE:ACCESS]\n"
				"\n"
				"* FILE contains lines of following format: \"NR KEY\\n\" (e.g. \"1 /usr/bin/find\").\n"
				"  When sandboxing, a rule on the NR layer with ACCESS access_mask will be added\n"
				"  for each key KEY\n"
				"* ACCESS is a binary string. Sets handled_access for ruleset and access_mask\n"
				"  for each key\n",
				argv[0]);
			goto out;
		}

		/* Next argument is workload. */
		if (optind < argc && *argv[optind] != '-')
			break;
		longind = -1;
	}

	if (optind >= argc) {
		pr_warn("Command is not specified\n");
		goto out;
	}
	if (landlock_do_sandboxing())
		goto out;

	cmd = argv[optind];
	execv(cmd, argv + optind);

	pr_warn("Failed to execute \"%s\": %s\n", cmd, strerror(errno));
	pr_warn("Hint: access to the binary, the interpreter or "
		"shared libraries may be denied.\n");
out:
	return 1;
}
