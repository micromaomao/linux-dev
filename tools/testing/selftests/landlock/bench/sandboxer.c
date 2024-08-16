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
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "common.h"

#define STRTOPOLOGY_DELIM ":"

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

	/* errno is set in strtol() on error. */
	errno = 0;
	handled_access = (unsigned long long)strtol(str_access, NULL, 16);
	if (errno) {
		pr_warn("Failed trying to parse handled_access: %s\n",
			str_access);
		goto out;
	}

	set_ruleset_config(rule_type, str_file, handled_access);
	return 0;
out:
	return 1;
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
