/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LANDLOCK_BENCH_COMMON_H
#define LANDLOCK_BENCH_COMMON_H

#include <stdio.h>
#include <linux/landlock.h>

#define STRBUF_MAXLEN 128

extern void set_ruleset_config(enum landlock_rule_type rule_type,
			       const char *topology_file,
			       unsigned long long access_right);

extern int landlock_do_sandboxing(void);

#define pr_warn(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#endif
