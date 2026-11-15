/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - mutable domains and supervisor support
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#ifdef CONFIG_SECURITY_LANDLOCK_SUPERVISE

#include <linux/refcount.h>
#include <linux/slab.h>

/**
 * struct landlock_supervisor - Shared state between a supervisor ruleset
 * and a supervisee ruleset or domain
 */
struct landlock_supervisor {
	/**
	 * @usage: Reference count for this structure.
	 */
	refcount_t usage;
};

struct landlock_supervisor *landlock_create_supervisor(void);

static inline void
landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	if (WARN_ON_ONCE(!supervisor))
		return;

	refcount_inc(&supervisor->usage);
}

static inline void
landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor && refcount_dec_and_test(&supervisor->usage))
		kfree(supervisor);
}

#endif /* CONFIG_SECURITY_LANDLOCK_SUPERVISE */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
