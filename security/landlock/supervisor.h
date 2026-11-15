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

#include "ruleset.h"

/**
 * struct landlock_committed_supervisor_rules - dynamic set of rules,
 *         allowed and quieted permissions committed to a supervisor.
 *
 * This is effectively a stripped down struct landlock_ruleset, without the
 * (unneeded by supervisor) refcount, lock, id and handled accesses.
 */
struct landlock_committed_supervisor_rules {
	/**
	 * @rules: Red-black tree storage for rules.
	 */
	struct landlock_rules rules;
	/**
	 * @allowed_permission: Additional permissions allowed by this layer.
	 */
	struct permission_masks allowed_permission;
	/**
	 * @quiet_permission: Additional permissions quieted by this layer.
	 */
	struct permission_masks quiet_permission;
};

/**
 * struct landlock_supervisor - Shared state between a supervisor ruleset
 * and a supervisee ruleset or domain
 */
struct landlock_supervisor {
	/**
	 * @usage: Reference count for this structure.
	 */
	refcount_t usage;
	/**
	 * @lock: Guard updates to @committed_rules.
	 */
	struct mutex lock;
	/**
	 * @committed_rules: A RCU-protected container of "live" rules for this
	 * supervisor.  On update, a new copy is created and this pointer is
	 * swapped, with the old struct freed after an RCU grace period.
	 */
	struct landlock_committed_supervisor_rules __rcu *committed_rules;
};

struct landlock_supervisor *landlock_create_supervisor(void);
void landlock_put_supervisor(struct landlock_supervisor *supervisor);

static inline void
landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	if (WARN_ON_ONCE(!supervisor))
		return;

	refcount_inc(&supervisor->usage);
}

int landlock_commit_supervisor(struct landlock_ruleset *ruleset);

#endif /* CONFIG_SECURITY_LANDLOCK_SUPERVISE */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
