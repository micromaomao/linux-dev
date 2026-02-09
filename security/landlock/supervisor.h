/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Supervisor management for mutable domains
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#include <linux/bug.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>

#include "ruleset.h"

/**
 * struct landlock_supervisor - Supervisor state for mutable domains
 *
 * A supervisor allows dynamic modification of Landlock rules after a domain
 * has been enforced.  The supervisor process keeps the supervisor ruleset fd
 * and can add/remove rules.  Changes take effect after committing.
 */
struct landlock_supervisor {
	/**
	 * @lock: Protects access to @committed_ruleset and the user-accessible
	 * supervisor ruleset during rule modifications and commits.
	 */
	struct mutex lock;
	/**
	 * @usage: Reference count for this supervisor.  The supervisor ruleset
	 * and all supervisee rulesets (including those merged into domains)
	 * hold a reference.
	 */
	refcount_t usage;
	/**
	 * @committed_ruleset: The "live" ruleset containing committed rules.
	 * This is RCU-protected for lockless reads during access checks.
	 * On commit, a new ruleset is created and this pointer is swapped.
	 * The old ruleset is freed after an RCU grace period.
	 */
	struct landlock_ruleset __rcu *committed_ruleset;
};

struct landlock_supervisor *landlock_create_supervisor(void);
void landlock_put_supervisor(struct landlock_supervisor *supervisor);
int landlock_commit_supervisor(struct landlock_ruleset *ruleset);

static inline void
landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	WARN_ON_ONCE(!supervisor);
	refcount_inc(&supervisor->usage);
}

/**
 * landlock_get_supervisor_committed_ruleset_rcu - Get committed ruleset under RCU
 *
 * @supervisor: The supervisor to get the committed ruleset from.
 *
 * Returns the committed ruleset pointer for use in RCU read-side critical
 * sections.  Caller must be in an RCU read-side critical section.
 *
 * Returns: The committed ruleset (may be NULL if no rules committed).
 */
static inline struct landlock_ruleset *
landlock_get_supervisor_committed_ruleset_rcu(
	struct landlock_supervisor *supervisor)
{
	if (!supervisor)
		return NULL;

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
		"landlock_get_supervisor_committed_ruleset_rcu() requires RCU");
	return rcu_dereference(supervisor->committed_ruleset);
}

/**
 * landlock_get_supervisor_committed_ruleset - Get the committed ruleset
 *
 * @supervisor: The supervisor to get the committed ruleset from.
 *
 * Gets a reference to the committed ruleset for use in access checks.
 * Uses RCU to safely read the committed_ruleset pointer while it may be
 * concurrently updated by landlock_commit_supervisor().
 *
 * Returns: The committed ruleset (may be NULL if no rules committed),
 *          with an incremented reference count.
 */
static inline struct landlock_ruleset *
landlock_get_supervisor_committed_ruleset(struct landlock_supervisor *supervisor)
{
	struct landlock_ruleset *committed;

	if (!supervisor)
		return NULL;

	scoped_guard(rcu) {
		committed = rcu_dereference(supervisor->committed_ruleset);
		if (committed)
			landlock_get_ruleset(committed);
	}

	return committed;
}

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
