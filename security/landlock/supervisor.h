/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - mutable domains and supervisor support
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#ifdef CONFIG_SECURITY_LANDLOCK_SUPERVISE

#include <linux/bug.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>

#include "ruleset.h"
#include "domain.h"

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

	RCU_LOCKDEP_WARN(
		!rcu_read_lock_held(),
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

/**
 * struct supervisor_committed_cache - Pre-captured supervisor committed rulesets
 *
 * This structure holds pointers to supervisor committed rulesets that were
 * captured at the start of an access check.  This ensures atomicity of the
 * access check with respect to supervisor commits - a commit that happens
 * during the pathwalk won't cause inconsistent results.
 *
 * The extra 128 bytes of stack space (16 pointers) is the tradeoff for
 * atomicity.
 */
struct supervisor_committed_cache {
	struct landlock_ruleset *rulesets[LANDLOCK_MAX_NUM_LAYERS];
};

void landlock_capture_supervisor_committed(
	const struct landlock_domain *const domain,
	struct supervisor_committed_cache *cache);

void landlock_release_supervisor_committed(
	struct supervisor_committed_cache *cache);

bool landlock_check_supervisor_access(
	const struct landlock_domain *const domain,
	const struct landlock_id id,
	struct layer_masks *const layer_masks,
	const struct supervisor_committed_cache *cache);

#endif /* CONFIG_SECURITY_LANDLOCK_SUPERVISE */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
