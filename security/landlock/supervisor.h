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

#include "ruleset.h"

/**
 * struct landlock_committed_supervisor_rules - dynamic set of rules,
 *            allowed and quieted permissions committed to a supervisor.
 *
 * This is effectively a stripped down struct landlock_ruleset, without the
 * (unneeded by supervisor) lock, id and handled accesses.
 */
struct landlock_committed_supervisor_rules {
	/**
	 * @usage: Reference count for this structure to keep it alive outside
	 * of RCU.
	 */
	refcount_t usage;
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
 * create_committed_supervisor_rules - Allocate and initialize an empty
 *                                     committed rules structure.
 */
static inline struct landlock_committed_supervisor_rules *
create_committed_supervisor_rules(void)
{
	struct landlock_committed_supervisor_rules *rules;

	rules = kzalloc(sizeof(*rules), GFP_KERNEL_ACCOUNT);
	if (!rules)
		return NULL;
	rules->rules.root_inode = RB_ROOT;

#if IS_ENABLED(CONFIG_INET)
	rules->rules.root_net_port = RB_ROOT;
#endif /* IS_ENABLED(CONFIG_INET) */

	refcount_set(&rules->usage, 1);
	return rules;
}

/**
 * put_committed_supervisor_rules - Release a reference to committed rules
 *                                  without synchronizing RCU.
 */
static inline void put_committed_supervisor_rules(
	struct landlock_committed_supervisor_rules *rules)
{
	if (!rules)
		return;

	if (refcount_dec_and_test(&rules->usage))
		kfree(rules);
}

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
	 * @committed_rules: A RCU-protected container of "live" rules for this
	 * supervisor.  On update, a new copy is created and this pointer is
	 * swapped, with the old struct freed after an RCU grace period.
	 *
	 * This field may be NULL if no rules have been committed yet.
	 */
	struct landlock_committed_supervisor_rules __rcu *committed_rules;
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
	struct landlock_committed_supervisor_rules *committed;

	if (supervisor && refcount_dec_and_test(&supervisor->usage)) {
		/*
		* Since we are the last reference owner, nobody else can be trying
		* to update or read our committed_rules, so we can just free it
		* without locking.
		*/
		committed = rcu_dereference_protected(
			supervisor->committed_rules, true);
		put_committed_supervisor_rules(committed);

		kfree(supervisor);
	}
}

int landlock_commit_supervisor(struct landlock_ruleset *ruleset);

#endif /* CONFIG_SECURITY_LANDLOCK_SUPERVISE */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
