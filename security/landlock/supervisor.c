// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor management for mutable domains
 *
 * Copyright © 2024-2025 Microsoft Corporation
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include "ruleset.h"
#include "supervisor.h"

/**
 * landlock_create_supervisor - Create a new supervisor
 *
 * Creates a new supervisor structure with an empty committed ruleset.
 *
 * Returns: A newly allocated supervisor, or an error pointer.
 */
struct landlock_supervisor *landlock_create_supervisor(void)
{
	struct landlock_supervisor *supervisor;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL_ACCOUNT);
	if (!supervisor)
		return ERR_PTR(-ENOMEM);

	mutex_init(&supervisor->lock);
	refcount_set(&supervisor->usage, 1);
	RCU_INIT_POINTER(supervisor->committed_ruleset, NULL);

	return supervisor;
}

static void free_supervisor(struct landlock_supervisor *supervisor)
{
	struct landlock_ruleset *committed;

	WARN_ON_ONCE(!supervisor);
	/*
	 * If we get here, we have to be the last reference owner, and thus
	 * nobody else can be trying to update or read us committed_ruleset,
	 * so the following operation is safe.
	 */
	committed = rcu_dereference_protected(supervisor->committed_ruleset,
					      true);
	if (committed)
		landlock_put_ruleset(committed);

	kfree(supervisor);
}

void landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor && refcount_dec_and_test(&supervisor->usage))
		free_supervisor(supervisor);
}

/**
 * copy_rules_tree - Copy rules from a source tree to a destination ruleset
 *
 * @dst: Destination ruleset (must be locked by caller)
 * @src_root: Source rb_root to copy from
 * @key_type: Type of rules being copied (LANDLOCK_KEY_INODE or LANDLOCK_KEY_NET_PORT)
 *
 * Copies all rules from @src_root to @dst.  Each rule must have exactly one
 * layer at level 0 (single-layer ruleset requirement for supervisor rulesets).
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int copy_rules_tree(struct landlock_ruleset *dst,
			   struct rb_root *src_root,
			   const enum landlock_key_type key_type)
{
	struct landlock_rule *rule;
	struct rb_node *node;

	for (node = rb_first(src_root); node; node = rb_next(node)) {
		int err;

		rule = rb_entry(node, struct landlock_rule, node);

		/* Supervisor rulesets must be single-layer with level 0 */
		if (WARN_ON_ONCE(rule->num_layers != 1 ||
				 rule->layers[0].level != 0))
			return -EINVAL;

		{
			const struct landlock_id id = {
				.key = rule->key,
				.type = key_type,
			};

			err = landlock_insert_rule(dst, id,
						   rule->layers[0].access,
						   rule->layers[0].flags.quiet ?
						   LANDLOCK_ADD_RULE_QUIET : 0);
		}
		if (err)
			return err;
	}

	return 0;
}

/**
 * copy_ruleset_for_commit - Create a copy of a ruleset for committing
 *
 * @src: Source ruleset to copy from.
 *
 * Creates a new ruleset containing copies of all rules from @src.
 * The new ruleset is suitable for use as a committed supervisor ruleset.
 *
 * Returns: A newly allocated ruleset copy, or an error pointer.
 */
static struct landlock_ruleset *copy_ruleset_for_commit(
	struct landlock_ruleset *src)
{
	struct landlock_ruleset *dst;
	int err;

	/* Create a new single-layer ruleset */
	dst = landlock_create_ruleset(
		src->access_masks[0].fs,
		src->access_masks[0].net,
		src->access_masks[0].scope);
	if (IS_ERR(dst))
		return dst;

	/* Copy quiet masks */
	dst->quiet_masks = src->quiet_masks;

	mutex_lock(&dst->lock);

	/* Copy inode rules */
	err = copy_rules_tree(dst, &src->root_inode, LANDLOCK_KEY_INODE);

#if IS_ENABLED(CONFIG_INET)
	/* Copy network port rules */
	if (!err)
		err = copy_rules_tree(dst, &src->root_net_port,
				      LANDLOCK_KEY_NET_PORT);
#endif /* IS_ENABLED(CONFIG_INET) */

	mutex_unlock(&dst->lock);

	if (err) {
		landlock_put_ruleset(dst);
		return ERR_PTR(err);
	}

	return dst;
}

/**
 * landlock_commit_supervisor - Commit pending changes to supervisor
 *
 * @ruleset: The supervisor ruleset (not the committed ruleset).
 *
 * Atomically commits all pending rule changes from the user-accessible
 * supervisor ruleset to the committed ruleset.  After this call, access
 * checks against domains using this supervisor will see the new rules.
 *
 * The caller must ensure the current task is not under a domain that uses
 * this supervisor.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int landlock_commit_supervisor(struct landlock_ruleset *ruleset)
{
	struct landlock_supervisor *supervisor;
	struct landlock_ruleset *new_committed, *old_committed;

	if (!ruleset || !ruleset->supervisor)
		return -EINVAL;

	supervisor = ruleset->supervisor;

	/*
	 * Lock ordering: ruleset->lock before supervisor->lock.
	 *
	 * This lock ordering is safe because:
	 * 1. Only the supervisor ruleset (not domain rulesets) has a supervisor
	 *    pointer, so no conflict with domain locking paths.
	 * 2. Access checks use RCU to read committed_ruleset, not locks.
	 * 3. This function is the only code path that takes supervisor->lock,
	 *    so there is no risk of ABBA deadlock with any other code.
	 */
	mutex_lock(&ruleset->lock);
	mutex_lock_nested(&supervisor->lock, SINGLE_DEPTH_NESTING);

	/* Create a new copy of the current ruleset state */
	new_committed = copy_ruleset_for_commit(ruleset);
	if (IS_ERR(new_committed)) {
		mutex_unlock(&supervisor->lock);
		mutex_unlock(&ruleset->lock);
		return PTR_ERR(new_committed);
	}

	/* Swap the committed ruleset pointer */
	old_committed = rcu_dereference_protected(supervisor->committed_ruleset,
			lockdep_is_held(&supervisor->lock));
	rcu_assign_pointer(supervisor->committed_ruleset, new_committed);

	mutex_unlock(&supervisor->lock);
	mutex_unlock(&ruleset->lock);

	/* Wait for all readers to finish, then free the old ruleset */
	if (old_committed) {
		synchronize_rcu();
		landlock_put_ruleset(old_committed);
	}

	return 0;
}
