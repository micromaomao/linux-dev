/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - mutable domains and supervisor support
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>

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

	refcount_set(&supervisor->usage, 1);

	return supervisor;
}

/**
 * landlock_commit_supervisor - Change the dynamic rules of a supervisor.
 *
 * @ruleset: The supervisor ruleset.  This is given to the supervisor user
 *           process from the initial landlock_create_ruleset() call.
 *
 * Atomically copy all rules and permissions from the user-accessible
 * supervisor ruleset to the committed rules of the supervisor
 * corresponding to it.  After this call, access checks against domains
 * using this supervisor will see the new rules.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int landlock_commit_supervisor(struct landlock_ruleset *ruleset)
{
	struct landlock_supervisor *supervisor;
	struct landlock_committed_supervisor_rules *new_rules, *old_rules;
	int err;

	if (!ruleset || !ruleset->layer.supervisor)
		return -EINVAL;

	supervisor = ruleset->layer.supervisor;
	new_rules = create_committed_supervisor_rules();

	mutex_lock(&ruleset->lock);

	err = landlock_copy_rules(&new_rules->rules, &ruleset->rules);
	if (err) {
		mutex_unlock(&ruleset->lock);
		/* We haven't exposed new_rules yet, no need to synchronize_rcu */
		put_committed_supervisor_rules(new_rules);
		return err;
	}

	old_rules = rcu_replace_pointer(supervisor->committed_rules, new_rules,
					lockdep_is_held(&ruleset->lock));

	/* TODO: remove on submission */
	trace_printk("committed = %p\n", new_rules);
	{
		struct rb_node *node;

		trace_printk("landlock: dumping inode rules:\n");
		for (node = rb_first(&new_rules->rules.root_inode); node;
		     node = rb_next(node)) {
			struct landlock_rule *rule =
				rb_entry(node, struct landlock_rule, node);
			u32 i;

			trace_printk("  rule key=0x%lx num_layers=%u\n",
				     (unsigned long)rule->key.data,
				     rule->num_layers);
			for (i = 0; i < rule->num_layers; i++) {
				trace_printk(
					"    layer[%u]: level=%u access=0x%llx quiet=%d\n",
					i, rule->layers[i].level,
					(unsigned long long)rule->layers[i]
						.access,
					rule->layers[i].flags.quiet);
			}
		}
#if IS_ENABLED(CONFIG_INET)
		trace_printk("landlock: dumping net_port rules:\n");
		for (node = rb_first(&new_rules->rules.root_net_port); node;
		     node = rb_next(node)) {
			struct landlock_rule *rule =
				rb_entry(node, struct landlock_rule, node);
			u32 i;

			trace_printk("  rule key=0x%lx num_layers=%u\n",
				     (unsigned long)rule->key.data,
				     rule->num_layers);
			for (i = 0; i < rule->num_layers; i++) {
				trace_printk(
					"    layer[%u]: level=%u access=0x%llx quiet=%d\n",
					i, rule->layers[i].level,
					(unsigned long long)rule->layers[i]
						.access,
					rule->layers[i].flags.quiet);
			}
		}
#endif /* IS_ENABLED(CONFIG_INET) */
	}

	mutex_unlock(&ruleset->lock);

	/* Wait for all readers to finish, then free the old ruleset */
	if (old_rules) {
		synchronize_rcu();
		put_committed_supervisor_rules(old_rules);
	}

	return 0;
}
