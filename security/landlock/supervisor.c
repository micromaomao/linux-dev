/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - mutable domains and supervisor support
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>

#include "ruleset.h"
#include "domain.h"
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

/**
 * landlock_capture_supervisor_committed - Pre-capture supervisor rulesets
 *
 * Captures the committed rulesets from all supervisors in the domain's
 * hierarchy.  This should be called at the start of an access check (before
 * pathwalk) to ensure atomicity - a supervisor commit during pathwalk won't
 * cause inconsistent results where some path components use the old ruleset
 * and others use the new one.
 *
 * @domain: The domain
 * @cache: Output structure to store captured ruleset pointers (stack-allocated)
 */
void landlock_capture_supervisor_committed(
	const struct landlock_domain *const domain,
	struct supervisor_committed_cache *cache)
{
	struct landlock_hierarchy *hierarchy;
	size_t layer_level;

	memset(cache, 0, sizeof(*cache));

	if (!domain || !domain->hierarchy)
		return;

	hierarchy = domain->hierarchy;

	scoped_guard(rcu) {
		for (layer_level = domain->num_layers; layer_level > 0;
		     layer_level--) {
			const size_t layer_idx = layer_level - 1;
			struct landlock_ruleset *committed;

			if (!hierarchy)
				break;

			if (hierarchy->supervisor) {
				committed =
					landlock_get_supervisor_committed_ruleset_rcu(
						hierarchy->supervisor);
				if (committed)
					landlock_get_ruleset(committed);
				cache->rulesets[layer_idx] = committed;
			}

			hierarchy = hierarchy->parent;
		}
	}
}

/**
 * landlock_release_supervisor_committed - Release captured supervisor rulesets
 *
 * @cache: The cache to release.
 *
 * Decrements the reference count on all captured rulesets.  Must be called
 * after landlock_capture_supervisor_committed() when the cache is no longer
 * needed.
 */
void landlock_release_supervisor_committed(
	struct supervisor_committed_cache *cache)
{
	size_t i;

	for (i = 0; i < LANDLOCK_MAX_NUM_LAYERS; i++) {
		if (cache->rulesets[i])
			landlock_put_ruleset(cache->rulesets[i]);
	}
}

/**
 * landlock_check_supervisor_access - Check if supervisor rulesets allow access
 *
 * When the supervisee ruleset denies access for certain layers, this function
 * checks if the supervisor rulesets for those layers allow the access.
 *
 * For an access to be allowed by supervisors:
 * 1. Each denying layer must have a supervisor with a committed ruleset
 * 2. Each supervisor's committed ruleset must have a rule that allows the
 *    requested access for the given object
 *
 * @domain: The domain (used for hierarchy traversal)
 * @id: The object identifier to check access for
 * @layer_masks: Per-layer masks of unfulfilled access rights (modified in place)
 * @cache: Pre-captured supervisor rulesets (NULL to fetch on demand, which is
 *         less atomic but still works for single-point checks)
 *
 * Returns: true if all unfulfilled accesses are satisfied by supervisor
 *          rulesets, false otherwise.
 */
bool landlock_check_supervisor_access(
	const struct landlock_domain *const domain,
	const struct landlock_id id,
	struct layer_masks *const layer_masks,
	const struct supervisor_committed_cache *cache)
{
	struct landlock_hierarchy *hierarchy;
	size_t layer_level;
	char single_layer_rule[struct_size_t(struct landlock_rule, layers,
					     1)] = { 0 };
	struct landlock_rule *modified_rule =
		(struct landlock_rule *)single_layer_rule;
	bool allowed = true;

	if (!domain || !domain->hierarchy || !layer_masks)
		return false;

	/*
	 * Traverse the hierarchy from the newest layer to the oldest.
	 * The hierarchy is a linked list where the current domain's
	 * hierarchy corresponds to layer num_layers, and each parent
	 * corresponds to the previous layer.
	 */
	hierarchy = domain->hierarchy;

	for (layer_level = domain->num_layers; layer_level > 0; layer_level--) {
		const size_t layer_idx = layer_level - 1;
		access_mask_t unfulfilled;
		struct landlock_ruleset *committed;
		const struct landlock_rule *rule;

		if (!hierarchy) {
			/*
			 * This shouldn't happen - there should be as many
			 * hierarchy nodes as layers.
			 */
			WARN_ON_ONCE(1);
			return false;
		}

		unfulfilled = layer_masks->layers[layer_idx].access;
		if (!unfulfilled) {
			/* This layer is already satisfied, check next */
			hierarchy = hierarchy->parent;
			continue;
		}

		/*
		 * Use pre-captured committed ruleset if available, otherwise
		 * fetch on demand (less atomic but works for single checks).
		 */
		 // TODO: get rid of this branching, if we need cache let's always
		 // pass in cache
		if (cache) {
			committed = cache->rulesets[layer_idx];
		} else {
			struct landlock_supervisor *supervisor =
				hierarchy->supervisor;
			if (!supervisor) {
				/*
				 * This layer denied access but has no supervisor,
				 * so there's no way to override.
				 */
				return false;
			}
			committed =
				landlock_get_supervisor_committed_ruleset_rcu(
					supervisor);
		}

		if (!committed) {
			/*
			 * Supervisor doesn't exist or has no committed rules, which
			 * means no rules allow access => this layer denies, and
			 * therefore we don't need to check other layers anymore.
			 */
			return false;
		}

		/* TODO: remove on submission */
		trace_printk("layer %zu: committed = %p\n", layer_idx,
			     committed);

		// TODO: new changes has made this not available to us, we need to
		// either refactor or manually search through the rb tree here.
		rule = find_rule(committed, id);
		if (!rule) {
			/* No rule for this object in supervisor ruleset */
			/* TODO: remove on submission */
			trace_printk("no rule for inode %p\n", id.key.object);
			return false;
		}
		/* TODO: remove on submission */
		trace_printk(
			"yes rule for inode %p, num_layers = %u, access = %x\n",
			id.key.object, rule->num_layers,
			rule->num_layers > 0 ? rule->layers[0].access : 0);

		/*
		 * Check if the supervisor rule grants all the unfulfilled
		 * access rights.  Supervisor rules only have one layer at
		 * level 0.
		 */
		if (WARN_ON_ONCE(rule->num_layers != 1)) {
			return false;
		}

		modified_rule->num_layers = 1;
		modified_rule->layers[0] = rule->layers[0];
		/*
		 * The level in rules in the committed ruleset are all 0 since it's
		 * a ruleset, but in order for landlock_unmask_layers to do the
		 * right thing it needs to have the layer index of the current
		 * (supervised) layer we're looking at
		 */
		modified_rule->layers[0].level = layer_level;

		/* TODO: extract what's inside the layer for loop in
		 * landlock_unmask_layers to another function and use that */
		// TODO: fix rebase
		if (!landlock_unmask_layers(modified_rule, layer_masks))
			allowed = false;
		/* TODO: double check >1 layer access check works */

		hierarchy = hierarchy->parent;
	}

	return allowed;
}
