// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Domain management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2024-2025 Microsoft Corporation
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#include <kunit/test.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/bsearch.h>
#include <linux/bug.h>
#include <linux/compiler_types.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>

#include "access.h"
#include "audit.h"
#include "common.h"
#include "domain.h"

/* Forward declarations for functions from ruleset.c */
static void get_hierarchy(struct landlock_hierarchy *const hierarchy)
{
	if (hierarchy)
		refcount_inc(&hierarchy->usage);
}

static void build_check_domain(void)
{
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES > U32_MAX);
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES * LANDLOCK_MAX_NUM_LAYERS >=
		     U32_MAX);
}

/**
 * landlock_alloc_domain - allocate a new domain given known sizes.  The
 * caller must then at least fill in the indices and layers arrays before
 * trying to free this domain.
 *
 * @sizes: A "fake" struct landlock_domain which just contains various
 * num_* numbers.  This function will call dom_rules_len() to compute the
 * total rules array length, and copy over the number fields.
 * sizes.usage, sizes.hierarchy and sizes.work_free are ignored.
 */
struct landlock_domain *
landlock_alloc_domain(const struct landlock_domain *sizes)
{
	u32 len_rules = dom_rules_len(sizes);
	struct landlock_domain *new_dom = kzalloc(
		struct_size(new_dom, rules, len_rules), GFP_KERNEL_ACCOUNT);

	if (!new_dom)
		return NULL;

	memcpy(new_dom, sizes, sizeof(*sizes));
	new_dom->hierarchy = NULL;
	new_dom->work_free =
		kzalloc(sizeof(*new_dom->work_free), GFP_KERNEL_ACCOUNT);
	if (!new_dom->work_free) {
		kfree(new_dom);
		return NULL;
	}
	new_dom->work_free->domain = new_dom;
	refcount_set(&new_dom->usage, 1);
	new_dom->len_rules = len_rules;

	/* Set up hashtable sizes based on number of indices */
	if (new_dom->num_fs_indices > 0) {
		/* Use power-of-2 sizing for fast hashing */
		u32 target_size = (new_dom->num_fs_indices * 4) / 3; /* Load factor ~0.75 */
		new_dom->fs_hash_size = 1U << fls(target_size - 1); /* Next power of 2 */
	} else {
		new_dom->fs_hash_size = 0;
	}

	if (new_dom->num_net_indices > 0) {
		/* Use power-of-2 sizing for fast hashing */
		u32 target_size = (new_dom->num_net_indices * 4) / 3; /* Load factor ~0.75 */
		new_dom->net_hash_size = 1U << fls(target_size - 1); /* Next power of 2 */
	} else {
		new_dom->net_hash_size = 0;
	}

	return new_dom;
}

static void free_domain(struct landlock_domain *const domain)
{
	struct landlock_domain_index *fs_indices;
	u32 i;

	might_sleep();
	if (WARN_ON_ONCE(!domain))
		return;

	/* Free filesystem object references */
	fs_indices = dom_fs_indices(domain);
	for (i = 0; i < domain->fs_hash_size; i++) {
		if (fs_indices[i].key.object)
			landlock_put_object(fs_indices[i].key.object);
	}

	/* Network indices don't hold object references, just port numbers */

	landlock_put_hierarchy(domain->hierarchy);
	domain->hierarchy = NULL;
	kfree(domain->work_free);
	domain->work_free = NULL;
	kfree(domain);
}

void landlock_put_domain(struct landlock_domain *const domain)
{
	might_sleep();

	if (domain && refcount_dec_and_test(&domain->usage))
		free_domain(domain);
}

static void free_domain_work(struct work_struct *const work)
{
	struct landlock_domain_work_free *const fw =
		container_of(work, struct landlock_domain_work_free, work);
	struct landlock_domain *domain = fw->domain;

	free_domain(domain);
	/* the work_free struct will be freed by free_domain */
}

/*
 * Schedule work to free a landlock_domain, useful in a non-sleepable
 * context.
 */
void landlock_put_domain_deferred(struct landlock_domain *const domain)
{
	if (domain && refcount_dec_and_test(&domain->usage)) {
		INIT_WORK(&domain->work_free->work, free_domain_work);

		if (WARN_ON_ONCE(domain->work_free->domain != domain))
			return;

		schedule_work(&domain->work_free->work);
	}
}

/**
 * build_hashtable - construct a hashtable using collision chaining within the array
 *
 * @indices: The hashtable array to populate
 * @hash_size: Size of the hashtable
 * @rules: Array of sorted rules to insert
 * @num_rules: Number of rules
 * @layers: The layers array (for writing layer indices)
 * @layer_offset: Offset to add to layer indices when writing
 * @layers_written: Pointer to track how many layers have been written
 *
 * This function builds a hashtable using collision chaining within the array.
 * When a collision occurs, the new entry is placed in any available slot and
 * linked via the next_collision field. This ensures fast lookups for missing
 * keys (immediate termination if ideal slot is empty) while handling collisions
 * correctly through explicit chaining.
 */
int build_hashtable(struct landlock_domain_index *indices,
			   u32 hash_size,
			   const struct landlock_rule **rules,
			   u32 num_rules,
			   struct landlock_layer *layers,
			   u32 layer_offset,
			   u32 *layers_written)
{
	u32 i, hash_index, slot_index;
	const struct landlock_rule *rule;
	struct landlock_domain_index *entry, *head_entry;

	if (!hash_size || !num_rules)
		return 0;

	/* Initialize hashtable - zero key.data means empty slot */
	for (i = 0; i < hash_size; i++) {
		indices[i].key.data = 0;
		indices[i].next_collision = UINT32_MAX;
	}

	/* Process each rule */
	for (i = 0; i < num_rules; i++) {
		rule = rules[i];
		hash_index = domain_hash_key(rule->key, hash_size);
		head_entry = &indices[hash_index];

		if (head_entry->key.data == 0) {
			/* Ideal slot is empty - place entry there */
			slot_index = hash_index;
		} else {
			/* Collision - find any empty slot */
			slot_index = 0;
			while (slot_index < hash_size && indices[slot_index].key.data != 0) {
				slot_index++;
			}

			if (slot_index >= hash_size) {
				return -ENOSPC;
			}

			/* Link new entry to the collision chain */
			/* Find the tail of the existing chain */
			struct landlock_domain_index *tail = head_entry;
			while (tail->next_collision != UINT32_MAX) {
				if (WARN_ON_ONCE(tail->next_collision >= hash_size))
					return -EINVAL;
				tail = &indices[tail->next_collision];
			}
			tail->next_collision = slot_index;
		}

		/* Place the rule in the found slot */
		entry = &indices[slot_index];
		entry->key = rule->key;
		entry->layer_start = layer_offset + *layers_written;
		entry->next_collision = UINT32_MAX;

		/* Copy layers for this rule */
		if (WARN_ON_ONCE(rule->num_layers != 1)) {
			return -EINVAL;
		}

		if (layers) {
			layers[*layers_written] = rule->layers[0];
		}
		(*layers_written)++;
		entry->layer_end = layer_offset + *layers_written;
	}

	return 0;
}

/**
 * merge_rules_pass_hash - Do one full merge walk for both fs and net, and
 * optionally copy over indices and layers using hashtable construction.
 *
 * @parent: Parent domain, or NULL if there is no parent.
 * @child: Child domain.  num_layers must be set to the new level.
 * @ruleset: Ruleset to be merged.  Must hold the ruleset lock across
 * calls to this function.
 * @only_calc_sizes: Whether this is a size-calculation pass, or the final
 * merge pass.
 * @use_power_of_2: Whether to use power-of-2 sizing for hash tables.
 *
 * If @only_calc_sizes is true, child->num_{fs,net}_{indices,layers} and
 * child->{fs,net}_hash_size will be updated.  Otherwise, the function
 * writes to child->rules and checks that the number of indices and layers
 * written matches with previously stored numbers in @child.
 */
static int merge_rules_pass_hash(const struct landlock_domain *parent,
			    struct landlock_domain *child,
			    struct landlock_ruleset *ruleset,
			    bool only_calc_sizes,
			    bool use_power_of_2) __must_hold(&ruleset->lock)
{
	struct landlock_rule *walker_rule, *next_rule;
	const struct landlock_rule **fs_rules = NULL, **net_rules = NULL;
	u32 fs_rule_count = 0, net_rule_count = 0;
	u32 fs_layers_written = 0, net_layers_written = 0;
	int err = 0;

	if (WARN_ON_ONCE(!ruleset || !child))
		return -EINVAL;

	if (WARN_ON_ONCE(child->num_layers == 0 ||
			  child->num_layers > LANDLOCK_MAX_NUM_LAYERS))
		return -EINVAL;

	build_check_domain();

	/* Count filesystem rules */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
					      &ruleset->root_inode, node) {
		fs_rule_count++;
	}

#if IS_ENABLED(CONFIG_INET)
	/* Count network rules */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
					      &ruleset->root_net_port, node) {
		net_rule_count++;
	}
#endif

	if (only_calc_sizes) {
		/* Calculate sizes */
		child->num_fs_indices = (parent ? parent->num_fs_indices : 0) + fs_rule_count;
		child->num_net_indices = (parent ? parent->num_net_indices : 0) + net_rule_count;

		/* Set hash table sizes */
		if (use_power_of_2) {
			child->fs_hash_size = child->num_fs_indices ?
				next_power_of_2_u32(child->num_fs_indices) : 0;
			child->net_hash_size = child->num_net_indices ?
				next_power_of_2_u32(child->num_net_indices) : 0;
		} else {
			child->fs_hash_size = child->num_fs_indices;
			child->net_hash_size = child->num_net_indices;
		}

		/* Calculate layer counts */
		child->num_fs_layers = (parent ? parent->num_fs_layers : 0) + fs_rule_count;
		child->num_net_layers = (parent ? parent->num_net_layers : 0) + net_rule_count;

		return 0;
	}

	/* Actual merge pass - allocate arrays for rules */
	if (fs_rule_count > 0) {
		fs_rules = kmalloc_array(fs_rule_count, sizeof(*fs_rules), GFP_KERNEL);
		if (!fs_rules) {
			err = -ENOMEM;
			goto out_free;
		}

		fs_rule_count = 0;
		rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
						      &ruleset->root_inode, node) {
			fs_rules[fs_rule_count++] = walker_rule;
		}
	}

#if IS_ENABLED(CONFIG_INET)
	if (net_rule_count > 0) {
		net_rules = kmalloc_array(net_rule_count, sizeof(*net_rules), GFP_KERNEL);
		if (!net_rules) {
			err = -ENOMEM;
			goto out_free;
		}

		net_rule_count = 0;
		rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
						      &ruleset->root_net_port, node) {
			net_rules[net_rule_count++] = walker_rule;
		}
	}
#endif

	/* Build filesystem hashtable */
	if (child->fs_hash_size > 0) {
		/* First copy parent entries if any */
		if (parent && parent->num_fs_indices > 0) {
			memcpy(dom_fs_indices(child), dom_fs_indices(parent),
			       parent->num_fs_indices * sizeof(struct landlock_domain_index));
			memcpy(dom_fs_layers(child), dom_fs_layers(parent),
			       parent->num_fs_layers * sizeof(struct landlock_layer));
			fs_layers_written = parent->num_fs_layers;
		}

		/* Add new rules using hashtable construction */
		if (fs_rule_count > 0) {
			err = build_hashtable(dom_fs_indices(child), child->fs_hash_size,
					       fs_rules, fs_rule_count,
					       dom_fs_layers(child), 0, &fs_layers_written);
			if (err)
				goto out_free;
		}
	}

#if IS_ENABLED(CONFIG_INET)
	/* Build network hashtable */
	if (child->net_hash_size > 0) {
		/* First copy parent entries if any */
		if (parent && parent->num_net_indices > 0) {
			memcpy(dom_net_indices(child), dom_net_indices(parent),
			       parent->num_net_indices * sizeof(struct landlock_domain_index));
			memcpy(dom_net_layers(child), dom_net_layers(parent),
			       parent->num_net_layers * sizeof(struct landlock_layer));
			net_layers_written = parent->num_net_layers;
		}

		/* Add new rules using hashtable construction */
		if (net_rule_count > 0) {
			err = build_hashtable(dom_net_indices(child), child->net_hash_size,
					       net_rules, net_rule_count,
					       dom_net_layers(child), 0, &net_layers_written);
			if (err)
				goto out_free;
		}
	}
#endif

	/* Verify counts match expectations */
	if (WARN_ON_ONCE(fs_layers_written != child->num_fs_layers ||
			  net_layers_written != child->num_net_layers)) {
		err = -EINVAL;
	}

out_free:
	kfree(fs_rules);
	kfree(net_rules);
	return err;
}

/**
 * Populate handled access masks and hierarchy for the child.
 *
 * @parent: Parent domain, or NULL if there is no parent.
 * @child: Child domain to be populated.
 * @ruleset: Ruleset to be merged.  Must hold the ruleset lock.
 */
static int inherit_domain(const struct landlock_domain *parent,
		  struct landlock_domain *child,
		  struct landlock_ruleset *ruleset)
	__must_hold(&ruleset->lock)
{
	if (WARN_ON_ONCE(!child || !ruleset || !child->hierarchy ||
		 child->num_layers < 1 || ruleset->num_layers != 1)) {
		return -EINVAL;
	}

	if (parent) {
		if (WARN_ON_ONCE(child->num_layers != parent->num_layers + 1))
			return -EINVAL;

		/* Copies the parent layer stack. */
		memcpy(dom_access_masks(child), dom_access_masks(parent),
		       array_size(parent->num_layers,
			  sizeof(*dom_access_masks(child))));

		if (WARN_ON_ONCE(!parent->hierarchy))
			return -EINVAL;

		get_hierarchy(parent->hierarchy);
		child->hierarchy->parent = parent->hierarchy;
	}

	/* Stacks the new layer. */
	dom_access_masks(child)[child->num_layers - 1] =
		landlock_upgrade_handled_access_masks(ruleset->access_masks[0]);

	return 0;
}

/**
 * landlock_domain_merge_ruleset - Merge a ruleset and a parent domain
 * into a new domain using hashtable-based arrays.
 *
 * @parent: Parent domain.
 * @ruleset: Ruleset to be merged.  This function will take the mutex on
 * this ruleset while merging.
 *
 * The current task is requesting to be restricted.  The subjective credentials
 * must not be in an overridden state. cf. landlock_init_hierarchy_log().
 *
 * Returns the intersection of @parent and @ruleset, or returns @parent if
 * @ruleset is empty, or returns a duplicate of @ruleset if @parent is empty.
 */
struct landlock_domain *
landlock_domain_merge_ruleset(const struct landlock_domain *parent,
		      struct landlock_ruleset *ruleset)
{
	struct landlock_domain *new_dom __free(landlock_put_domain) = NULL;
	struct landlock_hierarchy *new_hierarchy __free(kfree) = NULL;
	struct landlock_domain new_dom_sizes = {};
	u32 new_level;
	int err;
	bool use_power_of_2 = true; /* Use power-of-2 sizing for faster hashing */

	might_sleep();
	if (WARN_ON_ONCE(!ruleset))
		return ERR_PTR(-EINVAL);

	if (parent) {
		if (parent->num_layers >= LANDLOCK_MAX_NUM_LAYERS)
			return ERR_PTR(-E2BIG);
		new_level = parent->num_layers + 1;
	} else {
		new_level = 1;
	}

	new_dom_sizes.num_layers = new_level;

	/* Allocate this now so we fail early */
	new_hierarchy = kzalloc(sizeof(*new_hierarchy), GFP_KERNEL_ACCOUNT);
	if (!new_hierarchy)
		return ERR_PTR(-ENOMEM);

	/*
	 * Figure out how many indices and layer structs.  From this point
	 * until we actually merge in the ruleset, ruleset must not change.
	 */
	mutex_lock(&ruleset->lock);
	err = merge_rules_pass_hash(parent, &new_dom_sizes, ruleset, true, use_power_of_2);
	if (err)
		goto out_unlock;

	/*
	 * Ok, we know the required size now, allocate the domain and merge in
	 * the indices and rules.
	 */
	new_dom = landlock_alloc_domain(&new_dom_sizes);
	if (!new_dom) {
		err = -ENOMEM;
		goto out_unlock;
	}
	new_dom->hierarchy = new_hierarchy;
	new_hierarchy = NULL;
	refcount_set(&new_dom->hierarchy->usage, 1);

	err = merge_rules_pass_hash(parent, new_dom, ruleset, false, use_power_of_2);
	if (err) {
		/* new_dom can contain invalid landlock_object references. */
		kfree(new_dom);
		new_dom = NULL;
		goto out_unlock;
	}

	/* Increment object references for filesystem rules */
	if (new_dom->fs_hash_size > 0) {
		struct landlock_domain_index *fs_indices = dom_fs_indices(new_dom);
		for (size_t i = 0; i < new_dom->fs_hash_size; i++) {
			if (fs_indices[i].key.object)
				landlock_get_object(fs_indices[i].key.object);
		}
	}

	err = inherit_domain(parent, new_dom, ruleset);
	if (err)
		goto out_unlock;

	mutex_unlock(&ruleset->lock);

	err = landlock_init_hierarchy_log(new_dom->hierarchy);
	if (err)
		return ERR_PTR(err);

	return no_free_ptr(new_dom);

out_unlock:
	mutex_unlock(&ruleset->lock);
	return ERR_PTR(err);
}

void landlock_put_hierarchy(struct landlock_hierarchy *hierarchy)
{
	while (hierarchy && refcount_dec_and_test(&hierarchy->usage)) {
		const struct landlock_hierarchy *const freeme = hierarchy;

		landlock_log_drop_domain(hierarchy);
		landlock_free_hierarchy_details(hierarchy);
		hierarchy = hierarchy->parent;
		kfree(freeme);
	}
}

/*
 * @layer_masks is read and may be updated according to the access request and
 * the matching rule.
 * @masks_array_size must be equal to ARRAY_SIZE(*layer_masks).
 *
 * Returns true if the request is allowed (i.e. relevant layer masks for the
 * request are empty).
 */
bool landlock_domain_unmask_layers(const struct landlock_found_rule rule,
		    const access_mask_t access_request,
		    layer_mask_t (*const layer_masks)[],
		    const size_t masks_array_size)
{
	const struct landlock_layer *layer;

	if (!access_request || !layer_masks)
		return true;

	if (rule.layers_start == rule.layers_end)
		return false;

	if (WARN_ON_ONCE(rule.layers_start > rule.layers_end))
		return false;

	/* We should not have layers_start being NULL but layers_end not */
	if (WARN_ON_ONCE(rule.layers_start == NULL))
		return false;

	/*
	 * An access is granted if, for each policy layer, at least one rule
	 * encountered on the pathwalk grants the requested access,
	 * regardless of its position in the layer stack.  We must then check
	 * the remaining layers for each inode, from the first added layer to
	 * the last one.  When there is multiple requested accesses, for each
	 * policy layer, the full set of requested accesses may not be granted
	 * by only one rule, but by the union (binary OR) of multiple rules.
	 * E.g. /a/b <execute> + /a <read> => /a/b <execute + read>
	 */
	for (layer = rule.layers_start; layer < rule.layers_end; layer++) {
		const layer_mask_t layer_bit = BIT_ULL(layer->level - 1);
		const unsigned long access_req = access_request;
		unsigned long access_bit;
		bool is_empty;

		/*
		 * Records in @layer_masks which layer grants access to each
		 * requested access.
		 */
		is_empty = true;
		for_each_set_bit(access_bit, &access_req, masks_array_size) {
			if (layer->access & BIT_ULL(access_bit))
				(*layer_masks)[access_bit] &= ~layer_bit;
			is_empty = is_empty && !(*layer_masks)[access_bit];
		}
		if (is_empty)
			return true;
	}
	return false;
}

typedef access_mask_t
get_dom_access_mask_t(const struct landlock_domain *const domain,
	      const u16 layer_level);

/**
 * landlock_domain_init_layer_masks - Initialize layer masks from an access request
 *
 * Populates @layer_masks such that for each access right in @access_request,
 * the bits for all the layers are set where that access right is handled.
 * For each layer, the layer bit is set in @layer_masks for a given access
 * right, if and only if the current layer handles this access right and the
 * access right is requested.
 *
 * Returns: An access mask where each access right bit is set if it is
 * handled in any of the active layers in @domain.
 */
access_mask_t
landlock_domain_init_layer_masks(const struct landlock_domain *const domain,
		  const access_mask_t access_request,
		  layer_mask_t (*const layer_masks)[],
		  const enum landlock_key_type key_type)
{
	access_mask_t handled_accesses = 0;
	size_t layer_level, num_access;
	get_dom_access_mask_t *get_access_mask;

	switch (key_type) {
	case LANDLOCK_KEY_INODE:
		get_access_mask = landlock_dom_get_fs_access_mask;
		num_access = LANDLOCK_NUM_ACCESS_FS;
		break;

#if IS_ENABLED(CONFIG_INET)
	case LANDLOCK_KEY_NET_PORT:
		get_access_mask = landlock_dom_get_net_access_mask;
		num_access = LANDLOCK_NUM_ACCESS_NET;
		break;
#endif /* IS_ENABLED(CONFIG_INET) */

	default:
		WARN_ON_ONCE(1);
		return 0;
	}

	memset(layer_masks, 0,
	       array_size(num_access, sizeof((*layer_masks)[0])));

	/* An access request not handled by the domain is allowed. */
	for (layer_level = 0; layer_level < domain->num_layers; layer_level++) {
		const unsigned long access_req = access_request;
		unsigned long access_bit;
		const access_mask_t layer_access_mask =
			get_access_mask(domain, layer_level);

		for_each_set_bit(access_bit, &access_req, num_access) {
			if (layer_access_mask & BIT_ULL(access_bit)) {
				(*layer_masks)[access_bit] |=
					BIT_ULL(layer_level);
				handled_accesses |= BIT_ULL(access_bit);
			}
		}
	}
	return handled_accesses & access_request;
}
