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
#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/uidgid.h>

#include "access.h"
#include "audit.h"
#include "common.h"
#include "domain.h"
#include "id.h"

static void build_check_domain(void)
{
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES >= U32_MAX - 1);
	/* Non-inclusive end indices are involved, so needs to be U32_MAX - 1. */
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES * LANDLOCK_MAX_NUM_LAYERS >=
		     U32_MAX - 1);
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_LAYERS >= U16_MAX - 1);
	/*
	 * Make sure this function is changed when the type of the domain
	 * struct fields are changed
	 */
	BUILD_BUG_ON(sizeof((struct landlock_domain *)0)->num_layers <
		     sizeof(u16));
	BUILD_BUG_ON(sizeof((struct landlock_domain *)0)->num_fs_indices <
		     sizeof(u32));
	BUILD_BUG_ON(sizeof((struct landlock_domain *)0)->num_net_indices <
		     sizeof(u32));
	BUILD_BUG_ON(sizeof((struct landlock_domain *)0)->num_fs_layers <
		     sizeof(u32));
	BUILD_BUG_ON(sizeof((struct landlock_domain *)0)->num_net_layers <
		     sizeof(u32));
	BUILD_BUG_ON(sizeof((struct landlock_domain_index *)0)->layer_index <
		     sizeof(u32));
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

	return new_dom;
}

static void free_domain(struct landlock_domain *const domain)
{
	struct landlock_domain_index *fs_indices, ind;
	u32 i, num_fs_indices;

	might_sleep();
	if (WARN_ON_ONCE(!domain))
		return;
	fs_indices = dom_fs_indices(domain);
	num_fs_indices = domain->num_fs_indices;
	if (WARN_ON_ONCE((uintptr_t *)(fs_indices + num_fs_indices) -
				 domain->rules >
			 domain->len_rules))
		return;

	for (i = 0; i < num_fs_indices; i++) {
		ind = fs_indices[i];
		landlock_put_object(ind.key.object);
	}

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
 * dom_calculate_merged_sizes - Calculate the eventual size of the part of
 * a new domain for a given rule size (i.e. either fs or net).  Correct
 * usage requires the caller to hold the ruleset lock throughout the
 * merge.  Returns -E2BIG if limits would be exceeded.
 *
 * @dom_ind_array: The index table in the parent domain for the relevant
 * rule type.  Can be NULL if there is no parent domain.
 * @dom_num_indices: The length of @dom_ind_array, or 0 if no parent
 * domain.
 * @dom_num_layers: The total number of distinct layer objects in the
 * parent domain for the relevant rule type.
 * @child_rules: The root of the rules tree to be merged.
 * @out_num_indices: Outputs the number of indices that would be needed in
 * the new domain.
 * @out_num_layers: Outputs the number of layer objects that would be
 * needed in the new domain.
 */
static int dom_calculate_merged_sizes(
	const struct landlock_domain_index *const dom_ind_array,
	const u32 dom_num_indices, const u32 dom_num_layers,
	const struct rb_root *const child_rules, u32 *const out_num_indices,
	u32 *const out_num_layers)
{
	u32 num_indices = dom_num_indices;
	u32 num_layers = dom_num_layers;
	const struct landlock_rule *walker_rule, *next_rule;
	struct landlock_domain_index find_key;
	const struct landlock_domain_index *found;

	build_check_domain();

	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
					     child_rules, node) {
		found = NULL;
		if (dom_ind_array) {
			find_key.key = walker_rule->key;
			found = dom_hash_find(dom_ind_array, dom_num_indices,
					      &find_key);
		}
		/* A new index is only needed if this is a non-overlapping new rule */
		if (!found) {
			if (num_indices >= LANDLOCK_MAX_NUM_RULES)
				return -E2BIG;
			num_indices++;
		}

		/* Regardless, we have a new layer. */
		if (WARN_ON_ONCE(num_layers >= U32_MAX - 1))
			/*
			 * This situation should not be possible with the proper rule
			 * number limit.
			 */
			return -E2BIG;
		num_layers++;
	}

	*out_num_indices = num_indices;
	*out_num_layers = num_layers;
	return 0;
}

/**
 * dom_populate_indices - Populate the index table of a new domain.
 *
 * @dom_ind_array: The index table in the parent domain for the relevant
 * rule type.  Can be NULL if there is no parent domain.
 * @dom_num_indices: The length of @dom_ind_array, or 0 if no parent
 * domain.
 * @child_rules: The root of the rules tree to be merged.
 * @out_indices: The output indices array to be populated.
 * @out_size: The size of @out_indices, in number of elements.
 */
static int dom_populate_indices(
	const struct landlock_domain_index *const dom_ind_array,
	const u32 dom_num_indices, const struct rb_root *const child_rules,
	struct landlock_domain_index *const out_indices, const u32 out_size)
{
	u32 indices_written = 0;
	const struct landlock_domain_index *walker_index;
	struct landlock_domain_index target = {};
	const struct landlock_rule *walker_rule, *next_rule;
	const struct landlock_domain_index *found;
	struct h_insert_scratch scratch;
	int ret;
	size_t i;

	dom_hash_initialize(out_indices, out_size);
	for (i = 0; i < out_size; i++) {
		out_indices[i].key.data = 0;
		out_indices[i].layer_index = U32_MAX;
	}

	ret = h_init_insert_scratch(&scratch, out_indices, out_size,
				    sizeof(*out_indices));
	if (ret)
		return ret;

	/* Copy over all parent indices directly */
	for (size_t i = 0; i < dom_num_indices; i++) {
		walker_index = &dom_ind_array[i];
		if (WARN_ON_ONCE(indices_written >= out_size)) {
			ret = -E2BIG;
			goto out_free;
		}
		/* Don't copy over layer_index */
		target.key = walker_index->key;
		dom_hash_insert(&scratch, &target);
		indices_written++;
	}

	/* Copy over new child rules */
	rbtree_postorder_for_each_entry_safe(walker_rule, next_rule,
					     child_rules, node) {
		target.key = walker_rule->key;
		found = NULL;
		if (dom_ind_array)
			found = dom_hash_find(dom_ind_array, dom_num_indices,
					      &target);
		if (!found) {
			if (WARN_ON_ONCE(indices_written >= out_size)) {
				ret = -E2BIG;
				goto out_free;
			}
			dom_hash_insert(&scratch, &target);
			indices_written++;
		}
	}

out_free:
	h_free_insert_scratch(&scratch);

	if (ret)
		return ret;

	for (i = 0; i < out_size; i++) {
		walker_index = &out_indices[i];
		/* We are not supposed to leave empty slots behind. */
		WARN_ON_ONCE(dom_index_is_empty(walker_index));
	}

	return 0;
}

/**
 * dom_populate_layers - Populate the layer array of a new domain.
 *
 * @dom_ind_array: The index table in the parent domain for the relevant
 * rule type.  Can be NULL if there is no parent domain.
 * @dom_num_indices: The length of @dom_ind_array, or 0 if no parent
 * domain.
 * @dom_layer_array: The layer array in the parent domain for the relevant
 * rule type.  Can be NULL if there is no parent domain.
 * @dom_num_layers: The length of @dom_layer_array, or 0 if no parent
 * domain.
 * @child_rules: The root of the rules tree to be merged.
 * @child_indices: The already populated index table in the child ruleset
 * to be merged.  This function will set the layer_index field on each
 * indices.
 * @child_indices_size: The size of @child_indices, in number of elements.
 * @new_level: The level number of any new layers that will be added to
 * @out_layers.
 * @out_layers: The output layers array to be populated.
 * @out_size: The size of @out_layers, in number of elements.
 */
static int
dom_populate_layers(const struct landlock_domain_index *const dom_ind_array,
		    const u32 dom_num_indices,
		    const struct landlock_layer *const dom_layer_array,
		    const u32 dom_num_layers,
		    const struct rb_root *const child_rules,
		    struct landlock_domain_index *const child_indices,
		    const u32 child_indices_size, const u32 new_level,
		    struct landlock_layer *const out_layers, const u32 out_size)
{
	u32 layers_written = 0;
	struct landlock_domain_index *merged_index;
	struct landlock_found_rule found_in_parent;
	const struct landlock_rule *found_in_child;
	const struct landlock_layer *layer;
	struct landlock_layer child_layer;

	for (size_t i = 0; i < child_indices_size; i++) {
		merged_index = &child_indices[i];
		merged_index->layer_index = layers_written;

		found_in_parent.layers_start = NULL;
		found_in_parent.layers_end = NULL;
		if (dom_ind_array)
			found_in_parent = landlock_domain_find(
				dom_ind_array, dom_num_indices, dom_layer_array,
				dom_num_layers, merged_index->key);
		dom_rule_for_each_layer(found_in_parent, layer)
		{
			if (WARN_ON_ONCE(layers_written >= out_size))
				return -E2BIG;
			out_layers[layers_written++] = *layer;
		}

		found_in_child =
			landlock_find_in_tree(child_rules, merged_index->key);
		if (found_in_child) {
			if (WARN_ON_ONCE(layers_written >= out_size))
				return -E2BIG;
			if (WARN_ON_ONCE(found_in_child->num_layers != 1))
				return -EINVAL;
			child_layer.access = found_in_child->layers[0].access;
			child_layer.level = new_level;
			out_layers[layers_written++] = child_layer;
		}
	}

	return 0;
}

/**
 * merge_domain - Do merge for both fs and net.
 *
 * @parent: Parent domain, or NULL if there is no parent.
 * @child: Child domain.  child->num_layers must be set to the new level.
 * @ruleset: Ruleset to be merged.  Must hold the ruleset lock across
 * calls to this function.
 * @only_calc_sizes: Whether this is a size-calculation pass, or the final
 * merge pass.  For the size-calculation pass, no data except various sizes
 * in @child will be written.
 *
 * If @only_calc_sizes is true, child->num_{fs,net}_{indices,layers} will
 * be updated.  Otherwise, the function writes to child->rules and checks
 * that the number of indices and layers written matches with previously
 * stored numbers in @child.
 */
static int merge_domain(const struct landlock_domain *parent,
			struct landlock_domain *child,
			struct landlock_ruleset *ruleset, bool only_calc_sizes)
	__must_hold(&ruleset->lock)
{
	u32 new_level;
	int err;

	if (WARN_ON_ONCE(!ruleset || !child))
		return -EINVAL;

	new_level = child->num_layers;
	/* We should have checked new_level <= LANDLOCK_MAX_NUM_LAYERS already */
	if (WARN_ON_ONCE(new_level == 0 || new_level > LANDLOCK_MAX_NUM_LAYERS))
		return -EINVAL;

	if (only_calc_sizes) {
		err = dom_calculate_merged_sizes(
			parent ? dom_fs_indices(parent) : NULL,
			parent ? parent->num_fs_indices : 0,
			parent ? parent->num_fs_layers : 0,
			&ruleset->root_inode, &child->num_fs_indices,
			&child->num_fs_layers);
		if (err)
			return err;

#ifdef CONFIG_INET
		err = dom_calculate_merged_sizes(
			parent ? dom_net_indices(parent) : NULL,
			parent ? parent->num_net_indices : 0,
			parent ? parent->num_net_layers : 0,
			&ruleset->root_net_port, &child->num_net_indices,
			&child->num_net_layers);
		if (err)
			return err;
#else
		child->num_net_indices = 0;
		child->num_net_layers = 0;
#endif /* CONFIG_INET */
	} else {
		err = dom_populate_indices(
			parent ? dom_fs_indices(parent) : NULL,
			parent ? parent->num_fs_indices : 0,
			&ruleset->root_inode, dom_fs_indices(child),
			child->num_fs_indices);
		if (err)
			return err;

		err = dom_populate_layers(
			parent ? dom_fs_indices(parent) : NULL,
			parent ? parent->num_fs_indices : 0,
			parent ? dom_fs_layers(parent) : NULL,
			parent ? parent->num_fs_layers : 0,
			&ruleset->root_inode, dom_fs_indices(child),
			child->num_fs_indices, new_level, dom_fs_layers(child),
			child->num_fs_layers);
		if (err)
			return err;

		dom_fs_terminating_index(child)->layer_index =
			child->num_fs_layers;

#ifdef CONFIG_INET
		err = dom_populate_indices(
			parent ? dom_net_indices(parent) : NULL,
			parent ? parent->num_net_indices : 0,
			&ruleset->root_net_port, dom_net_indices(child),
			child->num_net_indices);
		if (err)
			return err;

		err = dom_populate_layers(
			parent ? dom_net_indices(parent) : NULL,
			parent ? parent->num_net_indices : 0,
			parent ? dom_net_layers(parent) : NULL,
			parent ? parent->num_net_layers : 0,
			&ruleset->root_net_port, dom_net_indices(child),
			child->num_net_indices, new_level,
			dom_net_layers(child), child->num_net_layers);
		if (err)
			return err;

		dom_net_terminating_index(child)->layer_index =
			child->num_net_layers;
#endif /* CONFIG_INET */
	}

	return 0;
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

		landlock_get_hierarchy(parent->hierarchy);
		child->hierarchy->parent = parent->hierarchy;
	}

	/* Stacks the new layer. */
	dom_access_masks(child)[child->num_layers - 1] =
		landlock_upgrade_handled_access_masks(ruleset->access_masks[0]);

	return 0;
}

/**
 * landlock_domain_merge_ruleset - Merge a ruleset and a parent domain
 * into a new domain.
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
	err = merge_domain(parent, &new_dom_sizes, ruleset, true);
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

	err = merge_domain(parent, new_dom, ruleset, false);
	if (err) {
		/* new_dom can contain invalid landlock_object references. */
		kfree(new_dom);
		new_dom = NULL;
		goto out_unlock;
	}

	for (size_t i = 0; i < new_dom->num_fs_indices; i++)
		landlock_get_object(dom_fs_indices(new_dom)[i].key.object);

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

#ifdef CONFIG_AUDIT

/**
 * get_current_exe - Get the current's executable path, if any
 *
 * @exe_str: Returned pointer to a path string with a lifetime tied to the
 *           returned buffer, if any.
 * @exe_size: Returned size of @exe_str (including the trailing null
 *            character), if any.
 *
 * Returns: A pointer to an allocated buffer where @exe_str point to, %NULL if
 * there is no executable path, or an error otherwise.
 */
static const void *get_current_exe(const char **const exe_str,
				   size_t *const exe_size)
{
	const size_t buffer_size = LANDLOCK_PATH_MAX_SIZE;
	struct mm_struct *mm = current->mm;
	struct file *file __free(fput) = NULL;
	char *buffer __free(kfree) = NULL;
	const char *exe;
	ssize_t size;

	if (!mm)
		return NULL;

	file = get_mm_exe_file(mm);
	if (!file)
		return NULL;

	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	exe = d_path(&file->f_path, buffer, buffer_size);
	if (WARN_ON_ONCE(IS_ERR(exe)))
		/* Should never happen according to LANDLOCK_PATH_MAX_SIZE. */
		return ERR_CAST(exe);

	size = buffer + buffer_size - exe;
	if (WARN_ON_ONCE(size <= 0))
		return ERR_PTR(-ENAMETOOLONG);

	*exe_size = size;
	*exe_str = exe;
	return no_free_ptr(buffer);
}

/*
 * Returns: A newly allocated object describing a domain, or an error
 * otherwise.
 */
static struct landlock_details *get_current_details(void)
{
	/* Cf. audit_log_d_path_exe() */
	static const char null_path[] = "(null)";
	const char *path_str = null_path;
	size_t path_size = sizeof(null_path);
	const void *buffer __free(kfree) = NULL;
	struct landlock_details *details;

	buffer = get_current_exe(&path_str, &path_size);
	if (IS_ERR(buffer))
		return ERR_CAST(buffer);

	/*
	 * Create the new details according to the path's length.  Do not
	 * allocate with GFP_KERNEL_ACCOUNT because it is independent from the
	 * caller.
	 */
	details =
		kzalloc(struct_size(details, exe_path, path_size), GFP_KERNEL);
	if (!details)
		return ERR_PTR(-ENOMEM);

	memcpy(details->exe_path, path_str, path_size);
	details->pid = get_pid(task_tgid(current));
	details->uid = from_kuid(&init_user_ns, current_uid());
	get_task_comm(details->comm, current);
	return details;
}

/**
 * landlock_init_hierarchy_log - Partially initialize landlock_hierarchy
 *
 * @hierarchy: The hierarchy to initialize.
 *
 * The current task is referenced as the domain that is enforcing the
 * restriction.  The subjective credentials must not be in an overridden state.
 *
 * @hierarchy->parent and @hierarchy->usage should already be set.
 */
int landlock_init_hierarchy_log(struct landlock_hierarchy *const hierarchy)
{
	struct landlock_details *details;

	details = get_current_details();
	if (IS_ERR(details))
		return PTR_ERR(details);

	hierarchy->details = details;
	hierarchy->id = landlock_get_id_range(1);
	hierarchy->log_status = LANDLOCK_LOG_PENDING;
	hierarchy->log_same_exec = true;
	hierarchy->log_new_exec = false;
	atomic64_set(&hierarchy->num_denials, 0);
	return 0;
}

static deny_masks_t
get_layer_deny_mask(const access_mask_t all_existing_optional_access,
		    const unsigned long access_bit, const size_t layer)
{
	unsigned long access_weight;

	/* This may require change with new object types. */
	WARN_ON_ONCE(all_existing_optional_access !=
		     _LANDLOCK_ACCESS_FS_OPTIONAL);

	if (WARN_ON_ONCE(layer >= LANDLOCK_MAX_NUM_LAYERS))
		return 0;

	access_weight = hweight_long(all_existing_optional_access &
				     GENMASK(access_bit, 0));
	if (WARN_ON_ONCE(access_weight < 1))
		return 0;

	return layer
	       << ((access_weight - 1) * HWEIGHT(LANDLOCK_MAX_NUM_LAYERS - 1));
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

static void test_get_layer_deny_mask(struct kunit *const test)
{
	const unsigned long truncate = BIT_INDEX(LANDLOCK_ACCESS_FS_TRUNCATE);
	const unsigned long ioctl_dev = BIT_INDEX(LANDLOCK_ACCESS_FS_IOCTL_DEV);

	KUNIT_EXPECT_EQ(test, 0,
			get_layer_deny_mask(_LANDLOCK_ACCESS_FS_OPTIONAL,
					    truncate, 0));
	KUNIT_EXPECT_EQ(test, 0x3,
			get_layer_deny_mask(_LANDLOCK_ACCESS_FS_OPTIONAL,
					    truncate, 3));

	KUNIT_EXPECT_EQ(test, 0,
			get_layer_deny_mask(_LANDLOCK_ACCESS_FS_OPTIONAL,
					    ioctl_dev, 0));
	KUNIT_EXPECT_EQ(test, 0xf0,
			get_layer_deny_mask(_LANDLOCK_ACCESS_FS_OPTIONAL,
					    ioctl_dev, 15));
}

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

deny_masks_t
landlock_get_deny_masks(const access_mask_t all_existing_optional_access,
			const access_mask_t optional_access,
			const layer_mask_t (*const layer_masks)[],
			const size_t layer_masks_size)
{
	const unsigned long access_opt = optional_access;
	unsigned long access_bit;
	deny_masks_t deny_masks = 0;

	/* This may require change with new object types. */
	WARN_ON_ONCE(access_opt !=
		     (optional_access & all_existing_optional_access));

	if (WARN_ON_ONCE(!layer_masks))
		return 0;

	if (WARN_ON_ONCE(!access_opt))
		return 0;

	for_each_set_bit(access_bit, &access_opt, layer_masks_size) {
		const layer_mask_t mask = (*layer_masks)[access_bit];

		if (!mask)
			continue;

		/* __fls(1) == 0 */
		deny_masks |= get_layer_deny_mask(all_existing_optional_access,
						  access_bit, __fls(mask));
	}
	return deny_masks;
}

#endif /* CONFIG_AUDIT */

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
bool landlock_unmask_layers(const struct landlock_found_rule rule,
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
	dom_rule_for_each_layer(rule, layer)
	{
		const layer_mask_t layer_bit = BIT_ULL(layer->level - 1);
		const unsigned long access_req = access_request;
		unsigned long access_bit;
		bool is_empty;

		/*
		 * Records in @layer_masks which layer grants access to each requested
		 * access: bit cleared if the related layer grants access.
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

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST
#ifdef CONFIG_AUDIT

static void test_landlock_get_deny_masks(struct kunit *const test)
{
	const layer_mask_t layers1[BITS_PER_TYPE(access_mask_t)] = {
		[BIT_INDEX(LANDLOCK_ACCESS_FS_EXECUTE)] = BIT_ULL(0) |
							  BIT_ULL(9),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_TRUNCATE)] = BIT_ULL(1),
		[BIT_INDEX(LANDLOCK_ACCESS_FS_IOCTL_DEV)] = BIT_ULL(2) |
							    BIT_ULL(0),
	};

	KUNIT_EXPECT_EQ(test, 0x1,
			landlock_get_deny_masks(_LANDLOCK_ACCESS_FS_OPTIONAL,
						LANDLOCK_ACCESS_FS_TRUNCATE,
						&layers1, ARRAY_SIZE(layers1)));
	KUNIT_EXPECT_EQ(test, 0x20,
			landlock_get_deny_masks(_LANDLOCK_ACCESS_FS_OPTIONAL,
						LANDLOCK_ACCESS_FS_IOCTL_DEV,
						&layers1, ARRAY_SIZE(layers1)));
	KUNIT_EXPECT_EQ(
		test, 0x21,
		landlock_get_deny_masks(_LANDLOCK_ACCESS_FS_OPTIONAL,
					LANDLOCK_ACCESS_FS_TRUNCATE |
						LANDLOCK_ACCESS_FS_IOCTL_DEV,
					&layers1, ARRAY_SIZE(layers1)));
}

#endif /* CONFIG_AUDIT */
#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST
#ifdef CONFIG_AUDIT

static struct kunit_case test_cases[] = {
	/* clang-format off */
	KUNIT_CASE(test_get_layer_deny_mask),
	KUNIT_CASE(test_landlock_get_deny_masks),
	{}
	/* clang-format on */
};

static struct kunit_suite test_suite = {
	.name = "landlock_domain",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);

#endif /* CONFIG_AUDIT */
#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */
