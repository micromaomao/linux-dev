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
#include "common.h"
#include "domain.h"
#include "id.h"

static void __maybe_unused build_check_domain(void)
{
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES >= U32_MAX);
	BUILD_BUG_ON(LANDLOCK_MAX_NUM_RULES * LANDLOCK_MAX_NUM_LAYERS >=
		     U32_MAX);
}

/**
 * landlock_domain_find - search for a key in a domain.  Don't use this
 * function directly, but use one of the dom_find_index_*() macros
 * instead.
 *
 * @dom: The domain to search in.
 * @indices_arr: The indices array to search in.
 * @num_indices: The number of elements in @indices_arr.
 * @layers_arr: The layers array.
 * @num_layers: The number of elements in @layers_arr.
 * @key: The key to search for.
 */
struct landlock_found_rule
landlock_domain_find(const struct landlock_domain *const dom,
		     const struct landlock_domain_index *const indices_arr,
		     const u32 num_indices,
		     const struct landlock_layer *const layers_arr,
		     const u32 num_layers, const union landlock_key key)
{
	struct landlock_found_rule out_found_rule = {};
	u32 left = 0, right = num_indices;
	u32 l_start, l_end;

	if (WARN_ON_ONCE(!dom || !indices_arr || !layers_arr))
		return out_found_rule;

	if (WARN_ON_ONCE((uintptr_t *)layers_arr <= dom->rules))
		return out_found_rule;

	while (left < right) {
		const u32 mid = left + (right - left) / 2;
		const struct landlock_domain_index *const curr_mid =
			&indices_arr[mid];

		if (curr_mid->key.data == key.data) {
			l_start = curr_mid->layer_index;
			if (mid + 1 < num_indices)
				l_end = indices_arr[mid + 1].layer_index;
			else
				l_end = num_layers;

			if (WARN_ON_ONCE(l_start >= num_layers ||
					 l_end > num_layers || l_start > l_end))
				return out_found_rule;

			if (WARN_ON_ONCE((uintptr_t *)&layers_arr[l_end] >
					 &dom->rules[dom->len_rules]))
				return out_found_rule;

			out_found_rule.layers_start = &layers_arr[l_start];
			out_found_rule.layers_end = &layers_arr[l_end];

			return out_found_rule;
		} else if (curr_mid->key.data < key.data) {
			left = mid + 1;
		} else {
			right = mid;
		}
	}

	return out_found_rule;
}

/**
 * landlock_merge_walk_step - do a "merging" walk with an existing domain
 * and a rbtree containing rules to be added (or extended).  Populates
 * @out_index and @out_layers appropriately (or sum up the number of
 * layers).
 *
 * @dom_ind_array: The indices subarray in the parent domain for the rule
 * type we're walking.  Can be NULL if there is no parent domain.
 * @dom_num_indices: The length of @dom_ind_array, or 0 if no parent
 * domain.
 * @dom_layer_array: The layers subarray in the parent domain for the rule
 * type we're walking, or NULL if there is no parent domain.
 * @dom_num_layers: The length of @dom_layer_array, or 0 if no parent
 * domain.
 * @new_level: The level number of any new layers that will be added to
 * @out_layers.
 * @next_index: Iterator in the domain.  Initialize to 0.
 * @next_rule: Iterator in the rules tree.  Initialize to rb_first.
 * @out_indices: If not NULL, this is a struct landlock_domain_index
 * array, where new indices are written to.  Reference counts for any
 * copied objects are NOT incremented by this function, if applicable the
 * caller should do so.  This argument should be constant throughout the
 * iteration.
 * @indices_written: Counts the number of iterations.  Initialize to 0 at
 * the beginning.
 * @out_layers: If not NULL, this is a struct landlock_layer array, where
 * existing layers will be copied over from the parent domain, and new
 * layers will also be added.  This argument should be constant throughout
 * the iteration.
 * @layers_written: Counts the number of layers written (or would be
 * written) to @out_layers.  Initialize to 0 at the beginning of the
 * iteration.
 *
 * Returns: true if iteration should continue, in which case
 * *next_{index,rule} and *layers_written are updated and
 * *out_{key,layers} are written to, if necessary.  False if all domain
 * and ruleset rules visisted.
 *
 * The expected way to use this function is to do two loops - first to
 * calculate the number of indices and layers needed to allocate, and then
 * to actually writes the indices and copy over the layers.
 */
bool landlock_merge_walk_step(
	const struct landlock_domain_index *dom_ind_array,
	const u32 dom_num_indices,
	const struct landlock_layer *const dom_layer_array,
	const u32 dom_num_layers, const u32 new_level, u32 *const next_index,
	const struct landlock_rule **const next_rule,
	struct landlock_domain_index *const out_indices,
	u32 *const indices_written, struct landlock_layer *const out_layers,
	u32 *const layers_written)
{
	const struct landlock_domain_index *index = NULL;
	const struct landlock_rule *rule = NULL;
	const struct landlock_layer *l;
	struct landlock_layer *outl;
	struct landlock_domain_index *out_index = NULL;

	if (*next_index >= dom_num_indices && !*next_rule)
		return false;

	if (WARN_ON_ONCE(!layers_written))
		return false;

	/* Check that dom_* is not mistakenly NULL */
	if (WARN_ON_ONCE((*next_index != 0 || dom_num_indices > 0 ||
			  dom_num_layers > 0) &&
			 (!dom_ind_array || !dom_layer_array)))
		return false;

	if (*next_index >= dom_num_indices) {
		/* Walk all remaining rules */
		rule = *next_rule;
	} else if (!*next_rule) {
		/* Walk all remaining indices */
		index = &dom_ind_array[*next_index];
	} else {
		/*
		 * Pick the smallest one to iterate next, but if they have the same
		 * key, merge them.
		 */

		union landlock_key domain_key = dom_ind_array[*next_index].key;
		union landlock_key rule_key = (*next_rule)->key;

		if (domain_key.data == rule_key.data) {
			rule = *next_rule;
			index = &dom_ind_array[*next_index];
		} else if (domain_key.data < rule_key.data) {
			index = &dom_ind_array[*next_index];
		} else {
			rule = *next_rule;
		}
	}

	if (rule && index)
		WARN_ON_ONCE(rule->key.data != index->key.data);

	if (out_indices)
		out_index = &out_indices[*indices_written];
	if (WARN_ON_ONCE(*indices_written >= U32_MAX))
		return false;
	*indices_written += 1;

	if (index) {
		u32 layer_i, layer_end, inc;

		if (out_index) {
			out_index->key = index->key;
			out_index->layer_index = *layers_written;
		}

		layer_i = index->layer_index;
		if ((*next_index) + 1 < dom_num_indices)
			layer_end =
				dom_ind_array[(*next_index) + 1].layer_index;
		else
			layer_end = dom_num_layers;

		if (out_layers) {
			while (layer_i < layer_end) {
				l = &dom_layer_array[layer_i++];
				WARN_ON_ONCE(l->level >= new_level);
				if (WARN_ON_ONCE(*layers_written >= U32_MAX))
					return false;
				out_layers[(*layers_written)++] = *l;
			}
		} else {
			inc = layer_end - layer_i;
			if (WARN_ON_ONCE(*layers_written > U32_MAX - inc))
				return false;
			*layers_written += inc;
		}

		(*next_index)++;
	}

	if (rule) {
		const struct rb_node *next_node;

		if (out_index && !index) {
			out_index->key = rule->key;
			out_index->layer_index = *layers_written;
		}

		WARN_ON_ONCE(rule->num_layers != 1);

		if (WARN_ON_ONCE(*layers_written >= U32_MAX))
			return false;

		if (out_layers) {
			l = &rule->layers[0];
			outl = &out_layers[(*layers_written)++];
			outl->access = l->access;
			outl->level = new_level;
		} else
			*layers_written += 1;

		next_node = rb_next(&rule->node);
		if (next_node)
			*next_rule = container_of(next_node,
						  struct landlock_rule, node);
		else
			*next_rule = NULL;
	}

	return true;
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

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

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

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

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

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#endif /* CONFIG_AUDIT */
