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

struct landlock_domain *landlock_alloc_domain(size_t num_inode_entries,
					      u16 num_layers)
{
	struct landlock_domain *new_domain =
		kzalloc(sizeof(struct landlock_domain), GFP_KERNEL_ACCOUNT);

	if (!new_domain)
		return NULL;
	refcount_set(&new_domain->usage, 1);
	new_domain->num_layers = num_layers;
	if (landlock_hash_init(num_inode_entries, &new_domain->inode_table)) {
		kfree(new_domain);
		return NULL;
	}

	return new_domain;
}

static void free_domain(struct landlock_domain *const domain)
{
	might_sleep();

	landlock_hash_free(&domain->inode_table, LANDLOCK_KEY_INODE);
	kfree(domain);
}

void landlock_put_domain(struct landlock_domain *const domain)
{
	might_sleep();

	if (domain && refcount_dec_and_test(&domain->usage)) {
		free_domain(domain);
	}
}

static void free_domain_work(struct work_struct *const work)
{
	struct landlock_domain *domain;

	domain = container_of(work, struct landlock_domain, work_free);
	free_domain(domain);
}

/* Only called by hook_cred_free(). */
void landlock_put_domain_deferred(struct landlock_domain *const domain)
{
	if (domain && refcount_dec_and_test(&domain->usage)) {
		INIT_WORK(&domain->work_free, free_domain_work);
		schedule_work(&domain->work_free);
	}
}

/**
 * @curr_table may be NULL.
 */
static int merge_domain_table(const enum landlock_key_type key_type,
			      const struct landlock_hashtable *const curr_table,
			      struct landlock_hashtable *const new_table,
			      struct landlock_layer new_layer,
			      const struct rb_root *ruleset_rb_root)
{
	int err;
	struct landlock_rule *iter, *iter2;

	if (curr_table) {
		err = landlock_hash_clone(new_table, curr_table, key_type);
		if (err) {
			return err;
		}
	}

	/* Merge in new rules */
	rbtree_postorder_for_each_entry_safe(iter, iter2, ruleset_rb_root,
					     node) {
		WARN_ON_ONCE(iter->layers[0].level != 0);
		WARN_ON_ONCE(iter->num_layers != 1);
		new_layer.access = iter->layers[0].access;

		err = landlock_hash_upsert(new_table, iter->key, key_type,
					   new_layer);
		if (err) {
			return err;
		}
	}

	return 0;
}

/**
 * @landlock_merge_ruleset2 - Merge a ruleset with a (possibly NULL)
 * domain, and return a new merged domain.
 */
struct landlock_domain *
landlock_merge_ruleset2(const struct landlock_domain *curr_domain,
			const struct landlock_ruleset *next_ruleset)
{
	size_t num_inodes = 0;
	int err;
	struct landlock_domain *new_domain;
	struct landlock_layer new_layer = {
		.level = 1,
	};
	struct landlock_rule *iter, *iter2;

	if (WARN_ON_ONCE(!next_ruleset)) {
		return ERR_PTR(-EINVAL);
	}

	if (curr_domain) {
		new_layer.level = curr_domain->num_layers + 1;
		num_inodes = landlock_hash_count(&curr_domain->inode_table);
	}

	/* Find new expected size of inode table */
	rbtree_postorder_for_each_entry_safe(iter, iter2,
					     &next_ruleset->root_inode, node) {
		if (!curr_domain ||
		    landlock_hash_find(&curr_domain->inode_table, iter->key) ==
			    NULL) {
			num_inodes += 1;
		}
	}

	new_domain = landlock_alloc_domain(num_inodes, new_layer.level);
	if (!new_domain)
		return ERR_PTR(-ENOMEM);

	err = merge_domain_table(LANDLOCK_KEY_INODE,
				 curr_domain ? &curr_domain->inode_table : NULL,
				 &new_domain->inode_table, new_layer,
				 &next_ruleset->root_inode);
	if (err) {
		landlock_put_domain(new_domain);
		return ERR_PTR(err);
	}

	return new_domain;
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
