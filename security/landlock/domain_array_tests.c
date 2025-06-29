// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Unit tests for struct landlock_domain and its algorithms.
 *
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#include <kunit/test.h>

#include "common.h"
#include "ruleset.h"
#include "domain.h"

/**
 * domain_check_valid_bounds - check that the dom_ macros are correct.
 * dom_rules_len() uses the offset macros, whereas here we manually
 * accumulate the size.
 */
static bool domain_check_valid_bounds(const struct landlock_domain *dom)
{
	char *start;
	u64 size;

	if (WARN_ON_ONCE(!dom))
		return false;
	if (WARN_ON_ONCE(dom->len_rules != dom_rules_len(dom)))
		return false;

	start = (char *)dom->rules;
	size = 0;
	if (WARN_ON_ONCE((char *)dom_access_masks(dom) - start != size))
		return false;
	size += dom->num_layers * sizeof(struct access_masks);
	size = ALIGN(size, sizeof(uintptr_t));
	if (WARN_ON_ONCE((char *)dom_fs_indices(dom) - start != size))
		return false;
	size += dom->num_fs_indices * sizeof(struct landlock_domain_index);
	if (WARN_ON_ONCE((char *)dom_net_indices(dom) - start != size))
		return false;
	size += dom->num_net_indices * sizeof(struct landlock_domain_index);
	if (WARN_ON_ONCE((char *)dom_fs_layers(dom) - start != size))
		return false;
	size += dom->num_fs_layers * sizeof(struct landlock_layer);
	if (WARN_ON_ONCE((char *)dom_net_layers(dom) - start != size))
		return false;
	size += dom->num_net_layers * sizeof(struct landlock_layer);
	size = ALIGN(size, sizeof(uintptr_t));
	if (WARN_ON_ONCE(size != (u64)dom->len_rules * sizeof(uintptr_t)))
		return false;

	return true;
}

static void test_domain_arr_macro_different_sizes(struct kunit *const test)
{
	struct test_config {
		u32 num_layers;
		u32 num_fs_indices;
		u32 num_net_indices;
		u32 num_fs_layers;
		u32 num_net_layers;
	} tests[] = {
		// clang-format off
		{ 0, 0, 0, 0, 0 },
		{ 1, 0, 0, 0, 0 },
		{ 1, 1, 0, 1, 0 },
		{ 1, 0, 1, 0, 1 },
		{ 1, 1, 1, 1, 1 },
		{ 2, 1, 1, 2, 2 },
		{ 2, 2, 2, 2, 2 },
		{ 2, 2, 4, 3, 6 },
		{ 2, 10, 0, 11, 0 },
		// clang-format on
	};
	size_t i;
	struct landlock_domain dom;

	for (i = 0; i < ARRAY_SIZE(tests) + 1000; i++) {
		struct test_config t = {};
		bool check = false;

		if (i < ARRAY_SIZE(tests)) {
			t = tests[i];
			dom.num_layers = t.num_layers;
			dom.num_fs_indices = t.num_fs_indices;
			dom.num_net_indices = t.num_net_indices;
			dom.num_fs_layers = t.num_fs_layers;
			dom.num_net_layers = t.num_net_layers;
		} else {
			dom.num_layers = get_random_u16();
			dom.num_fs_indices = get_random_u16();
			dom.num_net_indices = get_random_u16();
			dom.num_fs_layers = get_random_u16();
			dom.num_net_layers = get_random_u16();
		}

		dom.len_rules = dom_rules_len(&dom);
		check = domain_check_valid_bounds(&dom);

		if (!check) {
			kunit_printk(KERN_INFO, test,
				     "%zu: %u %u %u %u %u: len = %u * %zu\n", i,
				     dom.num_layers, dom.num_fs_indices,
				     dom.num_net_indices, dom.num_fs_layers,
				     dom.num_net_layers, dom.len_rules,
				     sizeof(*dom.rules));
		}

		KUNIT_ASSERT_TRUE(test, check);
	}
}

struct dom_test_config {
	/* How many layers do we already have in the parent domain */
	u32 num_layers;

	/* Parent domain contents */
	const struct landlock_domain_index *indices;
	const struct landlock_layer *layers;

	/* Test searches for non-existing keys */
	const uintptr_t *extra_searches;

	/* Keys and accesses to merge to a new domain */
	const uintptr_t *rule_keys_to_merge;
	const access_mask_t *rule_accesses_to_merge;

	/* Expected content of the merged domain */
	const struct landlock_domain_index *expected_merged_indices;
	const struct landlock_layer *expected_merged_layers;
};

static const struct dom_test_config kunit_dom_test_cases[] = {
	{
		/* No parent domain - test empty merge */
		0,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 2, 3, 0 },
		(const uintptr_t[]){ 0 },
		(const access_mask_t[]){ 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 0 },
		},
	},
	{
		/* No parent domain - merge first layer */
		0,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 2, 3, 0 },
		(const uintptr_t[]){ 123, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
	},
	{
		/* Empty parent domain */
		1,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 0 },
		(const uintptr_t[]){ 123, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
	},
	{
		/* Simple merge - existing rule */
		1,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 200, 0 },
		(const uintptr_t[]){ 123, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
	},
	{
		/* Simple merge - new rule */
		1,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 200, 0 },
		(const uintptr_t[]){ 234, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 234 }, .layer_start = 1 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
	},
	{
		/* Merge into new and existing rules in one go */
		1,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 234 }, .layer_start = 1 },
			{ .key = { .data = 567 }, .layer_start = 2 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 1, 200, 300, 0 },
		(const uintptr_t[]){ 123, 234, 456, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE,
					 LANDLOCK_ACCESS_FS_READ_FILE |
						 LANDLOCK_ACCESS_FS_WRITE_FILE,
					 LANDLOCK_ACCESS_FS_WRITE_FILE, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 234 }, .layer_start = 2 },
			{ .key = { .data = 456 }, .layer_start = 4 },
			{ .key = { .data = 567 }, .layer_start = 5 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			/* 123 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			/* 234 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			{ .level = 2,
			  .access = LANDLOCK_ACCESS_FS_READ_FILE |
				    LANDLOCK_ACCESS_FS_WRITE_FILE },
			/* 456 */
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			/* 567 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			{ .level = 0 },
		},
	},
	{
		/* Multiple layers */
		2,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 456 }, .layer_start = 1 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			/* 123 */
			{ .level = 1, .access = 1 },
			/* 456 */
			{ .level = 1, .access = 2 },
			{ .level = 2, .access = 3 },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 100, 200, 500, 0 },
		(const uintptr_t[]){ 123, 456, 0 },
		(const access_mask_t[]){ 4, 5, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 456 }, .layer_start = 2 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			/* 123 */
			{ .level = 1, .access = 1 },
			{ .level = 3, .access = 4 },
			/* 456 */
			{ .level = 1, .access = 2 },
			{ .level = 2, .access = 3 },
			{ .level = 3, .access = 5 },
			{ .level = 0 },
		},
	},
	{
		/* Layer gaps */
		3,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 456 }, .layer_start = 2 },
			{ .key = { .data = 500 }, .layer_start = 4 },
			{ .key = { .data = 567 }, .layer_start = 5 },
			{ .key = { .data = 789 }, .layer_start = 6 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			/* 123 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			/* 456 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			{ .level = 3, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			/* 500 */
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			/* 567 */
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			/* 789 */
			{ .level = 3, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 100, 200, 499, 501, 800, 0 },
		(const uintptr_t[]){ 1, 123, 456, 567, 789, 999, 0 },
		(const access_mask_t[]){ LANDLOCK_ACCESS_FS_READ_FILE,
					 LANDLOCK_ACCESS_FS_READ_FILE,
					 LANDLOCK_ACCESS_FS_WRITE_FILE,
					 LANDLOCK_ACCESS_FS_EXECUTE,
					 LANDLOCK_ACCESS_FS_EXECUTE,
					 LANDLOCK_ACCESS_FS_IOCTL_DEV, 0 },
		(const struct landlock_domain_index[]){
			{ .key = { .data = 1 }, .layer_start = 0 },
			{ .key = { .data = 123 }, .layer_start = 1 },
			{ .key = { .data = 456 }, .layer_start = 4 },
			{ .key = { .data = 500 }, .layer_start = 7 },
			{ .key = { .data = 567 }, .layer_start = 8 },
			{ .key = { .data = 789 }, .layer_start = 10 },
			{ .key = { .data = 999 }, .layer_start = 12 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			/* 1 */
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			/* 123 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			/* 456 */
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			{ .level = 3, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_WRITE_FILE },
			/* 500 */
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			/* 567 */
			{ .level = 2, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			/* 789 */
			{ .level = 3, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_EXECUTE },
			/* 999 */
			{ .level = 4, .access = LANDLOCK_ACCESS_FS_IOCTL_DEV },
			{ .level = 0 } },
	},
	{
		2,
		(const struct landlock_domain_index[]){
			{ .key = { .data = 123 }, .layer_start = 0 },
			{ .key = { .data = 456 }, .layer_start = 1 },
			{ .key = { .data = 0 } },
		},
		(const struct landlock_layer[]){
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 1, .access = LANDLOCK_ACCESS_FS_READ_FILE },
			{ .level = 0 },
		},
		(const uintptr_t[]){ 100, 200, 500, 0 },
	},
};

static struct landlock_domain *
construct_test_domain(struct kunit *const test,
		      const struct dom_test_config *const tconfig, bool use_net)
{
	struct landlock_domain dom_sizes = {};
	struct landlock_domain *dom;
	const struct landlock_domain_index *ind = &tconfig->indices[0];
	const struct landlock_layer *l = &tconfig->layers[0];
	struct landlock_domain_index *ind_w;
	struct landlock_layer *l_w;

	dom_sizes.num_layers = tconfig->num_layers;

	while (ind->key.data != 0) {
		if (!use_net)
			dom_sizes.num_fs_indices++;
		else
			dom_sizes.num_net_indices++;
		ind++;
	}

	while (l->level != 0) {
		if (!use_net)
			dom_sizes.num_fs_layers++;
		else
			dom_sizes.num_net_layers++;
		WARN_ON(l->level > tconfig->num_layers);
		l++;
	}

	dom = landlock_alloc_domain(&dom_sizes);
	KUNIT_EXPECT_NOT_NULL(test, dom);
	if (!dom)
		return ERR_PTR(-ENOMEM);

	ind = &tconfig->indices[0];
	if (!use_net)
		ind_w = dom_fs_indices(dom);
	else
		ind_w = dom_net_indices(dom);

	while (ind->key.data != 0)
		*(ind_w++) = *(ind++);

	l = &tconfig->layers[0];
	if (!use_net)
		l_w = dom_fs_layers(dom);
	else
		l_w = dom_net_layers(dom);

	while (l->level != 0)
		*(l_w++) = *(l++);

	KUNIT_ASSERT_TRUE(test, domain_check_valid_bounds(dom));

	return dom;
}

static void _test_domain_find(struct kunit *const test,
			      const struct dom_test_config *const tc,
			      const struct landlock_domain *const dom,
			      bool use_net)
{
	const struct landlock_domain_index *ind = tc->indices;
	union landlock_key search_key;
	const uintptr_t *extra_searches = tc->extra_searches;
	struct landlock_found_rule found_rule;
	struct landlock_layer *layers_arr;

	while (ind->key.data != 0) {
		u32 expected_end;

		search_key.data = ind->key.data;
		if ((ind + 1)->key.data == 0) {
			if (!use_net)
				expected_end = dom->num_fs_layers;
			else
				expected_end = dom->num_net_layers;
		} else {
			expected_end = (ind + 1)->layer_start;
		}

		if (!use_net) {
			layers_arr = dom_fs_layers(dom);
			found_rule = dom_find_index_fs(dom, search_key);
		} else {
			layers_arr = dom_net_layers(dom);
			found_rule = dom_find_index_net(dom, search_key);
		}

		KUNIT_ASSERT_TRUE(test, dom_find_success(found_rule));
		KUNIT_ASSERT_EQ(test, ind->layer_start,
				found_rule.layers_start - layers_arr);
		KUNIT_ASSERT_GE(test, expected_end,
				found_rule.layers_end - layers_arr);

		/*
		 * Since we're only testing either fs or net (but not
		 * both), we make sure that any searches on the other
		 * indices return NULL.
		 */

		if (use_net)
			found_rule = dom_find_index_fs(dom, search_key);
		else
			found_rule = dom_find_index_net(dom, search_key);

		KUNIT_ASSERT_FALSE_MSG(
			test, dom_find_success(found_rule),
			"Finding key %zu in the other indices type should fail, but did not",
			search_key.data);

		ind++;
	}

	while (*extra_searches != 0) {
		search_key.data = *extra_searches++;

		found_rule = dom_find_index_fs(dom, search_key);
		KUNIT_ASSERT_FALSE_MSG(
			test, dom_find_success(found_rule),
			"Finding key %zu should fail, but did not",
			search_key.data);

		found_rule = dom_find_index_net(dom, search_key);
		KUNIT_ASSERT_FALSE_MSG(
			test, dom_find_success(found_rule),
			"Finding key %zu should fail, but did not",
			search_key.data);
	}
}

static void test_domain_find(struct kunit *const test)
{
	size_t test_i, test_j;

	for (test_i = 0; test_i < ARRAY_SIZE(kunit_dom_test_cases); test_i++) {
		for (test_j = 0; test_j < 2; test_j += 1) {
			bool use_net = test_j == 1;
			const struct dom_test_config *const tc =
				&kunit_dom_test_cases[test_i];
			struct landlock_domain *dom __free(kfree) = NULL;

			if (tc->num_layers == 0)
				continue;

			kunit_printk(KERN_INFO, test,
				     "test %zu.%zu: num_layers = %u\n", test_i,
				     test_j, tc->num_layers);

			dom = construct_test_domain(test, tc, use_net);
			if (IS_ERR_OR_NULL(dom))
				continue;

			_test_domain_find(test, tc, dom, use_net);
		}
	}
}

static struct landlock_domain *
_do_test_merge(struct kunit *const test, const struct dom_test_config *const tc,
	       struct landlock_domain *const parent_dom)
{
	struct rb_root rules_tree = RB_ROOT;
	const uintptr_t *merge_key = tc->rule_keys_to_merge;
	const access_mask_t *merge_access = tc->rule_accesses_to_merge;
	struct landlock_rule *flat_rules_buf __free(kfree) = NULL;
	size_t nb_rules = 0;
	u32 new_level = tc->num_layers + 1, next_index = 0;
	u32 indices_written, layers_written;
	const struct landlock_rule *next_rule;
	struct landlock_domain new_dom_sizes = {};
	struct landlock_domain *new_dom = NULL;

	while (*merge_key != 0) {
		nb_rules++;
		merge_key++;
	}
	merge_key = tc->rule_keys_to_merge;
	flat_rules_buf = kmalloc_array(nb_rules, sizeof(struct landlock_rule),
				       GFP_KERNEL);
	KUNIT_EXPECT_NOT_NULL(test, flat_rules_buf);
	if (!flat_rules_buf)
		return NULL;

	nb_rules = 0;

	while (*merge_key != 0) {
		struct rb_node **new = &rules_tree.rb_node, *parent = NULL;
		struct landlock_rule *rule = &flat_rules_buf[nb_rules++];

		KUNIT_EXPECT_NE(test, 0, *merge_access);
		rule->key.data = *merge_key;
		rule->num_layers = 1;
		rule->layers[0].level = 0;
		rule->layers[0].access = *merge_access;

		while (*new) {
			struct landlock_rule *this =
				container_of(*new, struct landlock_rule, node);
			parent = *new;
			if (rule->key.data < this->key.data)
				new = &(*new)->rb_left;
			else if (rule->key.data > this->key.data)
				new = &(*new)->rb_right;
			else {
				KUNIT_EXPECT_TRUE_MSG(
					test, false,
					"Merge test config must not contain rules with the same key");
				return NULL;
			}
		}

		rb_link_node(&rule->node, parent, new);
		rb_insert_color(&rule->node, &rules_tree);

		merge_key++;
		merge_access++;
	}

	next_rule =
		container_of(rb_first(&rules_tree), struct landlock_rule, node);

	new_dom_sizes.num_layers = new_level;

	while (landlock_merge_walk_step(
		parent_dom ? dom_fs_indices(parent_dom) : NULL,
		parent_dom ? parent_dom->num_fs_indices : 0,
		parent_dom ? dom_fs_layers(parent_dom) : NULL,
		parent_dom ? parent_dom->num_fs_layers : 0, new_level,
		&next_index, &next_rule, NULL, &new_dom_sizes.num_fs_indices,
		NULL, &new_dom_sizes.num_fs_layers)) {
	}

	new_dom_sizes.len_rules = dom_rules_len(&new_dom_sizes);
	KUNIT_ASSERT_TRUE(test, domain_check_valid_bounds(&new_dom_sizes));

	new_dom = landlock_alloc_domain(&new_dom_sizes);
	KUNIT_EXPECT_NOT_NULL(test, new_dom);
	if (!new_dom)
		return NULL;

	memcpy(new_dom, &new_dom_sizes, sizeof(new_dom_sizes));

	next_rule =
		container_of(rb_first(&rules_tree), struct landlock_rule, node);
	next_index = 0;
	indices_written = 0;
	layers_written = 0;

	while (landlock_merge_walk_step(
		parent_dom ? dom_fs_indices(parent_dom) : NULL,
		parent_dom ? parent_dom->num_fs_indices : 0,
		parent_dom ? dom_fs_layers(parent_dom) : NULL,
		parent_dom ? parent_dom->num_fs_layers : 0, new_level,
		&next_index, &next_rule, dom_fs_indices(new_dom),
		&indices_written, dom_fs_layers(new_dom), &layers_written)) {
	}

	KUNIT_ASSERT_EQ(test, indices_written, new_dom->num_fs_indices);
	KUNIT_ASSERT_EQ(test, layers_written, new_dom->num_fs_layers);

	return new_dom;
}

static void assert_indices_eq(struct kunit *const test,
			      const struct landlock_domain_index *expected,
			      const struct landlock_domain_index *actual,
			      size_t num_indices)
{
	size_t i;

	for (i = 0; i < num_indices; i++) {
		KUNIT_ASSERT_EQ_MSG(test, expected[i].key.data,
				    actual[i].key.data,
				    "Index %zu: expected key %zu, got %zu", i,
				    expected[i].key.data, actual[i].key.data);
		KUNIT_ASSERT_EQ_MSG(
			test, expected[i].layer_start, actual[i].layer_start,
			"Index %zu: expected layer index %u, got %u", i,
			expected[i].layer_start, actual[i].layer_start);
	}
}

static void assert_layers_eq(struct kunit *const test,
			     const struct landlock_layer *expected,
			     const struct landlock_layer *actual,
			     size_t num_layers)
{
	size_t i;

	for (i = 0; i < num_layers; i++) {
		KUNIT_ASSERT_EQ_MSG(test, expected[i].level, actual[i].level,
				    "Layer %zu: expected level %u, got %u", i,
				    expected[i].level, actual[i].level);
		KUNIT_ASSERT_EQ_MSG(test, expected[i].access, actual[i].access,
				    "Layer %zu: expected access %u, got %u", i,
				    expected[i].access, actual[i].access);
	}
}

static void test_domain_merge(struct kunit *const test)
{
	size_t test_i;

	for (test_i = 0; test_i < ARRAY_SIZE(kunit_dom_test_cases); test_i++) {
		const struct dom_test_config *const tc =
			&kunit_dom_test_cases[test_i];
		struct landlock_domain *dom __free(kfree) = NULL;
		struct landlock_domain *new_dom __free(kfree) = NULL;
		size_t expected_count;
		const struct landlock_domain_index *ind;
		const struct landlock_layer *l;

		if (!tc->rule_keys_to_merge)
			continue;

		kunit_printk(KERN_INFO, test, "test %zu: num_layers = %u\n",
			     test_i, tc->num_layers);

		if (tc->num_layers > 0)
			dom = construct_test_domain(test, tc, false);

		new_dom = _do_test_merge(test, tc, dom);
		if (IS_ERR_OR_NULL(new_dom)) {
			KUNIT_FAIL(test, "Failed to merge domain");
			continue;
		}

		kunit_printk(KERN_INFO, test,
			     "... merged num_indices = %u, num_layers = %u\n",
			     new_dom->num_fs_indices, new_dom->num_fs_layers);

		expected_count = 0;
		ind = tc->expected_merged_indices;
		while (ind->key.data != 0) {
			expected_count++;
			ind++;
		}

		KUNIT_ASSERT_EQ(test, expected_count, new_dom->num_fs_indices);
		assert_indices_eq(test, tc->expected_merged_indices,
				  dom_fs_indices(new_dom), expected_count);

		expected_count = 0;
		l = tc->expected_merged_layers;
		while (l->level != 0) {
			expected_count++;
			l++;
		}

		KUNIT_ASSERT_EQ(test, expected_count, new_dom->num_fs_layers);
		assert_layers_eq(test, tc->expected_merged_layers,
				 dom_fs_layers(new_dom), expected_count);
	}
}

static struct kunit_case test_cases[] = {
	/* clang-format off */
	KUNIT_CASE(test_domain_arr_macro_different_sizes),
	KUNIT_CASE(test_domain_find),
	KUNIT_CASE(test_domain_merge),
	{}
	/* clang-format on */
};

static struct kunit_suite test_suite = {
	.name = "landlock_domain_array",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);
