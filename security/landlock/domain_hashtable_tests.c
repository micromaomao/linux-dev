// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Unit tests for hashtable-based domain implementation
 *
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#include <kunit/test.h>
#include <linux/sort.h>

#include "common.h"
#include "ruleset.h"
#include "domain.h"

/**
 * Test hash function for both power-of-2 and non-power-of-2 sizes
 */
static void test_domain_hash_key(struct kunit *test)
{
	union landlock_key key1 = { .data = 12345 };
	union landlock_key key2 = { .data = 67890 };
	
	/* Test power-of-2 size (fast path with bitwise AND) */
	u32 hash_size_p2 = 16; /* Power of 2 */
	u32 hash1_p2 = domain_hash_key(key1, hash_size_p2);
	u32 hash2_p2 = domain_hash_key(key2, hash_size_p2);
	
	KUNIT_EXPECT_LT(test, hash1_p2, hash_size_p2);
	KUNIT_EXPECT_LT(test, hash2_p2, hash_size_p2);
	KUNIT_EXPECT_EQ(test, hash1_p2, (u32)key1.data & (hash_size_p2 - 1));
	
	/* Test non-power-of-2 size (modulo path) */
	u32 hash_size_np2 = 15; /* Not power of 2 */
	u32 hash1_np2 = domain_hash_key(key1, hash_size_np2);
	u32 hash2_np2 = domain_hash_key(key2, hash_size_np2);
	
	KUNIT_EXPECT_LT(test, hash1_np2, hash_size_np2);
	KUNIT_EXPECT_LT(test, hash2_np2, hash_size_np2);
	KUNIT_EXPECT_EQ(test, hash1_np2, (u32)key1.data % hash_size_np2);
}

/**
 * Test power-of-2 detection utility function
 */
static void test_is_power_of_2_u32(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(1));
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(2));
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(4));
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(8));
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(16));
	KUNIT_EXPECT_TRUE(test, is_power_of_2_u32(1024));
	
	KUNIT_EXPECT_FALSE(test, is_power_of_2_u32(0));
	KUNIT_EXPECT_FALSE(test, is_power_of_2_u32(3));
	KUNIT_EXPECT_FALSE(test, is_power_of_2_u32(5));
	KUNIT_EXPECT_FALSE(test, is_power_of_2_u32(15));
	KUNIT_EXPECT_FALSE(test, is_power_of_2_u32(100));
}

/**
 * Test basic hashtable lookup functionality with linear probing
 */
static void test_hashtable_lookup(struct kunit *test)
{
	/* Create a simple domain with hashtable */
	struct landlock_domain test_domain = {};
	struct landlock_domain_index indices[8];
	struct landlock_layer layers[3];
	
	/* Choose keys that will create a collision in hashtable size 8 */
	union landlock_key key1 = { .data = 1 };  /* hash = 1 & 7 = 1 */
	union landlock_key key2 = { .data = 9 };  /* hash = 9 & 7 = 1 (collision!) */
	union landlock_key key3 = { .data = 17 }; /* hash = 17 & 7 = 1 (collision!) */
	union landlock_key key_missing = { .data = 999 };
	
	/* Initialize domain structure */
	test_domain.fs_hash_size = 8;
	test_domain.num_fs_layers = 3;
	
	/* Set up test data in hashtable manually with collision chaining */
	memset(indices, 0, sizeof(indices));
	memset(layers, 0, sizeof(layers));
	
	/* Initialize collision chains */
	for (int i = 0; i < 8; i++) {
		indices[i].next_collision = U32_MAX;
	}
	
	/* Insert first entry at its hash position */
	u32 hash1 = domain_hash_key(key1, 8);
	KUNIT_EXPECT_EQ(test, hash1, 1); /* Verify our expectation */
	indices[hash1].key = key1;
	indices[hash1].layer_start = 0;
	indices[hash1].layer_end = 1;
	indices[hash1].next_collision = U32_MAX;
	
	/* Insert second entry with collision - place in any empty slot and chain */
	u32 hash2 = domain_hash_key(key2, 8);
	KUNIT_EXPECT_EQ(test, hash2, 1); /* Should collide with key1 */
	indices[2].key = key2; /* Place in empty slot 2 */
	indices[2].layer_start = 1;
	indices[2].layer_end = 2;
	indices[2].next_collision = U32_MAX;
	indices[1].next_collision = 2; /* Chain from key1 to key2 */
	
	/* Insert third entry with collision - place in any empty slot and chain */
	u32 hash3 = domain_hash_key(key3, 8);
	KUNIT_EXPECT_EQ(test, hash3, 1); /* Should collide with key1 and key2 */
	indices[3].key = key3; /* Place in empty slot 3 */
	indices[3].layer_start = 2;
	indices[3].layer_end = 3;
	indices[3].next_collision = U32_MAX;
	indices[2].next_collision = 3; /* Chain from key2 to key3 */
	
	/* Test lookups */
	struct landlock_found_rule result1 = 
		landlock_domain_find_hash(&test_domain, indices, 8, layers, 3, key1);
	KUNIT_EXPECT_NOT_NULL(test, result1.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result1.layers_start, &layers[0]);
	KUNIT_EXPECT_PTR_EQ(test, result1.layers_end, &layers[1]);
	
	struct landlock_found_rule result2 = 
		landlock_domain_find_hash(&test_domain, indices, 8, layers, 3, key2);
	KUNIT_EXPECT_NOT_NULL(test, result2.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result2.layers_start, &layers[1]);
	KUNIT_EXPECT_PTR_EQ(test, result2.layers_end, &layers[2]);
	
	struct landlock_found_rule result3 = 
		landlock_domain_find_hash(&test_domain, indices, 8, layers, 3, key3);
	KUNIT_EXPECT_NOT_NULL(test, result3.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result3.layers_start, &layers[2]);
	KUNIT_EXPECT_PTR_EQ(test, result3.layers_end, &layers[3]);
	
	/* Test missing key */
	struct landlock_found_rule result_missing = 
		landlock_domain_find_hash(&test_domain, indices, 8, layers, 3, key_missing);
	KUNIT_EXPECT_NULL(test, result_missing.layers_start);
	KUNIT_EXPECT_NULL(test, result_missing.layers_end);
}

/**
 * Test domain allocation with hashtable sizing
 */
static void test_domain_allocation(struct kunit *test)
{
	struct landlock_domain sizes = {};
	sizes.num_layers = 2;
	sizes.num_fs_indices = 10;
	sizes.num_net_indices = 5;
	sizes.num_fs_layers = 15;
	sizes.num_net_layers = 8;
	
	struct landlock_domain *domain = landlock_alloc_domain(&sizes);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	
	/* Check that hashtable sizes are set appropriately */
	KUNIT_EXPECT_GT(test, domain->fs_hash_size, 0);
	KUNIT_EXPECT_GT(test, domain->net_hash_size, 0);
	
	/* Hashtable size should be larger than num_indices for good load factor */
	KUNIT_EXPECT_GE(test, domain->fs_hash_size, domain->num_fs_indices);
	KUNIT_EXPECT_GE(test, domain->net_hash_size, domain->num_net_indices);
	
	/* Verify domain structure is properly initialized */
	KUNIT_EXPECT_EQ(test, domain->num_layers, 2);
	KUNIT_EXPECT_EQ(test, domain->num_fs_indices, 10);
	KUNIT_EXPECT_EQ(test, domain->num_net_indices, 5);
	KUNIT_EXPECT_EQ(test, domain->num_fs_layers, 15);
	KUNIT_EXPECT_EQ(test, domain->num_net_layers, 8);
	
	landlock_put_domain(domain);
}

/**
 * Test hashtable collision handling with explicit chaining
 */
static void test_hashtable_collision_chaining(struct kunit *test)
{
	struct landlock_domain_index indices[10];
	struct landlock_layer layers[10];
	u32 hash_size = 10;
	u32 layers_written = 0;
	
	/* Create keys that will hash to the same value to test chaining */
	union landlock_key keys[5];
	const struct landlock_rule *rules[5];
	
	/* Allocate actual rules with proper sizes for flexible array member */
	struct landlock_rule *actual_rules[5];
	struct landlock_layer rule_layers[5];
	
	/* Set up keys - mix of non-colliding and colliding keys */
	keys[0].data = 7;  /* hashes to 7 % 10 = 7 */
	keys[1].data = 17; /* hashes to 17 % 10 = 7, collision with keys[0] */
	keys[2].data = 27; /* hashes to 27 % 10 = 7, collision with keys[0] and keys[1] */
	keys[3].data = 8;  /* hashes to 8 % 10 = 8, no collision */
	keys[4].data = 9;  /* hashes to 9 % 10 = 9, no collision */
	
	/* Initialize layers and rules */
	for (int i = 0; i < 5; i++) {
		/* Allocate rule with space for 1 layer */
		actual_rules[i] = kzalloc(sizeof(struct landlock_rule) + 
					  sizeof(struct landlock_layer), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, actual_rules[i]);
		
		rule_layers[i].level = i + 1;
		rule_layers[i].access = 0x1 << i;
		
		actual_rules[i]->key = keys[i];
		actual_rules[i]->num_layers = 1;
		actual_rules[i]->layers[0] = rule_layers[i];
		rules[i] = actual_rules[i];
	}
	
	/* Build hashtable - this should succeed */
	int result = build_hashtable(indices, hash_size, rules, 5, layers, 0, &layers_written);
	KUNIT_EXPECT_EQ(test, result, 0);
	KUNIT_EXPECT_EQ(test, layers_written, 5);
	
	/* Verify that entries are placed correctly with chaining */
	/* keys[0] (data=7) should be at its ideal position 7 */
	KUNIT_EXPECT_EQ(test, indices[7].key.data, 7);
	
	/* keys[3] (data=8) should be at its ideal position 8 */
	KUNIT_EXPECT_EQ(test, indices[8].key.data, 8);
	
	/* keys[4] (data=9) should be at its ideal position 9 */
	KUNIT_EXPECT_EQ(test, indices[9].key.data, 9);
	
	/* Colliding keys (17, 27) should be placed somewhere and chained from position 7 */
	bool found_17 = false, found_27 = false;
	for (int i = 0; i < 10; i++) {
		if (indices[i].key.data == 17) found_17 = true;
		if (indices[i].key.data == 27) found_27 = true;
	}
	KUNIT_EXPECT_TRUE(test, found_17);
	KUNIT_EXPECT_TRUE(test, found_27);
	
	/* Verify that collision chain from position 7 includes both colliding keys */
	/* Follow the chain from position 7 */
	u32 curr_index = 7;
	bool chain_has_17 = false, chain_has_27 = false;
	int chain_length = 0;
	
	while (curr_index != U32_MAX && chain_length < 10 /* prevent infinite loop */) {
		if (indices[curr_index].key.data == 17) chain_has_17 = true;
		if (indices[curr_index].key.data == 27) chain_has_27 = true;
		curr_index = indices[curr_index].next_collision;
		chain_length++;
	}
	
	KUNIT_EXPECT_TRUE(test, chain_has_17);
	KUNIT_EXPECT_TRUE(test, chain_has_27);
	KUNIT_EXPECT_EQ(test, chain_length, 3); /* Should have 3 entries (7, 17, 27) */
	
	/* Free allocated rules */
	for (int i = 0; i < 5; i++) {
		kfree(actual_rules[i]);
	}
}

/**
 * Test chaining early termination for missing keys
 */
static void test_chaining_early_termination(struct kunit *test)
{
	struct landlock_domain test_domain = {};
	struct landlock_domain_index indices[8];
	struct landlock_layer layers[4];
	
	/* 
	 * Set up a hashtable with collision chaining.
	 * Keys that hash to position 1 are chained together using next_collision.
	 */
	union landlock_key key1 = { .data = 1 };  /* hash = 1, placed at position 1 */
	union landlock_key key2 = { .data = 9 };  /* hash = 1, placed at position 2 (collision) */
	union landlock_key key3 = { .data = 17 }; /* hash = 1, placed at position 3 (collision) */
	
	/* Key that should terminate fast when ideal slot is empty */
	union landlock_key missing_key = { .data = 33 }; /* hash = 1, but not in table */
	
	/* Key that should terminate fast when ideal slot is empty */
	union landlock_key missing_key2 = { .data = 42 }; /* hash = 2, ideal slot empty */
	
	/* Initialize domain structure */
	test_domain.fs_hash_size = 8;
	test_domain.num_fs_layers = 4;
	
	/* Set up test data */
	memset(indices, 0, sizeof(indices));
	memset(layers, 0, sizeof(layers));
	
	/* Initialize collision chains */
	for (int i = 0; i < 8; i++) {
		indices[i].next_collision = U32_MAX;
	}
	
	/* Set up collision chain starting from position 1 (all hash to 1) */
	indices[1].key = key1;
	indices[1].layer_start = 0;
	indices[1].layer_end = 1;
	indices[1].next_collision = 2; /* Points to key2 */
	
	indices[2].key = key2;
	indices[2].layer_start = 1;
	indices[2].layer_end = 2;
	indices[2].next_collision = 3; /* Points to key3 */
	
	indices[3].key = key3;
	indices[3].layer_start = 2;
	indices[3].layer_end = 3;
	indices[3].next_collision = U32_MAX; /* End of chain */
	
	/* 
	 * Add an unrelated entry at position 5 to show that we don't scan
	 * outside the collision chain.
	 */
	union landlock_key key5 = { .data = 5 }; /* hash = 5, placed at position 5 */
	indices[5].key = key5;
	indices[5].layer_start = 3;
	indices[5].layer_end = 4;
	indices[5].next_collision = U32_MAX;
	
	/* 
	 * Test missing key lookup (same hash as existing chain): should follow 
	 * the collision chain from position 1 and check each entry, but should 
	 * not find a match and terminate at end of chain.
	 */
	struct landlock_found_rule result = 
		landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, missing_key);
	
	/* Should return not found */
	KUNIT_EXPECT_NULL(test, result.layers_start);
	KUNIT_EXPECT_NULL(test, result.layers_end);
	
	/* 
	 * Test missing key lookup (ideal slot empty): should check position 2 
	 * (hash of 42), find it empty, and terminate immediately.
	 */
	result = landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, missing_key2);
	
	/* Should return not found */
	KUNIT_EXPECT_NULL(test, result.layers_start);
	KUNIT_EXPECT_NULL(test, result.layers_end);
	
	/* Verify existing keys in the chain still work */
	result = landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, key1);
	KUNIT_EXPECT_NOT_NULL(test, result.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result.layers_start, &layers[0]);
	
	result = landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, key2);
	KUNIT_EXPECT_NOT_NULL(test, result.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result.layers_start, &layers[1]);
	
	result = landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, key3);
	KUNIT_EXPECT_NOT_NULL(test, result.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result.layers_start, &layers[2]);
	
	/* Verify non-colliding key works */
	result = landlock_domain_find_hash(&test_domain, indices, 8, layers, 4, key5);
	KUNIT_EXPECT_NOT_NULL(test, result.layers_start);
	KUNIT_EXPECT_PTR_EQ(test, result.layers_start, &layers[3]);
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_domain_hash_key),
	KUNIT_CASE(test_is_power_of_2_u32),
	KUNIT_CASE(test_hashtable_lookup),
	KUNIT_CASE(test_domain_allocation),
	KUNIT_CASE(test_hashtable_collision_chaining),
	KUNIT_CASE(test_chaining_early_termination),
	{}
};

static struct kunit_suite test_suite = {
	.name = "landlock_domain_hashtable",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);