/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Domain hashtable mainpulation
 *
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_HASH_H
#define _SECURITY_LANDLOCK_HASH_H

#include <linux/slab.h>
#include <linux/hash.h>

#include "ruleset.h"

#define LANDLOCK_HASH_LINEAR_THRESHOLD 4

struct landlock_hashtable {
	struct hlist_head *hlist;

	/**
	 * @hash_bits: Number of bits in this hash index (i.e.  hlist has
	 * 2^this many elements).
	 */
	int hash_bits;
};

#define landlock_hash_for_each(rule, ht, i)                \
	for (i = 0; i < (1ULL << (ht)->hash_bits); i += 1) \
		hlist_for_each_entry(rule, &(ht)->hlist[i], hlist)

#define landlock_hash_for_each_safe(rule, tmp, ht, i)      \
	for (i = 0; i < (1ULL << (ht)->hash_bits); i += 1) \
		hlist_for_each_entry_safe(rule, tmp, &(ht)->hlist[i], hlist)

static inline int landlock_hash_init(const size_t expected_num_entries,
				     struct landlock_hashtable *out_ht)
{
	size_t table_sz = 1;
	int hash_bits = 0;

	/*
	 * For small tables, we just have one slot, essentially making lookups
	 * a linear search.  Doing a hash for small tables is not worth it.
	 */
	if (expected_num_entries > LANDLOCK_HASH_LINEAR_THRESHOLD) {
		table_sz = roundup_pow_of_two(expected_num_entries);
		hash_bits = fls_long(table_sz - 1);
	}

	/*
	 * We allocate a table even if expected_num_entries == 0 to avoid
	 * unnecessary branching in lookup code
	 */

	out_ht->hash_bits = hash_bits;
	out_ht->hlist = kcalloc(table_sz, sizeof(struct hlist_head),
				GFP_KERNEL_ACCOUNT);
	if (!out_ht->hlist) {
		return -ENOMEM;
	}

	return 0;
}

static inline void landlock_hash_free(struct landlock_hashtable *ht,
				      const enum landlock_key_type key_type)
{
	struct landlock_rule *rule;
	struct hlist_node *tmp;
	size_t i;

	if (key_type == LANDLOCK_KEY_INODE)
		might_sleep();

	if (!ht->hlist)
		return;

	landlock_hash_for_each_safe(rule, tmp, ht, i)
	{
		free_rule(rule, key_type);
	}
	kfree(ht->hlist);
	ht->hlist = NULL;
}

static inline u32 landlock_hash_key(const union landlock_key key,
				    const int hash_bits)
{
	if (hash_bits == 0) {
		return 0;
	}

	return hash_ptr((void *)key.data, hash_bits);
}

static inline struct landlock_rule *
landlock_hash_find(const struct landlock_hashtable *const ht,
		   const union landlock_key key)
{
	struct hlist_head *head;
	struct landlock_rule *rule;

	head = &ht->hlist[landlock_hash_key(key, ht->hash_bits)];

	hlist_for_each_entry(rule, head, hlist) {
		if (rule->key.data == key.data)
			return rule;
	}

	return NULL;
}

/**
 * @landlock_hash_count - Return number of entries in the hashtable.
 */
static inline size_t landlock_hash_count(const struct landlock_hashtable *ht)
{
	size_t num_entries = 0;
	struct landlock_rule *rule;
	size_t i;
	landlock_hash_for_each(rule, ht, i)
	{
		num_entries += 1;
	}
	return num_entries;
}
