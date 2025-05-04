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
#include <linux/rculist.h>

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

/**
 * @landlock_hash_insert - Insert a rule in the hashtable, taking
 * ownership of the passed in struct landlock_rule. This function assumes
 * that the rule is already in the hash table.
 */
static inline void landlock_hash_insert(const struct landlock_hashtable *ht,
					struct landlock_rule *const new_rule)
{
	struct hlist_head *head =
		&ht->hlist[landlock_hash_key(new_rule->key, ht->hash_bits)];

	hlist_add_head(&new_rule->hlist, head);
}

static inline int
landlock_hash_clone(struct landlock_hashtable *const dst,
		    const struct landlock_hashtable *const src,
		    const enum landlock_key_type key_type)
{
	struct landlock_rule *curr_rule, *new_rule;
	struct landlock_id id = {
		.type = key_type,
	};
	size_t i;

	landlock_hash_for_each(curr_rule, src, i)
	{
		id.key = curr_rule->key;
		new_rule = landlock_create_rule(id, &curr_rule->layers,
						curr_rule->num_layers, NULL);

		if (IS_ERR(new_rule)) {
			return PTR_ERR(new_rule);
		}

		/*
		 * new_rule->hlist is invalid, but should still be safe to pass to
		 * hlist_add_head().
		 */
		landlock_hash_insert(dst, new_rule);
	}

	return 0;
}

/**
 * @landlock_hash_upsert - Either insert a new rule with the new layer in
 * the hashtable, or update an existing one, adding the new layer.
 *
 * Hash table must have at least one slot.  This function doesn't take any
 * locks - it's only valid to call this on a newly created (not yet
 * committed to creds) domain.
 *
 * May error with -ENOMEM.
 */
static inline int landlock_hash_upsert(struct landlock_hashtable *const ht,
				       union landlock_key key,
				       const enum landlock_key_type key_type,
				       struct landlock_layer new_layer)
{
	size_t index = landlock_hash_key(key, ht->hash_bits);
	struct hlist_head *head = &ht->hlist[index];
	struct landlock_rule *curr_rule, *new_rule;
	const struct landlock_id id = {
		.type = key_type,
		.key = key,
	};

	hlist_for_each_entry(curr_rule, head, hlist) {
		if (curr_rule->key.data != key.data)
			continue;

		new_rule = landlock_create_rule(id, &curr_rule->layers,
						curr_rule->num_layers,
						&new_layer);
		if (IS_ERR(new_rule))
			return PTR_ERR(new_rule);

		/*
		 * Replace curr_rule with new_rule in place within the hlist
		 * We don't really care about RCU... but there's no "hlist_replace"
		 * We should be safe to call hlist_replace_rcu() without first
		 * initializing new_rule->hlist
		 */
		hlist_replace_rcu(&curr_rule->hlist, &new_rule->hlist);
		free_rule(curr_rule, key_type);
		return 0;
	}

	/* No existing rules found, insert new one. */
	new_rule = landlock_create_rule(id, NULL, 0, &new_layer);
	if (IS_ERR(new_rule))
		return PTR_ERR(new_rule);

	/*
	 * new_rule->hlist is invalid, but should still be safe to pass to
	 * hlist_add_head().
	 */
	hlist_add_head(&new_rule->hlist, head);
	return 0;
}

static inline void
landlock_hash_debug_print(const struct landlock_hashtable *ht,
			  const enum landlock_key_type key_type)
{
	size_t max_hlist_len = 0, slot_index = 0, num_rules = 0;

	for (slot_index = 0; slot_index < (1ULL << ht->hash_bits);
	     slot_index += 1) {
		struct hlist_head *head = &ht->hlist[slot_index];
		struct landlock_rule *rule;
		size_t rule_index = 0;
		spinlock_t *lock;

		pr_debug("  [%zu]: first = %p\n", slot_index, head->first);

		hlist_for_each_entry(rule, head, hlist) {
			size_t j;

			switch (key_type) {
			case LANDLOCK_KEY_INODE:
				lock = &rule->key.object->lock;
				spin_lock(lock);
				struct inode *inode =
					((struct inode *)
						 rule->key.object->underobj);
				if (inode) {
					pr_debug(
						"    [%zu] rule: ino %lu (%p), %d layers\n",
						rule_index, inode->i_ino, inode,
						rule->num_layers);
				} else {
					pr_debug(
						"    [%zu] rule: inode released, %d layers\n",
						rule_index, rule->num_layers);
				}
				spin_unlock(lock);
				break;
			case LANDLOCK_KEY_NET_PORT:
				pr_debug(
					"    [%zu] rule: port %lu, %d layers\n",
					rule_index, rule->key.data,
					rule->num_layers);
				break;
			}
			for (j = 0; j < rule->num_layers; j++) {
				pr_debug("      layer %u: access %x\n",
					 rule->layers[j].level,
					 rule->layers[j].access);
			}
			rule_index += 1;
			num_rules += 1;
		}

		if (rule_index > max_hlist_len)
			max_hlist_len = rule_index;
	}

	pr_debug("  summary: %zu rules, %llu hash slots, "
		 "%zu max hlist chain len\n",
		 num_rules, (1ULL << ht->hash_bits), max_hlist_len);
}

#endif /* _SECURITY_LANDLOCK_HASH_H */
