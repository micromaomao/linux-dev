/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - utility functions for handling a compact coalesced hash
 * tables.
 *
 * A coalesced hash table is an array (typically completely filled), where
 * each element has a next_collision field that contains the index to the
 * next collision in the chain.  If there is no next collision, the
 * next_collision field is set to the index of the element itself.  A
 * search for a particular key starts at the index that it hashes to, then
 * we follow the chain of collisions until the key is found or we reach
 * the end of the chain.  Before starting the collision chain loop, if we
 * found that the element at the index we hashed to does not in fact hash
 * to its index, then we know that there is no elements with our hash, and
 * so we can terminate early.
 *
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#include <linux/mm.h>
#include <linux/types.h>

typedef u32 h_index_t;

typedef h_index_t (*hash_element_t)(const void *elem, h_index_t table_size);
typedef h_index_t (*get_next_collision_t)(const void *elem);
typedef void (*set_next_collision_t)(void *elem, h_index_t next_collision);
typedef bool (*compare_element_t)(const void *key_elem, const void *found_elem);
typedef bool (*element_is_empty_t)(const void *elem);

static inline void *h_find(const void *table, h_index_t table_size,
			   size_t elem_size, const void *elem_to_find,
			   hash_element_t hash_elem,
			   get_next_collision_t get_next_collision,
			   compare_element_t compare_elem,
			   element_is_empty_t element_is_empty)
{
	h_index_t curr_index, next_collision;
	const void *curr_elem;

	if (unlikely(table_size == 0))
		return NULL;

	curr_index = hash_elem(elem_to_find, table_size);
	if (WARN_ON_ONCE(curr_index >= table_size))
		return NULL;
	curr_elem = table + curr_index * elem_size;
	if (compare_elem(elem_to_find, curr_elem))
		return (void *)curr_elem;

	if (element_is_empty(curr_elem))
		return NULL;
	next_collision = get_next_collision(curr_elem);
	while (next_collision != curr_index) {
		curr_index = next_collision;
		curr_elem = table + curr_index * elem_size;
		if (compare_elem(elem_to_find, curr_elem))
			return (void *)curr_elem;
		next_collision = get_next_collision(curr_elem);
	}

	return NULL;
}

/**
 * DEFINE_COALESCED_HASH_TABLE - Define a set of functions to mainpulate a
 * coalesced hash table holding elements of type @elem_type.
 *
 * @elem_type: The type of the elements.
 * @table_func_prefix: The prefix to use for the functions.
 * @key_member: The name of a member in @elem_type that contains the key
 * (to compare for equality).
 * @next_collision_member: The name of a member in @elem_type that is used
 * to store the index of the next collision in a collision chain.
 * @hash_expr: An expression that computes the hash of an element, given
 * const @elem_type *elem and h_index_t table_size.  If this function is
 * evaluated, table_size is always positive.
 * @is_empty_expr: An expression that evaluates to true if the element is
 * empty (i.e. not used).  Empty elements are not returned by find.  If
 * the zero value of @elem_type is not "empty", the caller must set all
 * the slots to empty before using the table.
 */
#define DEFINE_COALESCED_HASH_TABLE(elem_type, table_func_prefix, key_member, \
				    next_collision_member, hash_expr,         \
				    is_empty_expr)                            \
	static inline h_index_t table_func_prefix##_hash_elem(                \
		const void *_elem, h_index_t table_size)                      \
	{                                                                     \
		const elem_type *elem = _elem;                                \
		return hash_expr;                                             \
	}                                                                     \
	static inline h_index_t table_func_prefix##_get_next_collision(       \
		const void *elem)                                             \
	{                                                                     \
		return ((const elem_type *)elem)->next_collision_member;      \
	}                                                                     \
	static inline void table_func_prefix##_set_next_collision(            \
		void *elem, h_index_t next_collision)                         \
	{                                                                     \
		((elem_type *)elem)->next_collision_member = next_collision;  \
	}                                                                     \
	static inline bool table_func_prefix##_compare_elem(                  \
		const void *key_elem, const void *found_elem)                 \
	{                                                                     \
		const elem_type *key = key_elem;                              \
		const elem_type *found = found_elem;                          \
		return key->key_member.data == found->key_member.data;        \
	}                                                                     \
	static inline bool table_func_prefix##_element_is_empty(              \
		const void *_elem)                                            \
	{                                                                     \
		const elem_type *elem = _elem;                                \
		return is_empty_expr;                                         \
	}                                                                     \
	static inline const elem_type *table_func_prefix##_find(              \
		const elem_type *table, h_index_t table_size,                 \
		const elem_type *elem_to_find)                                \
	{                                                                     \
		return h_find(table, table_size, sizeof(elem_type),           \
			      elem_to_find, table_func_prefix##_hash_elem,    \
			      table_func_prefix##_get_next_collision,         \
			      table_func_prefix##_compare_elem,               \
			      table_func_prefix##_element_is_empty);          \
	}
