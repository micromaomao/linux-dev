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

typedef h_index_t (*hash_element_t)(const void *elem, h_index_t table_size,
				    int hash_bits);
typedef h_index_t (*get_next_collision_t)(const void *elem);
typedef void (*set_next_collision_t)(void *elem, h_index_t next_collision);
typedef bool (*compare_element_t)(const void *key_elem, const void *found_elem);
typedef bool (*element_is_empty_t)(const void *elem);

static inline void *h_find(const void *table, h_index_t table_size,
			   int hash_bits, size_t elem_size,
			   const void *elem_to_find, hash_element_t hash_elem,
			   get_next_collision_t get_next_collision,
			   compare_element_t compare_elem,
			   element_is_empty_t element_is_empty)
{
	h_index_t curr_index, next_collision;
	const void *curr_elem;

	if (unlikely(table_size == 0))
		return NULL;

	curr_index = hash_elem(elem_to_find, table_size, hash_bits);
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

static inline void h_initialize(void *table, h_index_t table_size,
				size_t elem_size,
				set_next_collision_t set_next_collision,
				element_is_empty_t element_is_empty)
{
	h_index_t i;
	void *elem;

	WARN_ON_ONCE(array_size(table_size, elem_size) == SIZE_MAX);

	for (i = 0; i < table_size; i++) {
		elem = table + i * elem_size;
		set_next_collision(elem, i);
	}
}

struct h_insert_scratch {
	/**
	 * @prev_index: For each slot which belongs in a collision chain,
	 * stores the index of the previous element in the chain.  (The next
	 * index in the chain is stored in the element itself.)
	 */
	h_index_t *prev_index;
	/**
	 * @next_free_index: This index moves from end of the table towards
	 * the beginning.
	 */
	h_index_t next_free_index;

	/*
	 * The following members just helps us avoid passing those arguments
	 * around all the time.
	 */
	h_index_t table_size;
	int hash_bits;
	void *table;
	size_t elem_size;
};

static inline int h_init_insert_scratch(struct h_insert_scratch *scratch,
					void *table, h_index_t table_size,
					size_t elem_size, int hash_bits)
{
	h_index_t i;

	if (table_size == 0) {
		memset(scratch, 0, sizeof(*scratch));
		scratch->table = table;
		scratch->elem_size = elem_size;
		return 0;
	}

	if (array_size(table_size, elem_size) == SIZE_MAX)
		return -ENOMEM;

	scratch->prev_index =
		kcalloc(table_size, sizeof(h_index_t), GFP_KERNEL_ACCOUNT);
	if (!scratch->prev_index)
		return -ENOMEM;

	for (i = 0; i < table_size; i++)
		scratch->prev_index[i] = i;

	scratch->table_size = table_size;
	scratch->hash_bits = hash_bits;
	scratch->next_free_index = table_size - 1;
	scratch->table = table;
	scratch->elem_size = elem_size;
	return 0;
}

static inline void h_free_insert_scratch(struct h_insert_scratch *scratch)
{
	if (!scratch)
		return;

	kfree(scratch->prev_index);
	memset(scratch, 0, sizeof(*scratch));
}

static inline h_index_t
__h_insert_get_next_free(struct h_insert_scratch *scratch,
			 element_is_empty_t element_is_empty)
{
	h_index_t index_to_ret = scratch->next_free_index;
	void *free_slot;

	if (WARN_ON_ONCE(index_to_ret >= scratch->table_size)) {
		/*
		 * We used up all the available slots already.  This isn't
		 * supposed to happen with correct usage.
		 */
		return 0;
	}

	free_slot = scratch->table + index_to_ret * scratch->elem_size;
	while (!element_is_empty(free_slot)) {
		if (WARN_ON_ONCE(index_to_ret == 0)) {
			/* We unexpectedly used up all slots. */
			return 0;
		}
		index_to_ret--;
		free_slot = scratch->table + index_to_ret * scratch->elem_size;
	}

	if (index_to_ret == 0)
		scratch->next_free_index = scratch->table_size;
	else
		scratch->next_free_index = index_to_ret - 1;

	return index_to_ret;
}

/**
 * __h_relocate_entry - Moves the element at idx_to_move to another free
 * slot, and make the original slot free.  We will update any chain links
 * (scratch->prev_index and target->next_collision).
 *
 * Returns the new index of the moved element.
 */
static inline h_index_t
__h_relocate_entry(struct h_insert_scratch *scratch, h_index_t idx_to_move,
		   get_next_collision_t get_next_collision,
		   set_next_collision_t set_next_collision,
		   element_is_empty_t element_is_empty)
{
	h_index_t move_to = __h_insert_get_next_free(scratch, element_is_empty);
	void *move_to_elem = scratch->table + move_to * scratch->elem_size;
	void *move_target_elem =
		scratch->table + idx_to_move * scratch->elem_size;
	h_index_t old_next = get_next_collision(move_target_elem);
	h_index_t old_prev = scratch->prev_index[idx_to_move];
	void *old_prev_elem = scratch->table + old_prev * scratch->elem_size;

	memcpy(move_to_elem, move_target_elem, scratch->elem_size);

	/*
	 * The logic here is essentially hlist_replace_rcu, except in the
	 * hlist case the tail have next == NULL, whereas in our case the tail
	 * has next set to itself.
	 */

	/*
	 * if move target already points to something else, it would have been
	 * memcpy'd across.
	 */
	if (old_next == idx_to_move)
		/*
		 * Need to fix the tail pointer - it points to itself.  It's own
		 * prev is correct already.
		 */
		set_next_collision(move_to_elem, move_to);
	else
		/*
		 * the next_collision would have been memcpy'd over, but we need to
		 * fix that next element's prev
		 */
		scratch->prev_index[old_next] = move_to;

	if (old_prev == idx_to_move)
		/* The moved element is a head.  Fix its prev. */
		scratch->prev_index[move_to] = move_to;
	else {
		/*
		 * Need to make the moved element's prev point to it, and copy over
		 * the prev pointer.
		 */
		set_next_collision(old_prev_elem, move_to);
		scratch->prev_index[move_to] = old_prev;
	}

	scratch->prev_index[idx_to_move] = idx_to_move;
	memset(move_target_elem, 0, scratch->elem_size);
	set_next_collision(move_target_elem, idx_to_move);

	return move_to;
}

static inline void h_insert(struct h_insert_scratch *scratch, const void *elem,
			    hash_element_t hash_elem,
			    get_next_collision_t get_next_collision,
			    set_next_collision_t set_next_collision,
			    element_is_empty_t element_is_empty)
{
	h_index_t target_idx, target_hash, moved_to;
	void *target_elem;

	if (WARN_ON_ONCE(!scratch->table || !scratch->table_size))
		return;
	if (WARN_ON_ONCE(scratch->next_free_index >= scratch->table_size))
		/*
		 * We used up all the available slots already.  This isn't
		 * supposed to happen with correct usage.
		 */
		return;
	if (WARN_ON_ONCE(element_is_empty(elem)))
		return;

	/*
	 * The general logic here is basically that we always insert the new
	 * element at its rightful place, but we move any existing element in
	 * that place around.  Consider these cases:
	 *
	 * 1. target slot is empty - we can just insert the new element.
	 *
	 * 2. target slot is occupied by an element that is in a collision
	 *    chain (but not the head).
	 *    In this case, we can just move that existing element to a free
	 *    slot, and insert the new element in its rightful place.  This
	 *    will start a new chain (the fact that the target slot is not a
	 *    head means that there is no existing chain with this hash).
	 *
	 * 3. target slot is occupied by the head of a chain (i.e. that
	 *    existing element is already in its "rightful place").  In this
	 *    case, we can still move that existing element to a free slot,
	 *    and steals its current place to use for the new element.  The
	 *    new element will become the new head of the chain, and will
	 *    point to the existing element.
	 */

	target_idx = hash_elem(elem, scratch->table_size, scratch->hash_bits);
	if (WARN_ON_ONCE(target_idx >= scratch->table_size))
		return;
	target_elem = scratch->table + target_idx * scratch->elem_size;

	if (element_is_empty(target_elem)) {
		/*
		 * Simple case - just insert it.  scratch->prev_index is already
		 * correctly initialized.
		 */
		memcpy(target_elem, elem, scratch->elem_size);
		set_next_collision(target_elem, target_idx);
	} else {
		target_hash = hash_elem(target_elem, scratch->table_size,
					scratch->hash_bits);
		moved_to = __h_relocate_entry(scratch, target_idx,
					      get_next_collision,
					      set_next_collision,
					      element_is_empty);
		memcpy(target_elem, elem, scratch->elem_size);
		if (target_hash == target_idx) {
			/* We should be in the collision chain of the original target */
			set_next_collision(target_elem, moved_to);
			WARN_ON_ONCE(scratch->prev_index[moved_to] != moved_to);
			scratch->prev_index[moved_to] = target_idx;
		} else {
			/* We are starting a new chain. */
			set_next_collision(target_elem, target_idx);
		}
	}
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
 * const @elem_type *elem, h_index_t table_size and int hash_bits.  If
 * this function is evaluated, table_size is always positive.
 * @is_empty_expr: An expression that evaluates to true if the element is
 * empty (i.e. not used).  Empty elements are not returned by find.  If
 * the zero value of @elem_type is not "empty", the caller must set all
 * the slots to empty before using the table.
 */
#define DEFINE_COALESCED_HASH_TABLE(elem_type, table_func_prefix, key_member,  \
				    next_collision_member, hash_expr,          \
				    is_empty_expr)                             \
	static inline h_index_t table_func_prefix##_hash_elem(                 \
		const void *_elem, h_index_t table_size, int hash_bits)        \
	{                                                                      \
		const elem_type *elem = _elem;                                 \
		return hash_expr;                                              \
	}                                                                      \
	static inline h_index_t table_func_prefix##_get_next_collision(        \
		const void *elem)                                              \
	{                                                                      \
		return ((const elem_type *)elem)->next_collision_member;       \
	}                                                                      \
	static inline void table_func_prefix##_set_next_collision(             \
		void *elem, h_index_t next_collision)                          \
	{                                                                      \
		((elem_type *)elem)->next_collision_member = next_collision;   \
	}                                                                      \
	static inline bool table_func_prefix##_compare_elem(                   \
		const void *key_elem, const void *found_elem)                  \
	{                                                                      \
		const elem_type *key = key_elem;                               \
		const elem_type *found = found_elem;                           \
		return key->key_member.data == found->key_member.data;         \
	}                                                                      \
	static inline bool table_func_prefix##_element_is_empty(               \
		const void *_elem)                                             \
	{                                                                      \
		const elem_type *elem = _elem;                                 \
		return is_empty_expr;                                          \
	}                                                                      \
	static inline const elem_type *table_func_prefix##_find(               \
		const elem_type *table, h_index_t table_size, int hash_bits,   \
		const elem_type *elem_to_find)                                 \
	{                                                                      \
		return h_find(table, table_size, hash_bits, sizeof(elem_type), \
			      elem_to_find, table_func_prefix##_hash_elem,     \
			      table_func_prefix##_get_next_collision,          \
			      table_func_prefix##_compare_elem,                \
			      table_func_prefix##_element_is_empty);           \
	}                                                                      \
	static inline void table_func_prefix##_initialize(                     \
		elem_type *table, h_index_t table_size)                        \
	{                                                                      \
		h_initialize(table, table_size, sizeof(elem_type),             \
			     table_func_prefix##_set_next_collision,           \
			     table_func_prefix##_element_is_empty);            \
	}                                                                      \
	static inline void table_func_prefix##_insert(                         \
		struct h_insert_scratch *scratch, const elem_type *elem)       \
	{                                                                      \
		h_insert(scratch, elem, table_func_prefix##_hash_elem,         \
			 table_func_prefix##_get_next_collision,               \
			 table_func_prefix##_set_next_collision,               \
			 table_func_prefix##_element_is_empty);                \
	}
