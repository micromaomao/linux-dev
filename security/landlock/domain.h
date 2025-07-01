/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Domain management
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 * Copyright © 2024-2025 Microsoft Corporation
 * Copyright © 2025      Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_DOMAIN_H
#define _SECURITY_LANDLOCK_DOMAIN_H

#include <linux/bsearch.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "access.h"
#include "ruleset.h"

struct landlock_domain_index {
	/**
	 * @key: The landlock object or port identifier.
	 */
	union landlock_key key;
	/**
	 * @layer_start: The index of the first landlock_layer corresponding
	 * to this key in the relevant subarray.
	 */
	u32 layer_start;
	/**
	 * @layer_end: The non-inclusive end of this rule's range of layers.
	 */
	u32 layer_end;
	/**
	 * @next_collision: Index of the next entry in the collision chain,
	 * or UINT32_MAX if this is the last entry in the chain.
	 */
	u32 next_collision;
};

struct landlock_domain_work_free {
	struct work_struct work;
	struct landlock_domain *domain;
};

struct landlock_domain {
	/**
	 * @hierarchy: Enables hierarchy identification even when a parent
	 * domain vanishes.  This is needed for the ptrace protection.
	 */
	struct landlock_hierarchy *hierarchy;
	/**
	 * @work_free: Enables to free a domain within a lockless section.
	 * This is only used by landlock_put_domain_deferred() when @usage
	 * reaches zero. This is a pointer to an allocated struct in order to
	 * minimize the size of this struct. To prevent needing to allocate
	 * when freeing, this is pre-allocated on domain creation.
	 */
	struct landlock_domain_work_free *work_free;
	/**
	 * @usage: Number of processes (i.e. domains) or file descriptors
	 * referencing this ruleset.
	 */
	refcount_t usage;
	/**
	 * @num_layers: Number of layers in this domain.  This enables to
	 * check that all the layers allow an access request.
	 */
	u32 num_layers;
	/**
	 * @num_fs_indices: Number of non-overlapping (i.e. not for the same
	 * object) inode rules.
	 */
	u32 num_fs_indices;
	/**
	 * @num_net_indices: Number of non-overlapping (i.e. not for the same
	 * port) network rules.
	 */
	u32 num_net_indices;
	/**
	 * @num_fs_layers: Number of landlock_layer in the fs_layers array.
	 */
	u32 num_fs_layers;
	/**
	 * @num_net_layers: Number of landlock_layer in the net_layers array.
	 */
	u32 num_net_layers;
	/**
	 * @fs_hash_size: Size of the filesystem hashtable. Either equal to
	 * num_fs_indices (exact size) or the next power of 2 (for faster hashing).
	 */
	u32 fs_hash_size;
	/**
	 * @net_hash_size: Size of the network hashtable. Either equal to
	 * num_net_indices (exact size) or the next power of 2 (for faster hashing).
	 */
	u32 net_hash_size;
	/**
	 * @len_rules: Total length (in units of uintptr_t) of the rules
	 * array.  Used to check accesses are not out of bounds, but in theory
	 * this is always derivable from the other length fields.
	 */
	u32 len_rules;
	/**
	 * @rules: The rest of this struct consists of 5 dynamically-sized,
	 * arrays placed one after another, the contents of which are to be
	 * accessed with dom_ helper macros defined in this header.  They are:
	 *
	 *     struct access_masks access_masks[num_layers];
	 *     (possible alignment padding here)
	 *     struct landlock_domain_index fs_indices[fs_hash_size];
	 *     struct landlock_domain_index net_indices[net_hash_size];
	 *     struct landlock_layer fs_layers[num_fs_layers];
	 *     struct landlock_layer net_layers[num_net_layers];
	 *     (possible alignment padding here)
	 */
	uintptr_t rules[] __counted_by(len_rules);
};

#define dom_access_masks(dom) ((struct access_masks *)((dom)->rules))

#define _dom_fs_indices_offset(dom)                                        \
	(ALIGN(array_size((dom)->num_layers, sizeof(struct access_masks)), \
	       sizeof(uintptr_t)))

#define dom_fs_indices(dom)                                      \
	((struct landlock_domain_index *)((char *)(dom)->rules + \
			  _dom_fs_indices_offset(dom)))

#define _dom_net_indices_offset(dom)       \
	(_dom_fs_indices_offset(dom) +     \
	 array_size((dom)->fs_hash_size, \
		    sizeof(struct landlock_domain_index)))

#define dom_net_indices(dom)                                     \
	((struct landlock_domain_index *)((char *)(dom)->rules + \
			  _dom_net_indices_offset(dom)))

#define _dom_fs_layers_offset(dom)          \
	(_dom_net_indices_offset(dom) +     \
	 array_size((dom)->net_hash_size, \
		    sizeof(struct landlock_domain_index)))

#define dom_fs_layers(dom)                                \
	((struct landlock_layer *)((char *)(dom)->rules + \
		   _dom_fs_layers_offset(dom)))

#define _dom_net_layers_offset(dom)   \
	(_dom_fs_layers_offset(dom) + \
	 array_size((dom)->num_fs_layers, sizeof(struct landlock_layer)))

#define dom_net_layers(dom)                               \
	((struct landlock_layer *)((char *)(dom)->rules + \
		   _dom_net_layers_offset(dom)))

#define dom_rules_len(dom)                                        \
	(ALIGN(_dom_net_layers_offset(dom) +                      \
		       array_size((dom)->num_net_layers,          \
<<<<<<< HEAD
				  sizeof(struct landlock_layer)), \
	       sizeof(uintptr_t)) /                               \
	 sizeof(uintptr_t))
/* Hash function for domain keys */
static inline u32 domain_hash_key(union landlock_key key, u32 hash_size)
{
	/*
	 * Simple hash function: use the key data directly.
	 * For power-of-2 sizes, we can use bitwise AND for efficiency.
	 * For non-power-of-2 sizes, we use modulo.
	 */
	if (hash_size && (hash_size & (hash_size - 1)) == 0) {
		/* Power of 2: use fast bitwise AND */
		return (u32)key.data & (hash_size - 1);
	} else {
		/* Not power of 2: use modulo */
		return hash_size ? (u32)key.data % hash_size : 0;
	}
}

/* Check if a size is a power of 2 */
static inline bool is_power_of_2_u32(u32 x)
{
	return x && (x & (x - 1)) == 0;
}

/* Find the next power of 2 >= x */
static inline u32 next_power_of_2_u32(u32 x)
{
	if (x <= 1)
		return 1;
	return 1U << (32 - __builtin_clz(x - 1));
}

>>>>>>> 63f61f45bc7a (squash copilot changes)
struct landlock_domain *
landlock_alloc_domain(const struct landlock_domain *sizes);

{
	if (domain)
		refcount_inc(&domain->usage);
}

void landlock_put_domain(struct landlock_domain *const domain);
void landlock_put_domain_deferred(struct landlock_domain *const domain);

DEFINE_FREE(landlock_put_domain, struct landlock_domain *,
	    if (!IS_ERR_OR_NULL(_T)) landlock_put_domain(_T))

struct landlock_found_rule {
	const struct landlock_layer *layers_start;
	const struct landlock_layer *layers_end;
};

/**
 * landlock_domain_find_hash - search for a key in a domain using hashtable.
 *
 * @dom: The domain to search in.
 * @indices_arr: The indices hashtable array to search in.
 * @hash_size: The size of the hashtable.
 * @layers_arr: The layers array.
 * @num_layers: The number of elements in @layers_arr.
 * @key: The key to search for.
 *
 * Uses separate chaining within the array. Collisions are resolved by
 * following the next_collision chain starting from the ideal hash position.
 * This enables fast lookups with immediate termination when the ideal slot
 * is empty (key guaranteed not found) or when the collision chain ends.
 */
static inline struct landlock_found_rule
landlock_domain_find_hash(const struct landlock_domain *const dom,
		     const struct landlock_domain_index *const indices_arr,
		     const u32 hash_size,
		     const struct landlock_layer *const layers_arr,
		     const u32 num_layers, const union landlock_key key)
{
	struct landlock_found_rule out_found_rule = {};
	u32 probe_index;
	const struct landlock_domain_index *curr_entry;

	if (!hash_size || !indices_arr)
		return out_found_rule;

	probe_index = domain_hash_key(key, hash_size);
	curr_entry = &indices_arr[probe_index];

	/* Fast path: if ideal slot is empty, key is not in table */
	if (curr_entry->key.data == 0)
		return out_found_rule;

	/* Follow the collision chain */
	do {
		/* Found matching key */
		if (curr_entry->key.data == key.data) {
			if (WARN_ON_ONCE(curr_entry->layer_end > num_layers))
				return out_found_rule;

			out_found_rule.layers_start = &layers_arr[curr_entry->layer_start];
			out_found_rule.layers_end = &layers_arr[curr_entry->layer_end];
			return out_found_rule;
		}

		/* Move to next entry in collision chain */
		if (curr_entry->next_collision == UINT32_MAX)
			break;

		if (WARN_ON_ONCE(curr_entry->next_collision >= hash_size))
			break;

		probe_index = curr_entry->next_collision;
		curr_entry = &indices_arr[probe_index];
	} while (curr_entry->key.data != 0);

	return out_found_rule;
}

#define dom_find_index_fs(dom, key)                                           \
	landlock_domain_find_hash(dom, dom_fs_indices(dom), (dom)->fs_hash_size, \
		     dom_fs_layers(dom), (dom)->num_fs_layers, key)

#define dom_find_index_net(dom, key)                                      \
	landlock_domain_find_hash(dom, dom_net_indices(dom),                   \
		     (dom)->net_hash_size, dom_net_layers(dom), \
		     (dom)->num_net_layers, key)

#define dom_find_success(found_rule) ((found_rule).layers_start != NULL)

#define dom_rule_for_each_layer(found_rule, layer) \
	for (layer = (found_rule).layers_start;    \
	     layer < (found_rule).layers_end; layer++)

bool landlock_merge_walk_step(
	const struct landlock_domain_index *dom_ind_array,
	const u32 dom_num_indices,
	const struct landlock_layer *const dom_layer_array,
	const u32 dom_num_layers, const u32 new_level, u32 *const next_index,
	const struct landlock_rule **const next_rule,
	struct landlock_domain_index *const out_indices,
	u32 *const indices_written, struct landlock_layer *const out_layers,
	u32 *const layers_written);

struct landlock_domain *
landlock_domain_merge_ruleset(const struct landlock_domain *parent,
		      struct landlock_ruleset *ruleset);

/* Additional domain functions - these will be implemented in domain.c */
void landlock_put_hierarchy(struct landlock_hierarchy *hierarchy);

/* Hashtable construction function for testing */
int build_hashtable(struct landlock_domain_index *indices,
		   u32 hash_size,
		   const struct landlock_rule **rules,
		   u32 num_rules,
		   struct landlock_layer *layers,
		   u32 layer_offset,
		   u32 *layers_written);

bool landlock_domain_unmask_layers(const struct landlock_found_rule rule,
		    const access_mask_t access_request,
		    layer_mask_t (*const layer_masks)[],
		    const size_t masks_array_size);

access_mask_t
landlock_domain_init_layer_masks(const struct landlock_domain *const domain,
		  const access_mask_t access_request,
		  layer_mask_t (*const layer_masks)[],
		  const enum landlock_key_type key_type);

static inline access_mask_t
landlock_dom_get_fs_access_mask(const struct landlock_domain *const domain,
			const u16 layer_level)
{
	/* Handles all initially denied by default access rights. */
	return dom_access_masks(domain)[layer_level].fs |
	       _LANDLOCK_ACCESS_FS_INITIALLY_DENIED;
}

static inline access_mask_t
landlock_dom_get_net_access_mask(const struct landlock_domain *const domain,
			 const u16 layer_level)
{
	return dom_access_masks(domain)[layer_level].net;
}

static inline access_mask_t
landlock_dom_get_scope_mask(const struct landlock_domain *const domain,
		    const u16 layer_level)
{
	return dom_access_masks(domain)[layer_level].scope;
}

/**
 * landlock_dom_union_access_masks - Return all access rights handled in
 * the domain
 *
 * @domain: Landlock domain
 *
 * Returns: an access_masks result of the OR of all the domain's access masks.
 */
static inline struct access_masks
landlock_dom_union_access_masks(const struct landlock_domain *const domain)
{
	union access_masks_all matches = {};
	size_t layer_level;

	for (layer_level = 0; layer_level < domain->num_layers; layer_level++) {
		union access_masks_all layer = {
			.masks = dom_access_masks(domain)[layer_level],
		};

		matches.all |= layer.all;
	}

	return matches.masks;
}

#endif /* _SECURITY_LANDLOCK_DOMAIN_H */
