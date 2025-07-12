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

#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "access.h"
#include "ruleset.h"
#include "coalesced_hash.h"

struct landlock_domain_index {
	/**
	 * @key: The landlock object or port identifier.
	 */
	union landlock_key key;
	/**
	 * @next_collision: Points to another slot in the domain indices
	 * array, forming a collision chain in a coalesced hashtable.  See
	 * landlock_domain_find for how this is used.
	 */
	u32 next_collision;
	/**
	 * @layer_index: The index of the first landlock_layer corresponding
	 * to this key in the relevant subarray.  A rule may have multiple (at
	 * least one) layers.
	 */
	u32 layer_start;
	/**
	 * @layer_end: The non-inclusive index to the end of the layers for
	 * this rule.
	 */
	u32 layer_end;
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
	u16 num_layers;
	/**
	 * @fs_index_hash_bits: Precomputed hash bits for the fs table to
	 * avoid recomputing this power of 2 every hash.
	 */
	u8 fs_index_hash_bits;
	/**
	 * @net_index_hash_bits: Precomputed hash bits for the net table to
	 * avoid recomputing this power of 2 every hash.
	 */
	u8 net_index_hash_bits;
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
	 *     struct landlock_domain_index fs_indices[num_fs_indices];
	 *     struct landlock_domain_index net_indices[num_net_indices];
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

#define _dom_net_indices_offset(dom)                 \
	(_dom_fs_indices_offset(dom) +               \
	 array_size((size_t)((dom)->num_fs_indices), \
		    sizeof(struct landlock_domain_index)))

#define dom_net_indices(dom)                                     \
	((struct landlock_domain_index *)((char *)(dom)->rules + \
					  _dom_net_indices_offset(dom)))

#define _dom_fs_layers_offset(dom)                    \
	(_dom_net_indices_offset(dom) +               \
	 array_size((size_t)((dom)->num_net_indices), \
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
				  sizeof(struct landlock_layer)), \
	       sizeof(uintptr_t)) /                               \
	 sizeof(uintptr_t))

/*
 * We have to use layer_end for this as the key can be 0 for net rules.  A
 * valid index must have at least 1 layers, so layer_end will not be 0.
 */
#define dom_index_is_empty(elem) ((elem)->layer_end == 0)

/**
 * dom_index_hash_func - Hash function for the domain index tables.
 */
static inline h_index_t
dom_index_hash_func(const struct landlock_domain_index *elem,
		    const h_index_t table_size, const int hash_bits)
{
	if (hash_bits <= 0)
		/* hash_long requires hash_bits > 0 */
		return 0;
	return hash_long(elem->key.data, hash_bits);
}

static inline int get_hash_bits(const u32 table_size)
{
	if (table_size <= 1)
		return 0;
	return ilog2(roundup_pow_of_two(table_size));
}

DEFINE_COALESCED_HASH_TABLE(struct landlock_domain_index, dom_hash, key,
			    next_collision,
			    dom_index_hash_func(elem, table_size, hash_bits),
			    dom_index_is_empty(elem))

struct landlock_domain *
landlock_alloc_domain(const struct landlock_domain *sizes);

static inline void landlock_get_domain(struct landlock_domain *const domain)
{
	if (domain)
		refcount_inc(&domain->usage);
}

void landlock_put_domain(struct landlock_domain *const domain);
void landlock_put_domain_deferred(struct landlock_domain *const domain);

DEFINE_FREE(landlock_put_domain, struct landlock_domain *,
	    if (!IS_ERR_OR_NULL(_T)) landlock_put_domain(_T))

struct landlock_found_rule {
	/* start of layer range for the found rule */
	const struct landlock_layer *layers_start;
	/* non-inclusive end of layer range */
	const struct landlock_layer *layers_end;
};

/**
 * landlock_domain_find - search for a key in a domain.  Don't use this
 * function directly, but use one of the dom_find_index_*() macros
 * instead.
 *
 * @indices_arr: The indices array to search in.
 * @num_indices: The number of elements in @indices_arr.
 * @hash_bits: The corresponding hash_bits for the indices array.
 * @layers_arr: The layers array.
 * @num_layers: The number of elements in @layers_arr.
 * @key: The key to search for.
 */
static inline struct landlock_found_rule
landlock_domain_find(const struct landlock_domain_index *const indices_arr,
		     const u32 num_indices, const int hash_bits,
		     const struct landlock_layer *const layers_arr,
		     const u32 num_layers, const union landlock_key key)
{
	struct landlock_domain_index key_elem = {
		.key = key,
	};
	struct landlock_found_rule out_found_rule = {};
	const struct landlock_domain_index *found;

	found = dom_hash_find(indices_arr, num_indices, hash_bits, &key_elem);

	if (found) {
		if (WARN_ON_ONCE(found->layer_end > num_layers))
			return out_found_rule;
		out_found_rule.layers_start = &layers_arr[found->layer_start];
		out_found_rule.layers_end = &layers_arr[found->layer_end];
	}

	return out_found_rule;
}

#define dom_find_index_fs(dom, key)                                         \
	landlock_domain_find(dom_fs_indices(dom), (dom)->num_fs_indices,    \
			     (dom)->fs_index_hash_bits, dom_fs_layers(dom), \
			     (dom)->num_fs_layers, key)

#define dom_find_index_net(dom, key)                                          \
	landlock_domain_find(dom_net_indices(dom), (dom)->num_net_indices,    \
			     (dom)->net_index_hash_bits, dom_net_layers(dom), \
			     (dom)->num_net_layers, key)

#define dom_find_success(found_rule) ((found_rule).layers_start != NULL)

#define dom_rule_for_each_layer(found_rule, layer) \
	for (layer = (found_rule).layers_start;    \
	     layer < (found_rule).layers_end; layer++)

struct landlock_domain *
landlock_domain_merge_ruleset(const struct landlock_domain *parent,
			      struct landlock_ruleset *ruleset);

enum landlock_log_status {
	LANDLOCK_LOG_PENDING = 0,
	LANDLOCK_LOG_RECORDED,
	LANDLOCK_LOG_DISABLED,
};

/**
 * struct landlock_details - Domain's creation information
 *
 * Rarely accessed, mainly when logging the first domain's denial.
 *
 * The contained pointers are initialized at the domain creation time and never
 * changed again.  Contrary to most other Landlock object types, this one is
 * not allocated with GFP_KERNEL_ACCOUNT because its size may not be under the
 * caller's control (e.g. unknown exe_path) and the data is not explicitly
 * requested nor used by tasks.
 */
struct landlock_details {
	/**
	 * @pid: PID of the task that initially restricted itself.  It still
	 * identifies the same task.  Keeping a reference to this PID ensures that
	 * it will not be recycled.
	 */
	struct pid *pid;
	/**
	 * @uid: UID of the task that initially restricted itself, at creation time.
	 */
	uid_t uid;
	/**
	 * @comm: Command line of the task that initially restricted itself, at
	 * creation time.  Always NULL terminated.
	 */
	char comm[TASK_COMM_LEN];
	/**
	 * @exe_path: Executable path of the task that initially restricted
	 * itself, at creation time.  Always NULL terminated, and never greater
	 * than LANDLOCK_PATH_MAX_SIZE.
	 */
	char exe_path[];
};

/* Adds 11 extra characters for the potential " (deleted)" suffix. */
#define LANDLOCK_PATH_MAX_SIZE (PATH_MAX + 11)

/* Makes sure the greatest landlock_details can be allocated. */
static_assert(struct_size_t(struct landlock_details, exe_path,
			    LANDLOCK_PATH_MAX_SIZE) <= KMALLOC_MAX_SIZE);

/**
 * struct landlock_hierarchy - Node in a domain hierarchy
 */
struct landlock_hierarchy {
	/**
	 * @parent: Pointer to the parent node, or NULL if it is a root
	 * Landlock domain.
	 */
	struct landlock_hierarchy *parent;
	/**
	 * @usage: Number of potential children domains plus their parent
	 * domain.
	 */
	refcount_t usage;

#ifdef CONFIG_AUDIT
	/**
	 * @log_status: Whether this domain should be logged or not.  Because
	 * concurrent log entries may be created at the same time, it is still
	 * possible to have several domain records of the same domain.
	 */
	enum landlock_log_status log_status;
	/**
	 * @num_denials: Number of access requests denied by this domain.
	 * Masked (i.e. never logged) denials are still counted.
	 */
	atomic64_t num_denials;
	/**
	 * @id: Landlock domain ID, sets once at domain creation time.
	 */
	u64 id;
	/**
	 * @details: Information about the related domain.
	 */
	const struct landlock_details *details;
	/**
	 * @log_same_exec: Set if the domain is *not* configured with
	 * %LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF.  Set to true by default.
	 */
	u32 log_same_exec : 1,
		/**
		 * @log_new_exec: Set if the domain is configured with
		 * %LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON.  Set to false by default.
		 */
		log_new_exec : 1;
#endif /* CONFIG_AUDIT */
};

#ifdef CONFIG_AUDIT

deny_masks_t
landlock_get_deny_masks(const access_mask_t all_existing_optional_access,
			const access_mask_t optional_access,
			const layer_mask_t (*const layer_masks)[],
			size_t layer_masks_size);

int landlock_init_hierarchy_log(struct landlock_hierarchy *const hierarchy);

static inline void
landlock_free_hierarchy_details(struct landlock_hierarchy *const hierarchy)
{
	if (!hierarchy || !hierarchy->details)
		return;

	put_pid(hierarchy->details->pid);
	kfree(hierarchy->details);
}

#else /* CONFIG_AUDIT */

static inline int
landlock_init_hierarchy_log(struct landlock_hierarchy *const hierarchy)
{
	return 0;
}

static inline void
landlock_free_hierarchy_details(struct landlock_hierarchy *const hierarchy)
{
}

#endif /* CONFIG_AUDIT */

static inline void
landlock_get_hierarchy(struct landlock_hierarchy *const hierarchy)
{
	if (hierarchy)
		refcount_inc(&hierarchy->usage);
}

void landlock_put_hierarchy(struct landlock_hierarchy *hierarchy);

bool landlock_unmask_layers(const struct landlock_found_rule rule,
			    const access_mask_t access_request,
			    layer_mask_t (*const layer_masks)[],
			    const size_t masks_array_size);

access_mask_t
landlock_init_layer_masks(const struct landlock_domain *const domain,
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
