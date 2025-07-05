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
	 * or U32_MAX if this is the last entry in the chain.
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
				  sizeof(struct landlock_layer)), \
	       sizeof(uintptr_t)) /                               \
	 sizeof(uintptr_t))

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
	const struct landlock_layer *layers_start;
	const struct landlock_layer *layers_end;
};

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
		if (curr_entry->next_collision == U32_MAX)
			break;

		if (WARN_ON_ONCE(curr_entry->next_collision >= hash_size))
			break;

		probe_index = curr_entry->next_collision;
		curr_entry = &indices_arr[probe_index];
	} while (curr_entry->key.data != 0);

	return out_found_rule;
}

struct landlock_found_rule
landlock_domain_find(const struct landlock_domain *dom,
		     const struct landlock_domain_index *indices_arr,
		     u32 num_indices, const struct landlock_layer *layers_arr,
		     u32 num_layers, union landlock_key key);

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

/* Hashtable construction function for testing */
int build_hashtable(struct landlock_domain_index *indices,
		   u32 hash_size,
		   const struct landlock_rule **rules,
		   u32 num_rules,
		   struct landlock_layer *layers,
		   u32 layer_offset,
		   u32 *layers_written);

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

bool landlock_unmask_layers(const struct landlock_found_rule rule,
			    const access_mask_t access_request,
			    layer_mask_t (*const layer_masks)[],
			    const size_t masks_array_size);

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
