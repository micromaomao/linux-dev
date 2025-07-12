/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright © 2025 Microsoft Corporation
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM landlock

#if !defined(_TRACE_LANDLOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LANDLOCK_H

#include <linux/tracepoint.h>

struct landlock_domain_index;

TRACE_EVENT(
	landlock_domain_hash_find,
	TP_PROTO(
		const struct landlock_domain_index* indices_arr,
		u32 num_indices,
		int hash_bits,
		const struct landlock_domain_index* elem_to_find,
		u32 collisions_followed
	),

	TP_ARGS(indices_arr, num_indices, hash_bits, elem_to_find, collisions_followed),
	TP_STRUCT__entry(
		__field(const struct landlock_domain_index *, indices_arr)
		__field(u32, num_indices)
		__field(u32, hash_bits)
		__field(uintptr_t, key)
		__field(u32, collisions_followed)
	),

	TP_fast_assign(
		__entry->indices_arr = indices_arr;
		__entry->num_indices = num_indices;
		__entry->hash_bits = hash_bits;
		__entry->key = *(uintptr_t *)elem_to_find;
		__entry->collisions_followed = collisions_followed;
	),

	TP_printk(
		"indices_arr=%p num_indices=%u hash_bits=%u, key=%lx collisions_followed=%u",
		__entry->indices_arr,
		__entry->num_indices,
		__entry->hash_bits,
		__entry->key,
		__entry->collisions_followed
	)
);

#endif /* _TRACE_LANDLOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
