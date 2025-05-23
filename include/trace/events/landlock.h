/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright © 2025 Microsoft Corporation
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM landlock

#if !defined(_TRACE_LANDLOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LANDLOCK_H

#include <linux/tracepoint.h>

struct landlock_rule;
struct landlock_rule_ref;
struct landlock_ruleset;
struct path;
typedef u16 access_mask_t;

TRACE_EVENT(landlock_add_rule_fs,

	TP_PROTO(
		const struct landlock_ruleset *ruleset,
		const struct landlock_rule_ref *ref,
		access_mask_t access_rights,
		const struct path *path,
		const char *pathname
	),

	TP_ARGS(ruleset, ref, access_rights, path, pathname),

	TP_STRUCT__entry(
		__field(const struct landlock_ruleset *, ruleset)
		__field(uintptr_t, ref_key)
		__field(access_mask_t, allowed)
		__field(dev_t, dev)
		__field(ino_t, ino)
		__string(pathname, pathname)
	),

	TP_fast_assign(
		__entry->ruleset = ruleset;
		__entry->ref_key = ref->key.data;
		__entry->allowed = access_rights;
		__entry->dev = path->dentry->d_sb->s_dev;
		__entry->ino = path->dentry->d_inode->i_ino;
		__assign_str(pathname);
	),

	/*
	 * The inode number may not be the user-visible one, but it will be the same
	 * used by audit.
	 */
	TP_printk(
		"ruleset=0x%p key=inode:0x%lx allowed=0x%x dev=%u:%u ino=%lu path=%s",
		__entry->ruleset,
		__entry->ref_key,
		__entry->allowed,
		MAJOR(__entry->dev),
		MINOR(__entry->dev),
		__entry->ino,
		__print_untrusted_str(pathname)
	)
);

TRACE_EVENT(landlock_check_rule,

	TP_PROTO(
		const struct landlock_ruleset *domain,
		const struct landlock_rule_ref *ref,
		access_mask_t access_request,
		const struct landlock_rule *rule
	),

	TP_ARGS(domain, ref, access_request, rule),

	TP_STRUCT__entry(
		__field(__u64, domain_id)
		__field(access_mask_t, access_request)
		__field(int, ref_type)
		__field(uintptr_t, ref_key)
		__dynamic_array(access_mask_t, layers, domain->num_layers)
	),

	TP_fast_assign(
		__entry->domain_id = domain->hierarchy->id;
		__entry->access_request = access_request;
		__entry->ref_type = ref->type;
		/* TODO: Use an object's Landlock ID instead of a kernel address. */
		__entry->ref_key = ref->key.data;

		for (size_t level = 1, i = 0;
			level <= __get_dynamic_array_len(layers) / sizeof(access_mask_t);
			level++) {
			access_mask_t allowed;

			if (i < rule->num_layers &&
			    level == rule->layers[i].level) {
				allowed = rule->layers[i].access;
				i++;
			} else {
				allowed = 0;
			}
			((access_mask_t *)__get_dynamic_array( layers))[level - 1] = allowed;
		}
	),

	/* TODO: Do not print network ports as big endian. */
	TP_printk("domain=%llx key=%s:0x%lx request=0x%x allowed=%s",
		__entry->domain_id,
		__print_symbolic(__entry->ref_type,
			{ LANDLOCK_KEY_INODE, "inode" },
			{ LANDLOCK_KEY_NET_PORT, "net_port" }
		),
		__entry->ref_key,
		__entry->access_request,
		__print_dynamic_array(layers, sizeof(access_mask_t))
	)
);

#endif /* _TRACE_LANDLOCK_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
