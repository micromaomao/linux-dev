/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Supervisor management for mutable domains
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#include <linux/bug.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#include "access.h"
#include "ruleset.h"

/**
 * struct landlock_supervisor - Supervisor state for mutable domains
 *
 * A supervisor allows dynamic modification of Landlock rules after a domain
 * has been enforced.  The supervisor process keeps the supervisor ruleset fd
 * and can add/remove rules.  Changes take effect after committing.
 */
struct landlock_supervisor {
	/**
	 * @lock: Protects access to @committed_ruleset and the user-accessible
	 * supervisor ruleset during rule modifications and commits.
	 */
	struct mutex lock;
	/**
	 * @usage: Reference count for this supervisor.  The supervisor ruleset
	 * and all supervisee rulesets (including those merged into domains)
	 * hold a reference.
	 */
	refcount_t usage;
	/**
	 * @committed_ruleset: The "live" ruleset containing committed rules.
	 * This is RCU-protected for lockless reads during access checks.
	 * On commit, a new ruleset is created and this pointer is swapped.
	 * The old ruleset is freed after an RCU grace period.
	 */
	struct landlock_ruleset __rcu *committed_ruleset;
	/**
	 * @notification_enabled: Whether this supervisor wants to receive
	 * denial notification events.  Set when the supervisor is created
	 * with LANDLOCK_CREATE_SUPERVISOR_NOTIFICATION.
	 */
	bool notification_enabled;
	/**
	 * @notification_lock: Protects the event queue and notified list.
	 */
	spinlock_t notification_lock;
	/**
	 * @event_queue: List of pending events waiting to be read.
	 */
	struct list_head event_queue;
	/**
	 * @notified_events: Events that have been read but not responded to.
	 */
	struct list_head notified_events;
	/**
	 * @poll_wq: Wait queue for poll/select on the supervisor fd.
	 */
	struct wait_queue_head poll_wq;
	/**
	 * @next_event_id: Next cookie value for events.
	 */
	u32 next_event_id;
};

struct landlock_supervisor *landlock_create_supervisor(void);
void landlock_put_supervisor(struct landlock_supervisor *supervisor);
int landlock_commit_supervisor(struct landlock_ruleset *ruleset);

static inline void
landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	WARN_ON_ONCE(!supervisor);
	refcount_inc(&supervisor->usage);
}

/**
 * landlock_get_supervisor_committed_ruleset_rcu - Get committed ruleset under RCU
 *
 * @supervisor: The supervisor to get the committed ruleset from.
 *
 * Returns the committed ruleset pointer for use in RCU read-side critical
 * sections.  Caller must be in an RCU read-side critical section.
 *
 * Returns: The committed ruleset (may be NULL if no rules committed).
 */
static inline struct landlock_ruleset *
landlock_get_supervisor_committed_ruleset_rcu(
	struct landlock_supervisor *supervisor)
{
	if (!supervisor)
		return NULL;

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
		"landlock_get_supervisor_committed_ruleset_rcu() requires RCU");
	return rcu_dereference(supervisor->committed_ruleset);
}

/**
 * landlock_get_supervisor_committed_ruleset - Get the committed ruleset
 *
 * @supervisor: The supervisor to get the committed ruleset from.
 *
 * Gets a reference to the committed ruleset for use in access checks.
 * Uses RCU to safely read the committed_ruleset pointer while it may be
 * concurrently updated by landlock_commit_supervisor().
 *
 * Returns: The committed ruleset (may be NULL if no rules committed),
 *          with an incremented reference count.
 */
static inline struct landlock_ruleset *
landlock_get_supervisor_committed_ruleset(struct landlock_supervisor *supervisor)
{
	struct landlock_ruleset *committed;

	if (!supervisor)
		return NULL;

	scoped_guard(rcu) {
		committed = rcu_dereference(supervisor->committed_ruleset);
		if (committed)
			landlock_get_ruleset(committed);
	}

	return committed;
}

enum landlock_supervise_event_state {
	LANDLOCK_SUPERVISE_EVENT_NEW,
	LANDLOCK_SUPERVISE_EVENT_NOTIFIED,
	LANDLOCK_SUPERVISE_EVENT_ACKNOWLEDGED,
	LANDLOCK_SUPERVISE_EVENT_DENIED,
};

/**
 * struct landlock_supervise_event_kernel - Kernel-side supervisor event
 */
struct landlock_supervise_event_kernel {
	/** @node: List node for event_queue or notified_events. */
	struct list_head node;
	/** @usage: Reference count. */
	refcount_t usage;
	/** @state: Current state of this event. */
	enum landlock_supervise_event_state state;
	/** @event_id: Cookie value for matching responses. */
	u32 event_id;

	/** @type: Type of the event (FS or NET). */
	landlock_supervise_event_type_t type;
	/** @access_request: Denied access rights bitmask. */
	access_mask_t access_request;
	/** @accessor: PID of the accessing task. */
	struct pid *accessor;

	/** @response_ret_code: Return code from supervisor response. */
	s64 response_ret_code;
	/** @response_flags: Flags from supervisor response. */
	u16 response_flags;

	union {
		struct {
			/** @target_1: First path target. */
			struct path target_1;
			/** @target_2: Second path target (rename/link). */
			struct path target_2;
			/** @target_1_is_new: Target 1 is a new file. */
			u8 target_1_is_new : 1;
			/** @target_2_is_new: Target 2 is a new file. */
			u8 target_2_is_new : 1;
		};
		struct {
			/** @port: Network port. */
			__u16 port;
		};
	};
};

#define LANDLOCK_SUPERVISE_EVENT_HANDLED(event)                       \
	((event)->state == LANDLOCK_SUPERVISE_EVENT_ACKNOWLEDGED || \
	 (event)->state == LANDLOCK_SUPERVISE_EVENT_DENIED)

static inline void landlock_get_supervise_event(
	struct landlock_supervise_event_kernel *const event)
{
	refcount_inc(&event->usage);
}

static inline void landlock_put_supervise_event(
	struct landlock_supervise_event_kernel *const event)
{
	if (refcount_dec_and_test(&event->usage)) {
		switch (event->type) {
		case LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS:
			if (event->target_1.dentry)
				path_put(&event->target_1);
			if (event->target_2.dentry)
				path_put(&event->target_2);
			break;
		case LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS:
			break;
		}
		put_pid(event->accessor);
		kfree(event);
	}
}

DEFINE_FREE(landlock_put_supervise_event,
	    struct landlock_supervise_event_kernel *,
	    if (_T) landlock_put_supervise_event(_T))

static inline bool
landlock_supervisor_has_notification(const struct landlock_supervisor *supervisor)
{
	return supervisor && supervisor->notification_enabled;
}

int landlock_queue_supervisor_notification(
	struct landlock_supervisor *supervisor,
	const landlock_supervise_event_type_t type,
	const access_mask_t access_request,
	const struct path *path1, const struct path *path2,
	const bool path1_new, const bool path2_new,
	const __u16 port);

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
