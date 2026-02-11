/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Supervisor notification mechanism
 *
 * Copyright © 2025-2026 Tingmao Wang <m@maowtm.org>
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISE_H
#define _SECURITY_LANDLOCK_SUPERVISE_H

#include <linux/path.h>
#include <linux/pid.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "access.h"
#include "limits.h"

/**
 * enum landlock_supervise_event_type - Type of supervisor event
 */
enum landlock_supervise_event_type {
	LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS = 1,
	LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS,
};

/**
 * enum landlock_supervise_event_state - State of a supervisor event
 */
enum landlock_supervise_event_state {
	LANDLOCK_SUPERVISE_EVENT_NEW,
	LANDLOCK_SUPERVISE_EVENT_NOTIFIED,
	LANDLOCK_SUPERVISE_EVENT_ALLOWED,
	LANDLOCK_SUPERVISE_EVENT_DENIED,
};

#define LANDLOCK_SUPERVISE_EVENT_HANDLED(event) \
	((event)->state == LANDLOCK_SUPERVISE_EVENT_ALLOWED || \
	 (event)->state == LANDLOCK_SUPERVISE_EVENT_DENIED)

/**
 * struct landlock_supervise_event_kernel - Kernel representation of a supervisor event
 *
 * Events are created when access is denied and sent to the supervisor for
 * a decision.
 */
struct landlock_supervise_event_kernel {
	struct list_head node;
	refcount_t usage;
	enum landlock_supervise_event_state state;

	/* Event ID for matching with responses */
	u32 event_id;

	/* Event type */
	enum landlock_supervise_event_type type;

	/* Access request details */
	access_mask_t access_request;
	struct pid *accessor;

	/* Filesystem event details */
	struct path target_1;
	struct path target_2;
	bool target_1_is_new;
	bool target_2_is_new;

	/* Network event details */
	__u16 port;
};

/**
 * struct landlock_supervisor_notif - Supervisor notification state
 *
 * Contains notification queues and state for a supervisor that has
 * opted in to receive denial notifications.
 */
struct landlock_supervisor_notif {
	refcount_t usage;
	spinlock_t lock;

	/* Event queues (protected by @lock) */
	struct list_head event_queue;
	struct list_head notified_events;

	/* Wait queue for poll/read */
	struct wait_queue_head poll_event_wq;

	/* Next event ID */
	u32 next_event_id;
};

/* Forward declaration */
struct landlock_supervisor;

struct landlock_supervisor_notif *
landlock_create_supervisor_notif(struct landlock_supervisor *supervisor);
void landlock_get_supervisor_notif(struct landlock_supervisor_notif *notif);
void landlock_put_supervisor_notif(struct landlock_supervisor_notif *notif);

/* Forward declaration for ruleset */
struct landlock_hierarchy;

/**
 * landlock_queue_supervisor_event - Queue an event for supervisor notification
 *
 * @hierarchy: The layer's hierarchy containing the supervisor
 * @request_type: Type of access request
 * @access_request: Bitmask of denied access rights
 * @path1: First path (for FS events), may be NULL
 * @path2: Second path (for FS events, e.g., rename dest), may be NULL
 * @path1_new: Whether path1 is a new file being created
 * @path2_new: Whether path2 is a new file being created
 * @port: Port number (for network events)
 *
 * Creates and queues a notification event. The calling task will later
 * wait for supervisor response via task_work.
 *
 * Returns: The queued event (with a reference), or ERR_PTR on error.
 */
struct landlock_supervise_event_kernel *
landlock_queue_supervisor_event(const struct landlock_hierarchy *hierarchy,
				const enum landlock_supervise_event_type request_type,
				const access_mask_t access_request,
				const struct path *path1,
				const struct path *path2,
				const bool path1_new, const bool path2_new,
				const __u16 port);

static inline void
landlock_get_supervise_event(struct landlock_supervise_event_kernel *event)
{
	refcount_inc(&event->usage);
}

void landlock_put_supervise_event(struct landlock_supervise_event_kernel *event);

#endif /* _SECURITY_LANDLOCK_SUPERVISE_H */
