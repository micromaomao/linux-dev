// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Supervisor notification mechanism
 *
 * Copyright © 2025-2026 Tingmao Wang <m@maowtm.org>
 */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "supervise.h"
#include "supervisor.h"
#include "ruleset.h"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "landlock-supervise: " fmt

struct landlock_supervisor_notif *
landlock_create_supervisor_notif(struct landlock_supervisor *supervisor)
{
	struct landlock_supervisor_notif *notif;

	notif = kzalloc(sizeof(*notif), GFP_KERNEL_ACCOUNT);
	if (!notif)
		return ERR_PTR(-ENOMEM);

	refcount_set(&notif->usage, 1);
	notif->next_event_id = 1;
	spin_lock_init(&notif->lock);
	INIT_LIST_HEAD(&notif->event_queue);
	INIT_LIST_HEAD(&notif->notified_events);
	init_waitqueue_head(&notif->poll_event_wq);

	return notif;
}

void landlock_get_supervisor_notif(struct landlock_supervisor_notif *notif)
{
	if (notif)
		refcount_inc(&notif->usage);
}

static void deny_and_put_event(struct landlock_supervise_event_kernel *event)
{
	cmpxchg(&event->state, LANDLOCK_SUPERVISE_EVENT_NEW,
		LANDLOCK_SUPERVISE_EVENT_DENIED);
	cmpxchg(&event->state, LANDLOCK_SUPERVISE_EVENT_NOTIFIED,
		LANDLOCK_SUPERVISE_EVENT_DENIED);
	wake_up_var(event);
	landlock_put_supervise_event(event);
}

void landlock_put_supervisor_notif(struct landlock_supervisor_notif *notif)
{
	if (!notif)
		return;

	if (refcount_dec_and_test(&notif->usage)) {
		struct landlock_supervise_event_kernel *freeme, *next;

		might_sleep();
		/* We are the only reference, no locking needed */

		/* Deny all pending events */
		list_for_each_entry_safe(freeme, next, &notif->event_queue,
					 node) {
			list_del(&freeme->node);
			deny_and_put_event(freeme);
		}

		/* Deny all notified events */
		list_for_each_entry_safe(freeme, next, &notif->notified_events,
					 node) {
			list_del(&freeme->node);
			deny_and_put_event(freeme);
		}

		kfree(notif);
	}
}

void landlock_put_supervise_event(struct landlock_supervise_event_kernel *event)
{
	if (!event)
		return;

	if (refcount_dec_and_test(&event->usage)) {
		if (event->accessor)
			put_pid(event->accessor);

		if (event->type == LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS) {
			if (event->target_1.dentry)
				path_put(&event->target_1);
			if (event->target_2.dentry)
				path_put(&event->target_2);
		}

		kfree(event);
	}
}

struct landlock_supervise_event_kernel *
landlock_queue_supervisor_event(const struct landlock_hierarchy *hierarchy,
				const enum landlock_supervise_event_type request_type,
				const access_mask_t access_request,
				const struct path *path1,
				const struct path *path2,
				const bool path1_new, const bool path2_new,
				const __u16 port)
{
	struct landlock_supervisor *supervisor;
	struct landlock_supervisor_notif *notif;
	struct landlock_supervise_event_kernel *event;

	if (!hierarchy || !hierarchy->supervisor)
		return ERR_PTR(-EINVAL);

	supervisor = hierarchy->supervisor;
	notif = supervisor->notif;

	if (!notif)
		return ERR_PTR(-EINVAL);

	event = kzalloc(sizeof(*event), GFP_KERNEL_ACCOUNT);
	if (!event)
		return ERR_PTR(-ENOMEM);

	refcount_set(&event->usage, 1);
	event->state = LANDLOCK_SUPERVISE_EVENT_NEW;
	event->type = request_type;
	event->access_request = access_request;
	event->accessor = get_pid(task_pid(current));

	switch (request_type) {
	case LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS:
		if (path1) {
			event->target_1 = *path1;
			path_get(&event->target_1);
			event->target_1_is_new = path1_new;
		}
		if (path2) {
			event->target_2 = *path2;
			path_get(&event->target_2);
			event->target_2_is_new = path2_new;
		}
		break;
	case LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS:
		event->port = port;
		break;
	}

	spin_lock(&notif->lock);
	event->event_id = notif->next_event_id++;
	landlock_get_supervise_event(event);
	list_add_tail(&event->node, &notif->event_queue);
	spin_unlock(&notif->lock);

	wake_up(&notif->poll_event_wq);

	return event;
}
