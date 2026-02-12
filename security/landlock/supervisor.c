// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor management for mutable domains
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <linux/wait.h>
#include <linux/wait_bit.h>

#include "ruleset.h"
#include "supervisor.h"

/**
 * landlock_create_supervisor - Create a new supervisor
 *
 * Creates a new supervisor structure with an empty committed ruleset.
 *
 * Returns: A newly allocated supervisor, or an error pointer.
 */
struct landlock_supervisor *landlock_create_supervisor(void)
{
	struct landlock_supervisor *supervisor;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL_ACCOUNT);
	if (!supervisor)
		return ERR_PTR(-ENOMEM);

	mutex_init(&supervisor->lock);
	refcount_set(&supervisor->usage, 1);
	RCU_INIT_POINTER(supervisor->committed_ruleset, NULL);
	supervisor->notification_enabled = false;
	spin_lock_init(&supervisor->notification_lock);
	INIT_LIST_HEAD(&supervisor->event_queue);
	INIT_LIST_HEAD(&supervisor->notified_events);
	init_waitqueue_head(&supervisor->poll_wq);
	supervisor->next_event_id = 1;

	return supervisor;
}

static void free_supervisor(struct landlock_supervisor *supervisor)
{
	struct landlock_ruleset *committed;
	struct landlock_supervise_event_kernel *event, *tmp;

	WARN_ON_ONCE(!supervisor);

	/* Deny all pending and notified events. */
	spin_lock(&supervisor->notification_lock);
	list_for_each_entry_safe(event, tmp, &supervisor->event_queue, node) {
		list_del_init(&event->node);
		event->state = LANDLOCK_SUPERVISE_EVENT_DENIED;
		wake_up_var(event);
		landlock_put_supervise_event(event);
	}
	list_for_each_entry_safe(event, tmp, &supervisor->notified_events,
				 node) {
		list_del_init(&event->node);
		event->state = LANDLOCK_SUPERVISE_EVENT_DENIED;
		wake_up_var(event);
		landlock_put_supervise_event(event);
	}
	spin_unlock(&supervisor->notification_lock);

	/*
	 * If we get here, we have to be the last reference owner, and thus
	 * nobody else can be trying to update or read us committed_ruleset,
	 * so the following operation is safe.
	 */
	committed =
		rcu_dereference_protected(supervisor->committed_ruleset, true);
	if (committed)
		landlock_put_ruleset(committed);

	kfree(supervisor);
}

void landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor && refcount_dec_and_test(&supervisor->usage))
		free_supervisor(supervisor);
}

/**
 * copy_rules_tree - Copy rules from a source tree to a destination ruleset
 *
 * @dst: Destination ruleset (must be locked by caller)
 * @src_root: Source rb_root to copy from
 * @key_type: Type of rules being copied (LANDLOCK_KEY_INODE or LANDLOCK_KEY_NET_PORT)
 *
 * Copies all rules from @src_root to @dst.  Each rule must have exactly one
 * layer at level 0 (single-layer ruleset requirement for supervisor rulesets).
 *
 * Returns: 0 on success, negative error code on failure.
 */
static int copy_rules_tree(struct landlock_ruleset *dst,
			   struct rb_root *src_root,
			   const enum landlock_key_type key_type)
{
	struct landlock_rule *rule;
	struct rb_node *node;

	for (node = rb_first(src_root); node; node = rb_next(node)) {
		int err;

		rule = rb_entry(node, struct landlock_rule, node);

		/* Supervisor rulesets must be single-layer with level 0 */
		if (WARN_ON_ONCE(rule->num_layers != 1 ||
				 rule->layers[0].level != 0))
			return -EINVAL;

		{
			const struct landlock_id id = {
				.key = rule->key,
				.type = key_type,
			};

			err = landlock_insert_rule(
				dst, id, rule->layers[0].access,
				rule->layers[0].flags.quiet ?
					LANDLOCK_ADD_RULE_QUIET :
					0);
		}
		if (err)
			return err;
	}

	return 0;
}

/**
 * copy_ruleset_for_commit - Create a copy of a ruleset for committing
 *
 * @src: Source ruleset to copy from.
 *
 * Creates a new ruleset containing copies of all rules from @src.
 * The new ruleset is suitable for use as a committed supervisor ruleset.
 *
 * Returns: A newly allocated ruleset copy, or an error pointer.
 */
static struct landlock_ruleset *
copy_ruleset_for_commit(struct landlock_ruleset *src)
{
	struct landlock_ruleset *dst;
	int err;

	/* Create a new single-layer ruleset */
	dst = landlock_create_ruleset(src->access_masks[0].fs,
				      src->access_masks[0].net,
				      src->access_masks[0].scope);
	if (IS_ERR(dst))
		return dst;

	/* Copy quiet masks */
	dst->quiet_masks = src->quiet_masks;

	/*
	 * Use nested locking since the caller already holds src->lock
	 * (same lock class as dst->lock).  This is safe because dst is
	 * a newly created ruleset not yet visible to other threads.
	 */
	mutex_lock_nested(&dst->lock, SINGLE_DEPTH_NESTING);

	/* Copy inode rules */
	err = copy_rules_tree(dst, &src->root_inode, LANDLOCK_KEY_INODE);

#if IS_ENABLED(CONFIG_INET)
	/* Copy network port rules */
	if (!err)
		err = copy_rules_tree(dst, &src->root_net_port,
				      LANDLOCK_KEY_NET_PORT);
#endif /* IS_ENABLED(CONFIG_INET) */

	mutex_unlock(&dst->lock);

	if (err) {
		landlock_put_ruleset(dst);
		return ERR_PTR(err);
	}

	return dst;
}

/**
 * landlock_commit_supervisor - Commit pending changes to supervisor
 *
 * @ruleset: The supervisor ruleset (not the committed ruleset).
 *
 * Atomically commits all pending rule changes from the user-accessible
 * supervisor ruleset to the committed ruleset.  After this call, access
 * checks against domains using this supervisor will see the new rules.
 *
 * The caller must ensure the current task is not under a domain that uses
 * this supervisor.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int landlock_commit_supervisor(struct landlock_ruleset *ruleset)
{
	struct landlock_supervisor *supervisor;
	struct landlock_ruleset *new_committed, *old_committed;

	if (!ruleset || !ruleset->supervisor)
		return -EINVAL;

	supervisor = ruleset->supervisor;

	/*
	 * Lock ordering: ruleset->lock before supervisor->lock.
	 *
	 * This lock ordering is safe because:
	 * 1. Only the supervisor ruleset (not domain rulesets) has a supervisor
	 *    pointer, so no conflict with domain locking paths.
	 * 2. Access checks use RCU to read committed_ruleset, not locks.
	 * 3. This function is the only code path that takes supervisor->lock,
	 *    so there is no risk of ABBA deadlock with any other code.
	 */
	mutex_lock(&ruleset->lock);
	mutex_lock_nested(&supervisor->lock, SINGLE_DEPTH_NESTING);

	/* Create a new copy of the current ruleset state */
	new_committed = copy_ruleset_for_commit(ruleset);
	if (IS_ERR(new_committed)) {
		mutex_unlock(&supervisor->lock);
		mutex_unlock(&ruleset->lock);
		return PTR_ERR(new_committed);
	}

	/* Swap the committed ruleset pointer */
	old_committed =
		rcu_dereference_protected(supervisor->committed_ruleset,
					  lockdep_is_held(&supervisor->lock));
	rcu_assign_pointer(supervisor->committed_ruleset, new_committed);

	/* TODO: remove on submission */
	trace_printk("committed = %p\n", new_committed);
	{
		struct rb_node *node;

		trace_printk("landlock: dumping inode rules:\n");
		for (node = rb_first(&new_committed->root_inode); node;
		     node = rb_next(node)) {
			struct landlock_rule *rule =
				rb_entry(node, struct landlock_rule, node);
			u32 i;

			trace_printk("  rule key=0x%lx num_layers=%u\n",
				     (unsigned long)rule->key.data,
				     rule->num_layers);
			for (i = 0; i < rule->num_layers; i++) {
				trace_printk(
					"    layer[%u]: level=%u access=0x%llx quiet=%d\n",
					i, rule->layers[i].level,
					(unsigned long long)rule->layers[i]
						.access,
					rule->layers[i].flags.quiet);
			}
		}
#if IS_ENABLED(CONFIG_INET)
		trace_printk("landlock: dumping net_port rules:\n");
		for (node = rb_first(&new_committed->root_net_port); node;
		     node = rb_next(node)) {
			struct landlock_rule *rule =
				rb_entry(node, struct landlock_rule, node);
			u32 i;

			trace_printk("  rule key=0x%lx num_layers=%u\n",
				     (unsigned long)rule->key.data,
				     rule->num_layers);
			for (i = 0; i < rule->num_layers; i++) {
				trace_printk(
					"    layer[%u]: level=%u access=0x%llx quiet=%d\n",
					i, rule->layers[i].level,
					(unsigned long long)rule->layers[i]
						.access,
					rule->layers[i].flags.quiet);
			}
		}
#endif /* IS_ENABLED(CONFIG_INET) */
	}

	mutex_unlock(&supervisor->lock);
	mutex_unlock(&ruleset->lock);

	/* Wait for all readers to finish, then free the old ruleset */
	if (old_committed) {
		synchronize_rcu();
		landlock_put_ruleset(old_committed);
	}

	return 0;
}

/**
 * struct landlock_supervise_wait - Task work data for waiting on supervisor
 *
 * Allocated per notification event; the task_work callback blocks until
 * the supervisor responds, then releases resources.
 */
struct landlock_supervise_wait {
	/** @twork: Callback head for task_work_add(). */
	struct callback_head twork;
	/** @event: The notification event to wait on. */
	struct landlock_supervise_event_kernel *event;
};

/**
 * landlock_supervise_wait_work - Task work callback to wait for supervisor
 *
 * Runs before the task returns to user space.  Blocks until the supervisor
 * acknowledges or denies the event, then drops the event reference.
 */
static void landlock_supervise_wait_work(struct callback_head *twork)
{
	struct landlock_supervise_wait *wait =
		container_of(twork, struct landlock_supervise_wait, twork);
	struct landlock_supervise_event_kernel *event = wait->event;

	/* Block until the supervisor responds or the supervisor is freed. */
	wait_var_event(event, LANDLOCK_SUPERVISE_EVENT_HANDLED(event));

	landlock_put_supervise_event(event);
	kfree(wait);
}

/**
 * landlock_queue_supervisor_notification - Queue a notification event
 *
 * @supervisor: The supervisor to notify.
 * @type: Event type (FS or NET).
 * @access_request: The denied access rights.
 * @path1: First path target (may be NULL for net events).
 * @path2: Second path target for rename/link (may be NULL).
 * @path1_new: Whether path1 is a new file.
 * @path2_new: Whether path2 is a new file.
 * @port: Network port (only for NET events).
 *
 * Creates a notification event, adds it to the supervisor's event queue, and
 * installs a task_work callback that blocks the calling task (before it
 * returns to user space) until the supervisor responds.  This avoids blocking
 * inside the LSM hook (where inode locks may be held) while still preventing
 * the task from looping on syscall restart before the supervisor has a chance
 * to respond.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int landlock_queue_supervisor_notification(
	struct landlock_supervisor *supervisor,
	const landlock_supervise_event_type_t type,
	const access_mask_t access_request,
	const struct path *path1, const struct path *path2,
	const bool path1_new, const bool path2_new,
	const __u16 port)
{
	struct landlock_supervise_event_kernel *event;
	struct landlock_supervise_wait *wait;

	if (!supervisor || !supervisor->notification_enabled)
		return -EINVAL;

	/*
	 * Allocate both structures before initializing either, so failure
	 * cleanup is a simple kfree without needing to release resources.
	 */
	wait = kzalloc(sizeof(*wait), GFP_KERNEL);
	if (!wait)
		return -ENOMEM;

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		kfree(wait);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&event->node);
	/*
	 * Two refs: one for the queue/list, one for the task_work waiter.
	 * The queue/list ref is dropped when the supervisor reads + responds.
	 * The task_work ref is dropped after the wait completes.
	 */
	refcount_set(&event->usage, 2);
	event->state = LANDLOCK_SUPERVISE_EVENT_NEW;
	event->type = type;
	event->access_request = access_request;
	event->accessor = get_task_pid(current, PIDTYPE_PID);

	switch (type) {
	case LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS:
		if (path1) {
			event->target_1 = *path1;
			path_get(&event->target_1);
		}
		if (path2) {
			event->target_2 = *path2;
			path_get(&event->target_2);
		}
		event->target_1_is_new = path1_new;
		event->target_2_is_new = path2_new;
		break;
	case LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS:
		event->port = port;
		break;
	}

	spin_lock(&supervisor->notification_lock);
	event->event_id = supervisor->next_event_id++;
	list_add_tail(&event->node, &supervisor->event_queue);
	spin_unlock(&supervisor->notification_lock);

	wake_up_interruptible(&supervisor->poll_wq);

	/*
	 * Install a task_work that will block the task before it returns
	 * to user space, waiting for the supervisor to respond.  This
	 * ensures the task doesn't loop on syscall restart before the
	 * supervisor has had a chance to update rules or set quiet flags.
	 */
	wait->event = event;
	init_task_work(&wait->twork, landlock_supervise_wait_work);
	if (task_work_add(current, &wait->twork, TWA_RESUME)) {
		/*
		 * Task is exiting — the event is already queued and will
		 * be cleaned up when the supervisor is freed.  Drop the
		 * task_work ref.
		 */
		landlock_put_supervise_event(event);
		kfree(wait);
	}

	return 0;
}
