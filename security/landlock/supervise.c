#include <linux/path.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/wait_bit.h>

#include "supervise.h"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) "landlock-supervise: " fmt

struct landlock_supervisor *landlock_create_supervisor(void)
{
	struct landlock_supervisor *supervisor;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL_ACCOUNT);
	if (!supervisor)
		return ERR_PTR(-ENOMEM);
	refcount_set(&supervisor->usage, 1);
	supervisor->next_event_id = 1;
	spin_lock_init(&supervisor->lock);
	INIT_LIST_HEAD(&supervisor->event_queue);
	init_waitqueue_head(&supervisor->poll_event_wq);
	return supervisor;
}

void landlock_get_supervisor(struct landlock_supervisor *const supervisor)
{
	refcount_inc(&supervisor->usage);
}

void landlock_put_supervisor(struct landlock_supervisor *const supervisor)
{
	if (refcount_dec_and_test(&supervisor->usage)) {
		struct landlock_supervise_event_kernel *freeme, *next;

		might_sleep();
		/* we are the only reference, hence no locking */
		list_for_each_entry_safe(freeme, next, &supervisor->event_queue,
					 node) {
			list_del(&freeme->node);
			cmpxchg(&freeme->state, LANDLOCK_SUPERVISE_EVENT_NEW,
				LANDLOCK_SUPERVISE_EVENT_DENIED);
			cmpxchg(&freeme->state,
				LANDLOCK_SUPERVISE_EVENT_NOTIFIED,
				LANDLOCK_SUPERVISE_EVENT_DENIED);
			wake_up_var(freeme);
			landlock_put_supervise_event(freeme);
		}
		kfree(supervisor);
	}
}

/**
 * If all the layers in denied_layers are supervised, ask all of
 * them for permission, and return whether access should be
 * allowed.  If denied_layers contains any non-supervised layer,
 * will return false without making any supervisor event.
 */
bool landlock_ask_supervised_layers(
	const struct landlock_ruleset *const domain,
	const layer_mask_t denied_layers,
	const landlock_supervise_event_type_t request_type,
	const access_mask_t access_request, const struct path *const path1,
	const struct path *const path2, const __u16 port)
{
	size_t layer_level;
	unsigned long denied_layers_ = denied_layers;

	for_each_set_bit(layer_level, &denied_layers_, domain->num_layers) {
		if (!domain->layer_stack[layer_level].supervisor) {
			return false;
		}
	}

	/*
	 * All denied layers are supervisor layers, so we just ask
	 * them in turn. There's good argument for either order (top
	 * -> bottom, or the other way), so we just do the easiest
	 * thing here.
	 */

	for_each_set_bit(layer_level, &denied_layers_, domain->num_layers) {
		struct landlock_supervisor *const supervisor =
			domain->layer_stack[layer_level].supervisor;

		/*
		 * supervisor will stay valid here because we're blocking
		 * this thread which references the layer, which in terms
		 * references the supervisor.
		 */

		/* TODO: memchg supervisor owner then allocate with account */
		struct landlock_supervise_event_kernel *event __free(
			landlock_put_supervise_event) =
			kzalloc(sizeof(*event), GFP_KERNEL_ACCOUNT);

		int rc;

		if (!event) {
			pr_alert(
				"failed to allocate memory for supervisor event\n");
			return false;
		}

		refcount_set(&event->usage, 1);
		event->state = LANDLOCK_SUPERVISE_EVENT_NEW;

		event->type = request_type;
		event->access_request = access_request;
		event->accessor = get_pid(task_pid(current));
		switch (request_type) {
		case LANDLOCK_SUPERVISE_EVENT_TYPE_FS_ACCESS:
			if (path1) {
				path_get(path1);
				event->target_1 = *path1;
			}
			if (path2) {
				path_get(path2);
				event->target_2 = *path2;
			}
			break;
		case LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS:
			event->port = port;
			break;
		}

		BUG_ON(!supervisor);

		spin_lock(&supervisor->lock);
		event->event_id = supervisor->next_event_id++;
		list_add_tail(&event->node, &supervisor->event_queue);
		landlock_get_supervise_event(event);
		spin_unlock(&supervisor->lock);
		wake_up(&supervisor->poll_event_wq);

		rc = wait_var_event_killable(
			event, LANDLOCK_SUPERVISE_EVENT_HANDLED(event));
		if (rc) {
			/* Task died, doesn't matter what we say */
			return false;
		}
		if (event->state != LANDLOCK_SUPERVISE_EVENT_ALLOWED) {
			return false;
		}
	}

	return true;
}
