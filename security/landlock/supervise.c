#include <linux/path.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/wait_bit.h>

#include "supervise.h"

struct landlock_supervisor *landlock_create_supervisor(void)
{
	struct landlock_supervisor *supervisor;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL_ACCOUNT);
	if (!supervisor)
		return ERR_PTR(-ENOMEM);
	refcount_set(&supervisor->usage, 1);
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
			cmpxchg(&freeme->state,
				LANDLOCK_SUPERVISE_EVENT_PENDING,
				LANDLOCK_SUPERVISE_EVENT_DENIED);
			wake_up_var(freeme);
			landlock_put_supervise_event(freeme);
		}
		kfree(supervisor);
	}
}
