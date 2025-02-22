#ifndef _SECURITY_LANDLOCK_SUPERVISE_H
#define _SECURITY_LANDLOCK_SUPERVISE_H

#include <linux/refcount.h>
#include <linux/wait.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <uapi/linux/landlock.h>

#include "access.h"
#include "ruleset.h"

/**
 * Each supervisor is associated with one active layer in a
 * domain (or associated with a not-yet-active struct
 * landlock_layer). This is referenced (with refcount increments)
 * by all the individual rules within the domain. User-space
 * interact with the event queue through a landlock_supervise_fd.
 */
struct landlock_supervisor {
	refcount_t usage;
	spinlock_t lock;
	/* protected by @lock, contains landlock_supervise_event_kernel */
	struct list_head event_queue;
	struct wait_queue_head poll_event_wq;
};

enum landlock_supervise_event_state {
	LANDLOCK_SUPERVISE_EVENT_NEW,
	LANDLOCK_SUPERVISE_EVENT_NOTIFIED,
	LANDLOCK_SUPERVISE_EVENT_ALLOWED,
	LANDLOCK_SUPERVISE_EVENT_DENIED,
};

struct landlock_supervise_event_kernel {
	struct list_head node;
	refcount_t usage;
	enum landlock_supervise_event_state state;

	landlock_supervise_event_type_t type;
	access_mask_t access_request;
	struct pid *accessor;
	union {
		struct {
			struct path *target_1, *target_2;
		};
		struct {
			__u16 port;
		};
	};
};

struct landlock_supervisor *landlock_create_supervisor(void);
void landlock_get_supervisor(struct landlock_supervisor *const supervisor);
void landlock_put_supervisor(struct landlock_supervisor *const supervisor);

static inline void landlock_get_supervise_event(
	struct landlock_supervise_event_kernel *const event)
{
	refcount_inc(&event->usage);
}

static inline void landlock_put_supervise_event(
	struct landlock_supervise_event_kernel *const event)
{
	if (refcount_dec_and_test(&event->usage)) {
		if (event->target_1)
			path_put(event->target_1);
		if (event->target_2)
			path_put(event->target_2);
		put_pid(event->accessor);
		kfree(event);
	}
}

#endif /* _SECURITY_LANDLOCK_SUPERVISE_H */
