/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - mutable domains and supervisor support
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>

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

	refcount_set(&supervisor->usage, 1);

	return supervisor;
}

void landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor && refcount_dec_and_test(&supervisor->usage))
		kfree(supervisor);
}
