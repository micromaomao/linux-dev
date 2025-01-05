// SPDX-License-Identifier: GPL-2.0

#include <linux/ick.h>
#include <linux/errno.h>

/**
 * Initialize the ick data structures on the current task and checkpoint it.
 */
int ick_checkpoint_proc(void)
{
	/* TODO: implement */

	/* We just return 0 for now to make the code in `read` work. */
	return 0;
}

/**
 * Revert the current task to the state checkpointed by ick_checkpoint_proc.
 */
int ick_revert_proc(void)
{
	/* TODO: implement */

	/* We just return 0 for now to make the code in `write` work. */
	return 0;
}

/**
 * Clean up any saved ick checkpoints from the current task, if there is any.
 * Call before a task exits.
 */
void ick_cleanup(struct task_struct *task)
{
	/* TODO: implement */
}
