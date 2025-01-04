/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_ICK_H
#define _LINUX_ICK_H

#include <linux/types.h>
#include <linux/sched.h>

#ifdef CONFIG_ICK
struct ick_checked_process {
	// ???
};

/**
 * Initialize the ick data structures on the current task and checkpoint it.
 */
int ick_checkpoint_proc(void);

/**
 * Revert the current task to the state checkpointed by ick_checkpoint_proc.
 */
int ick_revert_proc(void);

/**
 * Clean up any saved ick checkpoints from the current task, if there is any.
 * Call before a task exits.
 */
void ick_cleanup(struct task_struct *task);

#endif

#endif
