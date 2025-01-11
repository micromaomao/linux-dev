// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_ICK_H
#define _LINUX_ICK_H

#include <linux/types.h>
#include <linux/sched.h>

#ifdef CONFIG_ICK

struct ick_checked_process {
	struct pt_regs saved_regs;
	/* ... more to come ... */
};

int ick_checkpoint_proc(void);
int ick_revert_proc(void);
void ick_cleanup(struct task_struct *task);

#endif /* CONFIG_ICK */

#endif /* _LINUX_ICK_H */
