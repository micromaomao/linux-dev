// SPDX-License-Identifier: GPL-2.0

#ifndef _LINUX_ICK_H
#define _LINUX_ICK_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#ifdef CONFIG_ICK

struct ick_checked_process {
	struct pt_regs saved_regs;
	struct rb_root modified_pages_tree;
	spinlock_t tree_lock;
	bool reverting;
};

struct ick_modified_page {
	unsigned long addr;
	struct rb_node node;
	/*
	 * Don't include a whole page of data here, otherwise this struct will be just
	 * a bit over PAGE_SIZE, which makes memory allocation inefficient.
	 */
	u8 *orig_page_content;
};

vm_fault_t ick_do_wp_page(struct vm_fault *vmf);

int ick_checkpoint_proc(void);
int ick_revert_proc(void);
void ick_cleanup(struct task_struct *task);

#endif /* CONFIG_ICK */

#endif /* _LINUX_ICK_H */
