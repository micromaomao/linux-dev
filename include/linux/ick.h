/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_ICK_H
#define _LINUX_ICK_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#ifdef CONFIG_ICK
struct ick_checked_process {
	struct pt_regs saved_regs;
	struct rb_root modified_pages_tree;
	struct spinlock tree_lock;
	bool reverting;
};

struct ick_modified_page {
	unsigned long addr;
	struct rb_node node;
	// Don't include a whole page of data here, otherwise this struct will be just
	// a bit over PAGE_SIZE, which makes memory allocation inefficient
	u8 *orig_page_content;
};

/**
 * Called from page fault handler to copy off page content before allowing
 * it to be modified.  Returns zero on success, and any of the bits in
 * VM_FAULT_ERROR on failure.
 */
vm_fault_t ick_do_wp_page(struct vm_fault *vmf);

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
