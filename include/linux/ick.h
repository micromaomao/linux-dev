/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_ICK_H
#define _LINUX_ICK_H

#include <linux/types.h>
#include <linux/sched.h>

struct ick_checked_process {
  struct thread_struct saved_state;
  struct pt_regs saved_regs;
  struct rb_root modified_pages_tree;
  struct spinlock tree_lock;
};

struct ick_modified_page {
  unsigned long addr;
  struct rb_node node;
  // Don't include a whole page of data here, otherwise this struct will be just
  // a bit over PAGE_SIZE, which makes memory allocation inefficient
  u8 *orig_page_content;
};

#ifdef CONFIG_ICK
int ick_checkpoint_proc(void);
int ick_revert_proc(void);
vm_fault_t ick_do_wp_page(struct vm_fault *vmf);
#endif

#endif
