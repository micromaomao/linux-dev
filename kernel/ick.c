/* SPDX-License-Identifier: GPL-2.0 */

/*
 * ick: Instant checkpoint
 *
 * Provides a mechanism to "checkpoint" a process at some syscall entry, saving
 * its register and marking its writable memory pages as read-only, such that
 * any attempted writes will cause the current content of these pages to be
 * saved before allowing the write to proceed.
 *
 * At some later point in time, the process can be reverted back to the state
 * when it first made the checkpoint-ing syscall.
 *
 * To simplify the implementation, we only support single-threaded processes,
 * and we do not allow the process to make any syscalls other than read / write
 * to/from stdin/stdout/stderr. We also do not support things like huge pages.
 *
 * This is designed for quick brute-forcing of e.g. CTF binaries. A checkpoint
 * can be made when it first tries reading from stdin for a "password", and then
 * the whole process can be quickly reverted (in a matter of microseconds) to
 * try a different password if the one provided earlier was incorrect, and the
 * process tries to write a message to stdout saying so.
 */

#include <asm/gsseg.h>
#include <asm/segment.h>
#include <asm/tlb.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <linux/ick.h>

#include <linux/kgdb.h>

static int __ick_mark_pages(struct task_struct *task,
                            struct ick_checked_process *ick_data);
static int __ick_revert_process(struct task_struct *task);

int ick_checkpoint_proc(void) {
  struct ick_checked_process *ick_data;
  int ret;

  struct task_struct *curr_task = current;

  pid_t pid = curr_task->pid;

  if (!thread_group_empty(curr_task)) {
    pr_alert("ick: %s[%d] is not single-threaded\n", curr_task->comm, pid);
    return -EINVAL;
  }

  if (curr_task->ick_data) {
    pr_alert("ick: %s[%d] already has a checkpoint\n", curr_task->comm, pid);
    return -EEXIST;
  }

  ick_data = kzalloc(sizeof(*ick_data), GFP_KERNEL);
  if (!ick_data) {
    return -ENOMEM;
  }
  ick_data->modified_pages_tree = RB_ROOT;
  spin_lock_init(&ick_data->tree_lock);

  // Save registers
#if defined(__x86_64__)
  struct pt_regs *regs = task_pt_regs(curr_task);
  memcpy(&ick_data->saved_regs, regs, sizeof(struct pt_regs));
  // TODO: Save other thread states, see e.g. fork or switch_to implementation
  // process_64.c:__switch_to
  // or process.c:copy_thread
  // However we do not need to store fpus as this is a syscall kernel entry and
  // fpus are caller-saved.

  current_save_fsgs();
  ick_data->saved_state.fsindex = current->thread.fsindex;
  ick_data->saved_state.fsbase = current->thread.fsbase;
  ick_data->saved_state.gsindex = current->thread.gsindex;
  ick_data->saved_state.gsbase = current->thread.gsbase;

  savesegment(es, ick_data->saved_state.es);
  savesegment(ds, ick_data->saved_state.ds);
#else
#error "Unsupported architecture"
#endif

  ret = __ick_mark_pages(curr_task, ick_data);
  if (ret) {
    goto free_ickdata;
  }

  curr_task->ick_data = ick_data;
  trace_printk("ick: Checkpointed %s[%d], ip = %px, sp = %px\n", curr_task->comm, pid, (void*)regs->ip, (void*)regs->sp);

  return 0;

free_ickdata:
  kfree(ick_data);
  curr_task->ick_data = NULL;
  return ret;
}

// Stop monitoring a process
int ick_revert_proc(bool reset_ick) {
  struct task_struct *curr_task = current;

  pid_t pid = curr_task->pid;

  if (!curr_task->ick_data) {
    pr_alert("ick: ick_revert_proc called on %s[%d] which is not under ick checkpoint\n", curr_task->comm, pid);
    return -EINVAL;
  }

  __ick_revert_process(curr_task);

  if (reset_ick) {
    ick_cleanup(curr_task);
  }

  return 0;
}

// Checkpoint the process: mark pages as read-only and hook VMAs
static int __ick_mark_pages(struct task_struct *task,
                            struct ick_checked_process *ick_data) {
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct mmu_gather tlb;
  MA_STATE(mas, &task->mm->mm_mt, 0, ULONG_MAX);

  mm = task->mm;
  if (!mm) {
    return -EINVAL;
  }

  // This is the lock used for the maple tree as well
  mmap_write_lock_killable(mm);
  tlb_gather_mmu(&tlb, task->mm);

  while ((vma = mas_find(&mas, ULONG_MAX))) {
    if (!(vma->vm_flags & (VM_WRITE | VM_MAYWRITE))) {
      trace_printk("Skipping VMA %lx-%lx (%s) as not VM_WRITE\n", vma->vm_start,
                   vma->vm_end,
                   vma->vm_file ? (char *)vma->vm_file->f_path.dentry->d_iname
                                : "anon");
      BUG_ON(vma->vm_page_prot.pgprot & VM_WRITE);
      continue;
    }

    trace_printk(
        "Marking VMA %lx-%lx (%lu KiB of %s) as read-only\n", vma->vm_start,
        vma->vm_end, (vma->vm_end - vma->vm_start) / 1024,
        vma->vm_file ? (char *)vma->vm_file->f_path.dentry->d_iname : "anon");

    vma_set_page_prot(vma);
    change_protection(&tlb, vma, vma->vm_start, vma->vm_end, 0);
  }

  tlb_finish_mmu(&tlb);
  mmap_write_unlock(mm); // Calls vma_end_write_all
  return 0;
}

vm_fault_t ick_do_wp_page(struct vm_fault *vmf) {
  unsigned long addr = (unsigned long)vmf->address;
  unsigned long page_addr = addr & PAGE_MASK;
  struct task_struct *task = current;
  struct ick_checked_process *ick_data = task->ick_data;
  struct ick_modified_page *mod_page;
  struct rb_node **new;
  struct rb_node *parent = NULL;
  long ret;

  BUG_ON(!ick_data);
  BUG_ON(!(vmf->flags & FAULT_FLAG_WRITE));

  if (READ_ONCE(ick_data->reverting)) {
    return VM_FAULT_LOCKED;
  }

  spin_lock(&ick_data->tree_lock);
  new = &ick_data->modified_pages_tree.rb_node;
  while (*new) {
    parent = *new;
    mod_page = rb_entry(parent, struct ick_modified_page, node);

    if (page_addr < mod_page->addr)
      new = &parent->rb_left;
    else if (page_addr > mod_page->addr)
      new = &parent->rb_right;
    else {
      // Page already in tree, so it's already copied before. Ignore.
      trace_printk("Already in tree page 0x%px hti wp fault at 0x%px again\n", (void*)page_addr, (void*)addr);
      spin_unlock(&ick_data->tree_lock);
      return VM_FAULT_LOCKED;
    }
  }

  u8 *copied_page_content = vmalloc(PAGE_SIZE);
  if (!copied_page_content) {
    spin_unlock(&ick_data->tree_lock);
    return VM_FAULT_OOM;
  }

  mod_page = vmalloc(sizeof(*mod_page));
  mod_page->addr = page_addr;
  rb_link_node(&mod_page->node, parent, new);
  rb_insert_color(&mod_page->node, &ick_data->modified_pages_tree);
  mod_page->orig_page_content = copied_page_content;
  trace_printk("CoWing page 0x%px following wp fault at 0x%px\n", (void*) page_addr, (void*) addr);
  ret = copy_from_user_nofault(copied_page_content, (void *)page_addr, PAGE_SIZE);
  if (ret) {
    pr_alert("ick: Failed to copy page 0x%px following wp fault at 0x%px: %pe\n", (void*)page_addr, (void*)addr, ERR_PTR(ret));
    spin_unlock(&ick_data->tree_lock);
    return VM_FAULT_SIGBUS;
  }

  spin_unlock(&ick_data->tree_lock);

  return VM_FAULT_LOCKED;
}

// copied from process_64.c
enum which_selector { FS, GS };

// copied from process_64.c
static __always_inline void loadseg(enum which_selector which,
                                    unsigned short sel) {
  if (which == FS)
    loadsegment(fs, sel);
  else
    load_gs_index(sel);
}

// copied from process_64.c
static __always_inline void load_seg_legacy(unsigned short prev_index,
                                            unsigned long prev_base,
                                            unsigned short next_index,
                                            unsigned long next_base,
                                            enum which_selector which) {
  if (likely(next_index <= 3)) {
    /*
     * The next task is using 64-bit TLS, is not using this
     * segment at all, or is having fun with arcane CPU features.
     */
    if (next_base == 0) {
      /*
       * Nasty case: on AMD CPUs, we need to forcibly zero
       * the base.
       */
      if (static_cpu_has_bug(X86_BUG_NULL_SEG)) {
        loadseg(which, __USER_DS);
        loadseg(which, next_index);
      } else {
        /*
         * We could try to exhaustively detect cases
         * under which we can skip the segment load,
         * but there's really only one case that matters
         * for performance: if both the previous and
         * next states are fully zeroed, we can skip
         * the load.
         *
         * (This assumes that prev_base == 0 has no
         * false positives.  This is the case on
         * Intel-style CPUs.)
         */
        if (likely(prev_index | next_index | prev_base))
          loadseg(which, next_index);
      }
    } else {
      if (prev_index != next_index)
        loadseg(which, next_index);
      wrmsrl(which == FS ? MSR_FS_BASE : MSR_KERNEL_GS_BASE, next_base);
    }
  } else {
    /*
     * The next task is using a real segment.  Loading the selector
     * is sufficient.
     */
    loadseg(which, next_index);
  }
}

// copied from process_64.c
static noinstr void __wrgsbase_inactive(unsigned long gsbase) {
  lockdep_assert_irqs_disabled();

  if (!cpu_feature_enabled(X86_FEATURE_FRED) &&
      !cpu_feature_enabled(X86_FEATURE_XENPV)) {
    native_swapgs();
    wrgsbase(gsbase);
    native_swapgs();
  } else {
    instrumentation_begin();
    wrmsrl(MSR_KERNEL_GS_BASE, gsbase);
    instrumentation_end();
  }
}

// copied from process_64.c
static __always_inline void x86_fsgsbase_load(struct thread_struct *prev,
                                              struct thread_struct *next) {
  if (static_cpu_has(X86_FEATURE_FSGSBASE)) {
    /* Update the FS and GS selectors if they could have changed. */
    if (unlikely(prev->fsindex || next->fsindex))
      loadseg(FS, next->fsindex);
    if (unlikely(prev->gsindex || next->gsindex))
      loadseg(GS, next->gsindex);

    /* Update the bases. */
    wrfsbase(next->fsbase);
    __wrgsbase_inactive(next->gsbase);
  } else {
    load_seg_legacy(prev->fsindex, prev->fsbase, next->fsindex, next->fsbase,
                    FS);
    load_seg_legacy(prev->gsindex, prev->gsbase, next->gsindex, next->gsbase,
                    GS);
  }
}

// Restore the process to the checkpointed state
static int __ick_revert_process(struct task_struct *task) {
  struct ick_checked_process *ick_data;
  struct ick_modified_page *mod_page;
  struct rb_node *node;
  struct mm_struct *mm;
  unsigned long addr;
  int ret = 0;
  struct pt_regs *regs;

  BUG_ON(task != current);
  // TODO: we should probably just get rid of the task argument

  ick_data = task->ick_data;
  BUG_ON(!ick_data);

  mm = task->mm;
  if (!mm) {
    return -EINVAL;
  }

  BUG_ON(xchg(&ick_data->reverting, true));

  spin_lock(&ick_data->tree_lock);
  // Do it in order for better cache locality
  for (node = rb_first(&ick_data->modified_pages_tree); node;
        node = rb_next(node)) {
    mod_page = rb_entry(node, struct ick_modified_page, node);
    addr = mod_page->addr;
    u8 *orig_page_content = mod_page->orig_page_content;
    trace_printk("Restoring CoW'd page at 0x%px\n", (void*)addr);
    ret = copy_to_user_nofault((void *)addr, orig_page_content, PAGE_SIZE);
    if (ret) {
      pr_alert("ick: Failed to copy page content for 0x%px back: %pe\n", (void*)addr, ERR_PTR(ret));
      spin_unlock(&ick_data->tree_lock);
      return ret;
    }
  }
  spin_unlock(&ick_data->tree_lock);

  WRITE_ONCE(ick_data->reverting, false);

  // Restore registers
#if defined(__x86_64__)
  {
    regs = task_pt_regs(task);
    memcpy(regs, &ick_data->saved_regs, sizeof(struct pt_regs));

    // XXX: there is some issue with this code which causes recursive page
    // faults when spin_unlock above is preempted for some reason???

    // current_save_fsgs();
    // x86_fsgsbase_load(&task->thread, &ick_data->saved_state);
    // task->thread.fsindex = ick_data->saved_state.fsindex;
    // task->thread.fsbase = ick_data->saved_state.fsbase;
    // task->thread.gsindex = ick_data->saved_state.gsindex;
    // task->thread.gsbase = ick_data->saved_state.gsbase;

    // task->thread.es = ick_data->saved_state.es;
    // loadsegment(es, ick_data->saved_state.es);
    // task->thread.ds = ick_data->saved_state.ds;
    // loadsegment(ds, ick_data->saved_state.ds);
  }
#else
#error "Unsupported architecture"
#endif

  trace_printk("Restored process %s[%d], ip = %px, sp = %px\n", task->comm, task->pid, (void*)regs->ip, (void*)regs->sp);

  return 0;
}

void ick_cleanup(struct task_struct *task) {
  struct ick_checked_process *ick_data = task->ick_data;

  if (!ick_data) {
    return;
  }

  trace_printk("Cleaning up ick data for %s[%d]\n", task->comm, task->pid);

  spin_lock(&ick_data->tree_lock);
  if (!RB_EMPTY_ROOT(&ick_data->modified_pages_tree)) {
    struct ick_modified_page *mod_page, *tmp;
    rbtree_postorder_for_each_entry_safe(mod_page, tmp, &ick_data->modified_pages_tree, node) {
      vfree(mod_page->orig_page_content);
      vfree(mod_page);
    }
  }
  spin_unlock(&ick_data->tree_lock);

  kfree(ick_data);
  task->ick_data = NULL;
}
