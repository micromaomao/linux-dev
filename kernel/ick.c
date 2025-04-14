/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/ick.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <asm/tlb.h>

// Mark pages as write-protected
static void mark_pages(void) {
	struct mm_struct *mm = current->mm;
	// Kernel threads don't have their own `mm`, and we can't checkpoint a kernel
	// thread anyway
	BUG_ON(!mm);
	struct vm_area_struct *vma;
	struct mmu_gather tlb;
	VMA_ITERATOR(vmi, mm, 0);
	pgprotval_t vm_page_prot;

	if (mmap_write_lock_killable(mm)) {
		// If we return from here, we're getting killed anyway
		return;
	}
	tlb_gather_mmu(&tlb, mm);

	for_each_vma(vmi, vma) {
		if (!(vma->vm_flags & VM_WRITE)) {
			// The VMA can still have VM_MAYWRITE, which means that a future mprotect
			// call can make it writable (for example because the underlying file is
			// opened as writable). For now we don't care - we will block all
			// memory-related syscalls anyway.
			trace_printk("Skipping non-writable VMA %lx-%lx (%s)\n",
				vma->vm_start, vma->vm_end,
				vma->vm_file ? (char *)vma->vm_file->f_path.dentry->d_iname : "anon");
			continue;
		}

		trace_printk("Marking VMA %lx-%lx (%lu KiB) as read-only\n",
			vma->vm_start, vma->vm_end, (vma->vm_end - vma->vm_start) / 1024);

		vma_start_write(vma);
		// Maybe there's a more standard way to do this? But various useful
		// functions in mm/memory.c are static
		vm_page_prot = vma->vm_page_prot.pgprot;
		vm_page_prot &= ~_PAGE_RW;
		WRITE_ONCE(vma->vm_page_prot.pgprot, vm_page_prot);
		change_protection(&tlb, vma, vma->vm_start, vma->vm_end, 0);
	}

	tlb_finish_mmu(&tlb);
	mmap_write_unlock(mm);
}

vm_fault_t ick_do_wp_page(struct vm_fault *vmf) {
	unsigned long page_addr = vmf->address;
	struct task_struct *task = current;
	struct ick_checked_process *ick_data = task->ick_data;

	BUG_ON(!ick_data);
	BUG_ON(!(vmf->flags & FAULT_FLAG_WRITE));

	trace_printk("CoWing page 0x%px following wp fault at offset 0x%x\n",
					(void *)page_addr, (int)(vmf->real_address - page_addr));

	/* TODO */

	return 0;
}

int ick_checkpoint_proc(void) {
	struct ick_checked_process *ick_data;
	struct pt_regs *regs;

	if (current->ick_data) {
		pr_alert("ick: %s[%d] already has a checkpoint\n",
				current->comm, current->pid);
		return -EEXIST;
	}

	ick_data = kzalloc(sizeof(*ick_data), GFP_KERNEL);
	if (!ick_data) {
		return -ENOMEM;
	}

	// Save registers
#if defined(__x86_64__)
	regs = current_pt_regs();
	memcpy(&ick_data->saved_regs, regs, sizeof(struct pt_regs));
#else
#error "Unsupported architecture"
#endif

	mark_pages();

	// TODO: implement rest

	current->ick_data = ick_data;
	trace_printk("ick: Checkpointed %s[%d]\n", current->comm, current->pid);

	return 0;
}

int ick_revert_proc(void) {
	struct ick_checked_process *ick_data;
	struct pt_regs *regs;

	ick_data = current->ick_data;
	if (!ick_data) {
		pr_alert("ick: ick_revert_proc called on %s[%d] which is not under ick checkpoint\n",
				current->comm, current->pid);
		return -EINVAL;
	}

	// Restore registers
#if defined(__x86_64__)
	regs = current_pt_regs();
	memcpy(regs, &ick_data->saved_regs, sizeof(struct pt_regs));
#else
#error "Unsupported architecture"
#endif

	// TODO: implement rest

	trace_printk("Restored process %s[%d]\n",
			current->comm, current->pid);

	return 0;
}

void ick_cleanup(struct task_struct *task) {
	struct ick_checked_process *ick_data = task->ick_data;

	if (!ick_data) {
		return;
	}

	trace_printk("Cleaning up ick data for %s[%d]\n", task->comm, task->pid);

	// TODO: add more clean-up code here

	kfree(ick_data);
	task->ick_data = NULL;
	return;
}
