// SPDX-License-Identifier: GPL-2.0

#include <linux/ick.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/vmalloc.h>
#include <asm/tlb.h>

/* Mark pages as write-protected */
static void mark_pages(void)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct mmu_gather tlb;

	/*
	 * Kernel threads don't have their own `mm`, and we can't checkpoint a kernel
	 * thread anyway
	 */
	BUG_ON(!mm);
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

/**
 * Called from page fault handler to copy off page content before allowing
 * it to be modified.  Returns zero on success, and any of the bits in
 * VM_FAULT_ERROR on failure.
 */
vm_fault_t ick_do_wp_page(struct vm_fault *vmf)
{
	unsigned long page_addr = vmf->address;
	struct task_struct *task = current;
	struct ick_checked_process *ick_data = task->ick_data;
	struct ick_modified_page *mod_page, *new_mod_page __free(kfree) = NULL;
	u8 *copied_page_content __free(kfree) = NULL;
	struct rb_node **new;
	struct rb_node *parent = NULL;
	long ret;

	BUG_ON(!ick_data);
	BUG_ON(!(vmf->flags & FAULT_FLAG_WRITE));

	trace_printk("CoWing page 0x%px following wp fault at offset 0x%x\n",
					(void *)page_addr, (int)(vmf->real_address - page_addr));

	/*
	 * We will pretty much always need these, so do the allocations now,
	 * outside of the spinlock
	 */
	copied_page_content = kmalloc(PAGE_SIZE, GFP_KERNEL_ACCOUNT);
	new_mod_page = kmalloc(sizeof(*mod_page), GFP_KERNEL_ACCOUNT);

	if (!copied_page_content || !new_mod_page) {
		return VM_FAULT_OOM;
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
			/* Page already in tree, so it's already copied before. Ignore. */
			trace_printk("Already in tree page 0x%px hti wp fault again\n", (void *)page_addr);
			spin_unlock(&ick_data->tree_lock);
			return 0;
		}
	}

	ret = copy_from_user_nofault(copied_page_content, (void *)page_addr, PAGE_SIZE);
	if (ret) {
		pr_alert("ick: Failed to copy page 0x%px following wp fault\n", (void *)page_addr);
		spin_unlock(&ick_data->tree_lock);
		return VM_FAULT_SIGBUS;
	}

	mod_page = new_mod_page;
	mod_page->addr = page_addr;
	mod_page->orig_page_content = copied_page_content;
	rb_link_node(&mod_page->node, parent, new);
	rb_insert_color(&mod_page->node, &ick_data->modified_pages_tree);

	/* Don't free these anymore */
	new_mod_page = NULL;
	copied_page_content = NULL;

	spin_unlock(&ick_data->tree_lock);

	return 0;
}

/**
 * Initialize the ick data structures on the current task and checkpoint it.
 */
int ick_checkpoint_proc(void)
{
	struct ick_checked_process *ick_data;
	struct pt_regs *regs;

	if (current->ick_data) {
		pr_alert("ick: %s[%d] already has a checkpoint\n",
				current->comm, current->pid);
		return -EEXIST;
	}

	ick_data = kzalloc(sizeof(*ick_data), GFP_KERNEL);
	if (!ick_data)
		return -ENOMEM;

	/* Save registers */
#if defined(__x86_64__)
	regs = current_pt_regs();
	memcpy(&ick_data->saved_regs, regs, sizeof(struct pt_regs));
#else
#error "Unsupported architecture"
#endif

	mark_pages();

	/* TODO: implement rest */

	current->ick_data = ick_data;
	trace_printk("ick: Checkpointed %s[%d]\n", current->comm, current->pid);

	return 0;
}

static void print_modified_page_tree(struct rb_root *root)
{
	struct rb_node *node;
	struct ick_modified_page *mod_page;
	u8 *current_page_content __free(kfree) = kmalloc(PAGE_SIZE, GFP_KERNEL);
	u8 *orig_page_content;
	int ret;

	if (WARN_ON(!current_page_content))
		return;

	if (!root)
		return;

	trace_printk("Modified pages:\n");
	for (node = rb_first(root); node; node = rb_next(node)) {
		int diff_start_byte = -1;
		int diff_n_bytes = 0;

		mod_page = rb_entry(node, struct ick_modified_page, node);
		ret = copy_from_user_nofault(
			current_page_content,
			(const void __user *)mod_page->addr, PAGE_SIZE);
		if (WARN_ON(ret)) {
			return;
		}
		orig_page_content = mod_page->orig_page_content;
		for (int i = 0; i < PAGE_SIZE; i++) {
			if (diff_start_byte >= 0) {
				if (current_page_content[i] != orig_page_content[i])
					diff_n_bytes = i - diff_start_byte + 1;
			} else if (current_page_content[i] != orig_page_content[i]) {
				diff_start_byte = i;
				diff_n_bytes = 1;
			}
		}
		if (diff_start_byte != -1) {
			trace_printk(
				"Page 0x%016lx: change starting at offset 0x%03x for %d bytes\n",
				mod_page->addr, diff_start_byte, diff_n_bytes);
		} else {
			trace_printk("Page 0x%016lx: no changes\n", mod_page->addr);
		}
	}
}

/**
 * Revert the current task to the state checkpointed by ick_checkpoint_proc.
 */
int ick_revert_proc(void)
{
	struct ick_checked_process *ick_data;
	struct pt_regs *regs;
	struct ick_modified_page *mod_page;
	struct rb_node *node;
	unsigned long addr;
	int ret = 0;
	u8 *orig_page_content;

	ick_data = current->ick_data;
	if (!ick_data) {
		pr_alert("ick: ick_revert_proc called on %s[%d] which is not under ick checkpoint\n",
				current->comm, current->pid);
		return -EINVAL;
	}

	/* Restore registers */
#if defined(__x86_64__)
	regs = current_pt_regs();
	memcpy(regs, &ick_data->saved_regs, sizeof(struct pt_regs));
#else
#error "Unsupported architecture"
#endif

	spin_lock(&ick_data->tree_lock);
	/* Do it in address space order for better cache locality when copying */
	for (node = rb_first(&ick_data->modified_pages_tree); node;
				node = rb_next(node)) {
		mod_page = rb_entry(node, struct ick_modified_page, node);
		addr = mod_page->addr;
		orig_page_content = mod_page->orig_page_content;
		trace_printk("Restoring CoW'd page at 0x%px\n", (void *)addr);
		ret = copy_to_user_nofault((void *)addr, orig_page_content, PAGE_SIZE);
		if (ret) {
			pr_alert("ick: Failed to copy page content for 0x%px back\n", (void *)addr);
			spin_unlock(&ick_data->tree_lock);
			return -EFAULT;
		}
	}
	spin_unlock(&ick_data->tree_lock);

	trace_printk("Restored process %s[%d]\n",
			current->comm, current->pid);

	return 0;
}

/**
 * Clean up any saved ick checkpoints from the current task, if there is any.
 * Call before a task exits.
 */
void ick_cleanup(struct task_struct *task)
{
	struct ick_checked_process *ick_data = task->ick_data;

	if (!ick_data)
		return;

	trace_printk("Cleaning up ick data for %s[%d]\n", task->comm, task->pid);

	/* TODO: add more clean-up code here */

	kfree(ick_data);
	task->ick_data = NULL;
	return;
}
