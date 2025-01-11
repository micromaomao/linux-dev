/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/ick.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>

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
