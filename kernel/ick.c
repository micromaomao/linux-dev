/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/ick.h>
#include <linux/errno.h>

int ick_checkpoint_proc(void) {
	// TODO: implement
	return -EPERM;
}

int ick_revert_proc(void) {
	// TODO: implement
	return -EPERM;
}

void ick_cleanup(struct task_struct *task) {
	// TODO: implement
	return;
}
