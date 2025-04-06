// SPDX-License-Identifier: GPL-2.0-only
/*
 * Specific operations on the v9fs_ino_path structure.
 *
 * Copyright (C) 2025 by Tingmao Wang <m@maowtm.org>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/dcache.h>

#include <linux/posix_acl.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>
#include "v9fs.h"

/*
 * Must hold rename_sem due to traversing parents
 */
struct v9fs_ino_path *make_ino_path(struct dentry *dentry)
{
	struct v9fs_ino_path *path;
	size_t path_components = 0;
	struct dentry *curr = dentry;
	ssize_t i;

	lockdep_assert_held_read(&v9fs_dentry2v9ses(dentry)->rename_sem);

	rcu_read_lock();

    /* Don't include the root dentry */
	while (curr->d_parent != curr) {
		path_components++;
		curr = curr->d_parent;
	}
	if (WARN_ON(path_components > SSIZE_MAX)) {
		rcu_read_unlock();
		return NULL;
	}

	path = kmalloc(struct_size(path, names, path_components),
		       GFP_KERNEL);
	if (!path) {
		rcu_read_unlock();
		return NULL;
	}

	path->nr_components = path_components;
	curr = dentry;
	for (i = path_components - 1; i >= 0; i--) {
		take_dentry_name_snapshot(&path->names[i], curr);
		curr = curr->d_parent;
	}
	WARN_ON(curr != curr->d_parent);
	rcu_read_unlock();
	return path;
}

void free_ino_path(struct v9fs_ino_path *path)
{
	if (path) {
		for (size_t i = 0; i < path->nr_components; i++)
			release_dentry_name_snapshot(&path->names[i]);
		kfree(path);
	}
}

/*
 * Must hold rename_sem due to traversing parents
 */
bool ino_path_compare(struct v9fs_ino_path *ino_path,
			     struct dentry *dentry)
{
	struct dentry *curr = dentry;
	struct qstr *curr_name;
	struct name_snapshot *compare;
	ssize_t i;

	lockdep_assert_held_read(&v9fs_dentry2v9ses(dentry)->rename_sem);

	rcu_read_lock();
	for (i = ino_path->nr_components - 1; i >= 0; i--) {
		if (curr->d_parent == curr) {
			/* We're supposed to have more components to walk */
			rcu_read_unlock();
			return false;
		}
		curr_name = &curr->d_name;
		compare = &ino_path->names[i];
		/*
		 * We can't use hash_len because it is salted with the parent
		 * dentry pointer.  We could make this faster by pre-computing our
		 * own hashlen for compare and ino_path outside, probably.
		 */
		if (curr_name->len != compare->name.len) {
			rcu_read_unlock();
			return false;
		}
		if (strncmp(curr_name->name, compare->name.name,
			    curr_name->len) != 0) {
			rcu_read_unlock();
			return false;
		}
		curr = curr->d_parent;
	}
	rcu_read_unlock();
	if (curr != curr->d_parent) {
		/* dentry is deeper than ino_path */
		return false;
	}
	return true;
}
