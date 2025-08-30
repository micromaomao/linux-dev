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

static struct kmem_cache *v9fs_ino_path_cache;

int v9fs_init_ino_path_cache(void)
{
	v9fs_ino_path_cache = kmem_cache_create(
		"v9fs_ino_path_cache", sizeof(struct v9fs_ino_path), 0,
		(SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT), NULL);
	if (!v9fs_ino_path_cache)
		return -ENOMEM;

	return 0;
}

static struct v9fs_ino_path *inopath_for_dentry_rcu(struct dentry *dentry)
{
	struct inode *inode = d_inode_rcu(dentry);

	if (!inode)
		return NULL;
	return V9FS_I(inode)->path;
}

/*
 * Must hold rename_sem due to traversing parents.  Caller must hold
 * reference to dentry.
 */
struct v9fs_ino_path *make_ino_path(struct dentry *dentry)
{
	struct v9fs_ino_path *this_inopath = NULL, *parent_inopath = NULL;
	struct dentry *parent;
	struct inode *parent_inode;
	int ret = 0;

	/* Either read or write lock held is ok */
	lockdep_assert_held(&v9fs_dentry2v9ses(dentry)->rename_sem);
	might_sleep(); /* Allocation below might block */

	this_inopath = kmem_cache_alloc(v9fs_ino_path_cache, GFP_KERNEL);
	if (!this_inopath)
		return NULL;

	refcount_set(&this_inopath->usage, 1);

	rcu_read_lock();
	parent = READ_ONCE(dentry->d_parent);
	if (parent != dentry) {
		parent_inode = d_inode_rcu(parent);
		if (WARN_ON_ONCE(!parent_inode) ||
			WARN_ON_ONCE(parent_inode->i_sb != dentry->d_sb)) {
			ret = -EINVAL;
			goto error_rcu;
		}
		parent_inopath = V9FS_I(parent_inode)->path;
		if (WARN_ON_ONCE(!parent_inopath)) {
			ret = -EINVAL;
			goto error_rcu;
		}
		get_ino_path(parent_inopath);
	}

	this_inopath->parent = parent_inopath;
	take_dentry_name_snapshot(&this_inopath->name, dentry);
	rcu_read_unlock();
	return this_inopath;

error_rcu:
	rcu_read_unlock();
	kmem_cache_free(v9fs_ino_path_cache, this_inopath);
	return ERR_PTR(ret);
}

void get_ino_path(struct v9fs_ino_path *inopath)
{
	refcount_inc(&inopath->usage);
}

void put_ino_path(struct v9fs_ino_path *inopath)
{
	struct v9fs_ino_path *curr = inopath, *parent;

	/*
	 * Puts the passed in ino_path, and if freed, recursively puts and
	 * frees its parent as well.
	 */
	while (curr && refcount_dec_and_test(&curr->usage)) {
		release_dentry_name_snapshot(&curr->name);
		parent = curr->parent;
		kfree(curr);
		curr = parent;
	}
}

/*
 * Must hold rename_sem due to traversing parents.  Returns whether
 * ino_path matches with the path of a v9fs dentry.  This function does
 * not sleep.
 */
bool ino_path_compare(struct v9fs_ino_path *ino_path, struct dentry *dentry)
{
	struct dentry *curr = dentry;
	struct name_snapshot *compare;
	ssize_t i;
	bool ret;

	lockdep_assert_held_read(&v9fs_dentry2v9ses(dentry)->rename_sem);

	rcu_read_lock();
	for (i = ino_path->nr_components - 1; i >= 0; i--) {
		if (curr->d_parent == curr) {
			/* We're supposed to have more components to walk */
			rcu_read_unlock();
			return false;
		}
		compare = &ino_path->names[i];
		if (!d_same_name(curr, curr->d_parent, &compare->name)) {
			rcu_read_unlock();
			return false;
		}
		curr = curr->d_parent;
	}
	/* Comparison fails if dentry is deeper than ino_path */
	ret = (curr == curr->d_parent);
	rcu_read_unlock();
	return ret;
}

void ino_path_rename(struct v9fs_ino_path *src, struct dentry *dst_name)
{
}
