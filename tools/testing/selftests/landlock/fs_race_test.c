// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Pathwalk race conditions
 *
 * Copyright © 2025 Tingmao Wang <m@maowtm.org>
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include "common.h"

#define NUM_SUBDIRS 1000
#define TEST_DIR TMP_DIR "/fs_race_test"
#define SUBDIR_NAME_FORMAT "s%dd1"
#define SUBSUBDIR_NAME_FORMAT "s%dd2"
#define TEST_FILE_NAME "file"
#define TEST_TIME 30

/* layout hierarchy:
 * tmp
 * └── fs_race_test
 *     ├── s0d1
 *     │   └── file
 *     |── s1d1
 *     └── ...
 *
 * or
 *
 * tmp
 * └── fs_race_test
 *     ├── s0d1
 *     │   └── s0d2
 *     │       └── file
 *     |── s1d1
 *     |   └── s1d2
 *     └── ...
 */

FIXTURE(layout)
{
	int base_dir_fd;
	bool need_subdir_cleanup;
	int subdir_fds[NUM_SUBDIRS];
	bool has_subsubdir;
	int subsubdir_fds[NUM_SUBDIRS];
	int ruleset_fd;
	int test_file_at;
};

static void create_subdirs(struct __test_metadata *const _metadata,
			   struct _test_data_layout *const self)
{
	int i, err;
	char subdir[20];

	for (i = 0; i < NUM_SUBDIRS; i++) {
		snprintf(subdir, sizeof(subdir), SUBDIR_NAME_FORMAT, i);
		err = mkdirat(self->base_dir_fd, subdir, 0755);

		ASSERT_TRUE(err == 0 || errno == EEXIST)
		{
			TH_LOG("Failed to create " TEST_DIR "/%s: %s", subdir,
			       strerror(errno));
		}
		self->subdir_fds[i] = openat(self->base_dir_fd, subdir, O_PATH);
		ASSERT_NE(self->subdir_fds[i], -1)
		{
			TH_LOG("Failed to open " TEST_DIR "/%s: %s", subdir,
			       strerror(errno));
		}

		if (self->has_subsubdir) {
			char subsubdir[20];
			snprintf(subsubdir, sizeof(subsubdir),
				 SUBSUBDIR_NAME_FORMAT, i);

			err = mkdirat(self->subdir_fds[i], subsubdir, 0755);
			ASSERT_TRUE(err == 0 || errno == EEXIST)
			{
				TH_LOG("Failed to create " TEST_DIR
				       "/%s/%s: %s",
				       subdir, subsubdir, strerror(errno));
			}
			self->subsubdir_fds[i] =
				openat(self->subdir_fds[i], subsubdir, O_PATH);
			ASSERT_NE(self->subsubdir_fds[i], -1)
			{
				TH_LOG("Failed to open " TEST_DIR "/%s/%s: %s",
				       subdir, subsubdir, strerror(errno));
			}
		} else {
			self->subsubdir_fds[i] = -1;
		}
	}

	self->need_subdir_cleanup = true;
}

static void cleanup_subdirs(struct __test_metadata *const _metadata,
			    struct _test_data_layout *const self)
{
	int i, err;
	char subdir[20];
	char subsubdir[20];

	if (!self->need_subdir_cleanup)
		return;

	self->need_subdir_cleanup = false;

	for (i = 0; i < NUM_SUBDIRS; i++) {
		snprintf(subdir, sizeof(subdir), SUBDIR_NAME_FORMAT, i);
		if (self->has_subsubdir) {
			snprintf(subsubdir, sizeof(subsubdir),
				 SUBSUBDIR_NAME_FORMAT, i);

			if (self->subsubdir_fds[i] != -1) {
				close(self->subsubdir_fds[i]);
				self->subsubdir_fds[i] = -1;

				err = unlinkat(self->subdir_fds[i], subsubdir,
					       AT_REMOVEDIR);
				ASSERT_TRUE(err == 0 || errno == ENOENT)
				{
					TH_LOG("Failed to remove " TEST_DIR
					       "/%s/%s: %s",
					       subdir, subsubdir,
					       strerror(errno));
				}
			}
		}

		if (self->subdir_fds[i] == -1)
			continue;
		close(self->subdir_fds[i]);
		self->subdir_fds[i] = -1;

		err = unlinkat(self->base_dir_fd, subdir, AT_REMOVEDIR);
		ASSERT_TRUE(err == 0 || errno == ENOENT)
		{
			TH_LOG("Failed to remove " TEST_DIR "/%s: %s", subdir,
			       strerror(errno));
		}
	}
}

static void create_test_dir(struct __test_metadata *const _metadata,
			    struct _test_data_layout *const self)
{
	int err;

	err = mkdir(TMP_DIR, 0755);
	ASSERT_TRUE(err == 0 || errno == EEXIST)
	{
		TH_LOG("Failed to create ./" TMP_DIR ": %s", strerror(errno));
		return;
	}

	err = mkdir(TEST_DIR, 0755);
	ASSERT_TRUE(err == 0 || errno == EEXIST)
	{
		TH_LOG("Failed to create " TEST_DIR ": %s", strerror(errno));
		return;
	}

	self->base_dir_fd = open(TEST_DIR, O_PATH);
	ASSERT_NE(self->base_dir_fd, -1)
	{
		TH_LOG("Failed to open " TEST_DIR ": %s", strerror(errno));
		return;
	}
}

static void cleanup_test_dir(struct __test_metadata *const _metadata,
			     struct _test_data_layout *const self)
{
	int err;

	close(self->base_dir_fd);
	err = rmdir(TEST_DIR);
	ASSERT_EQ(0, err)
	{
		TH_LOG("Failed to remove " TEST_DIR ": %s", strerror(errno));
	}
	err = rmdir(TMP_DIR);
	ASSERT_EQ(0, err)
	{
		TH_LOG("Failed to remove ./" TMP_DIR ": %s", strerror(errno));
	}
}

static int test_file_dfd(struct __test_metadata *const _metadata,
			 struct _test_data_layout *const self, int at)
{
	if (self->has_subsubdir) {
		return self->subsubdir_fds[at];
	} else {
		return self->subdir_fds[at];
	}
}

static void create_test_file(struct __test_metadata *const _metadata,
			     struct _test_data_layout *const self)
{
	int dfd;
	int fd;

	ASSERT_EQ(-1, self->test_file_at);

	self->test_file_at = 0;
	dfd = test_file_dfd(_metadata, self, self->test_file_at);
	ASSERT_NE(-1, dfd);

	fd = openat(dfd, TEST_FILE_NAME, O_CREAT | O_RDWR, 0644);
	ASSERT_NE(-1, fd)
	{
		TH_LOG("Failed to create " TEST_DIR "/%s: %s", TEST_FILE_NAME,
		       strerror(errno));
		return;
	}
	close(fd);
}

struct shared_region {
	int test_file_at_dfd;
	bool stop;
};

/* TODO: this is probably wrong for non x86 */
#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) (*(volatile typeof(x) *)&(x) = (val))
#endif

static void move_test_file_and_rmdir(struct __test_metadata *const _metadata,
				     struct _test_data_layout *const self,
				     int to, struct shared_region *shr)
{
	int from_fd, to_fd, err;
	char pathbuf[255];

	ASSERT_NE(-1, self->test_file_at);
	ASSERT_FALSE(self->test_file_at == to);

	from_fd = test_file_dfd(_metadata, self, self->test_file_at);
	to_fd = test_file_dfd(_metadata, self, to);

	ASSERT_NE(-1, from_fd);
	ASSERT_NE(-1, to_fd);

	err = renameat(from_fd, TEST_FILE_NAME, to_fd, TEST_FILE_NAME);
	ASSERT_EQ(0, err)
	{
		TH_LOG("Failed to move test file from subdir %d to subdir %d: %s",
		       self->test_file_at, to, strerror(errno));
	}
	WRITE_ONCE(shr->test_file_at_dfd, to_fd);
	if (self->has_subsubdir) {
		close(self->subsubdir_fds[self->test_file_at]);
		self->subsubdir_fds[self->test_file_at] = -1;
		snprintf(pathbuf, sizeof(pathbuf), SUBSUBDIR_NAME_FORMAT,
			 self->test_file_at);
		err = unlinkat(self->subdir_fds[self->test_file_at], pathbuf,
			       AT_REMOVEDIR);
		ASSERT_NE(-1, err)
		{
			TH_LOG("Failed to remove " TEST_DIR "/%s: %s", pathbuf,
			       strerror(errno));
		}
	}

	close(self->subdir_fds[self->test_file_at]);
	self->subdir_fds[self->test_file_at] = -1;
	snprintf(pathbuf, sizeof(pathbuf), SUBDIR_NAME_FORMAT,
		 self->test_file_at);
	err = unlinkat(self->base_dir_fd, pathbuf, AT_REMOVEDIR);
	ASSERT_NE(-1, err)
	{
		TH_LOG("Failed to remove " TEST_DIR "/%s: %s", pathbuf,
		       strerror(errno));
	}

	self->test_file_at = to;
}

static void cleanup_test_file(struct __test_metadata *const _metadata,
			      struct _test_data_layout *const self)
{
	if (self->test_file_at == -1)
		return;

	int dfd = test_file_dfd(_metadata, self, self->test_file_at);
	int err = unlinkat(dfd, TEST_FILE_NAME, 0);
	ASSERT_EQ(0, err)
	{
		TH_LOG("Failed to remove " TEST_DIR "/%s: %s", TEST_FILE_NAME,
		       strerror(errno));
	}
	self->test_file_at = -1;
}

static void create_ruleset(struct __test_metadata *const _metadata,
			   struct _test_data_layout *const self)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_READ_DIR |
				     LANDLOCK_ACCESS_FS_WRITE_FILE |
				     LANDLOCK_ACCESS_FS_REMOVE_FILE |
				     LANDLOCK_ACCESS_FS_MAKE_REG |
				     LANDLOCK_ACCESS_FS_MAKE_DIR |
				     LANDLOCK_ACCESS_FS_REMOVE_DIR |
				     LANDLOCK_ACCESS_FS_REFER,
		.handled_access_net = 0,
		.scoped = 0,
	};
	struct landlock_path_beneath_attr rule_attr = {
		.parent_fd = -1,
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
				  LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int ruleset_fd, err, dfd;

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_GE(ruleset_fd, 0)
	{
		TH_LOG("Failed to create ruleset: %s", strerror(errno));
	}

	for (int i = 0; i < NUM_SUBDIRS; i++) {
		/* We want the rule to be on s*d1 */
		dfd = self->subdir_fds[i];
		ASSERT_NE(-1, dfd);
		rule_attr.parent_fd = dfd;
		err = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
					&rule_attr, 0);
		ASSERT_EQ(0, err)
		{
			TH_LOG("Failed to add rule for " TEST_DIR
			       "/" SUBDIR_NAME_FORMAT ": %s",
			       i, strerror(errno));
		}
	}

	self->ruleset_fd = ruleset_fd;
}

static int child_restrict_self(int ruleset_fd)
{
	int err, n;
	char errstr[512];

	err = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (err != 0) {
		err = errno;
		n = snprintf(errstr, sizeof(errstr),
			     "child process prctl(PR_SET_NO_NEW_PRIVS): %s\n",
			     strerror(err));
		write(STDERR_FILENO, errstr, n + 1);
		return err;
	}

	err = landlock_restrict_self(ruleset_fd, 0);
	if (err != 0) {
		err = errno;
		n = snprintf(errstr, sizeof(errstr),
			     "child process landlock_restrict_self: %s\n",
			     strerror(err));
		write(STDERR_FILENO, errstr, n + 1);
		return err;
	}

	return 0;
}

static int child_process(struct shared_region *shr, int ruleset_fd)
{
	int err;

	err = child_restrict_self(ruleset_fd);
	if (err != 0) {
		return err;
	}

	while (!READ_ONCE(shr->stop)) {
		int dfd = READ_ONCE(shr->test_file_at_dfd);
		err = openat(dfd, TEST_FILE_NAME, O_RDONLY);
		char errstr[512];
		int n;
		if (err < 0) {
			if (errno == ENOENT || errno == EBADF) {
				continue;
			} else {
				err = errno;
				n = snprintf(errstr, sizeof(errstr),
					     "openat(%d, " TEST_FILE_NAME
					     "): %s\n",
					     dfd, strerror(err));
				write(STDERR_FILENO, errstr, n + 1);
				return err;
			}
		}
		close(err);
	}
	return 0;
}

static void do_test(struct __test_metadata *const _metadata,
		    struct _test_data_layout *const self)
{
	struct shared_region *shr;
	int child_pid, status, err;

	create_test_file(_metadata, self);

	ASSERT_LE(sizeof(struct shared_region), 4096);
	shr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(shr, MAP_FAILED)
	{
		TH_LOG("Failed to create shared memory region with mmap: %s",
		       strerror(errno));
		return;
	}

	WRITE_ONCE(shr->test_file_at_dfd,
		   test_file_dfd(_metadata, self, self->test_file_at));
	WRITE_ONCE(shr->stop, false);

	child_pid = fork();
	if (child_pid == 0) {
		_exit(child_process(shr, self->ruleset_fd));
		return;
	}

	ASSERT_NE(-1, child_pid)
	{
		TH_LOG("Failed to fork child process: %s", strerror(errno));
	}

	for (int i = 1; i < NUM_SUBDIRS; i++) {
		move_test_file_and_rmdir(_metadata, self, i, shr);
	}

	WRITE_ONCE(shr->stop, true);
	err = waitpid(child_pid, &status, 0);
	ASSERT_NE(-1, err)
	{
		TH_LOG("Failed to wait for child process: %s", strerror(errno));
	}
	ASSERT_EQ(child_pid, err);
	status = WEXITSTATUS(status);
	ASSERT_EQ(0, status)
	{
		TH_LOG("Child process terminated with exit code %d", status);
	}

	cleanup_test_file(_metadata, self);
}

FIXTURE_SETUP(layout)
{
	create_test_dir(_metadata, self);
	self->test_file_at = -1;
};

FIXTURE_TEARDOWN(layout)
{
	cleanup_subdirs(_metadata, self);
	cleanup_test_dir(_metadata, self);
}

TEST_F_TIMEOUT(layout, pathwalk_test_depth1, TEST_TIME)
{
	self->has_subsubdir = false;
	create_subdirs(_metadata, self);
	create_ruleset(_metadata, self);
	do_test(_metadata, self);
	cleanup_subdirs(_metadata, self);
}

TEST_F_TIMEOUT(layout, pathwalk_test_depth2, TEST_TIME)
{
	self->has_subsubdir = true;
	create_subdirs(_metadata, self);
	create_ruleset(_metadata, self);
	do_test(_metadata, self);
	cleanup_subdirs(_metadata, self);
}

TEST_HARNESS_MAIN
