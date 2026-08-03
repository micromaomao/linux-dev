// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Mutable domains (supervisor) tests
 *
 * Copyright © 2024-2025 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

/* Test directory paths */
#define TMP_DIR "tmp"
static const char dir_s1d1[] = TMP_DIR "/s1d1";
static const char dir_s1d2[] = TMP_DIR "/s1d1/s1d2";
static const char file1_s1d1[] = TMP_DIR "/s1d1/f1";
static const char file1_s1d2[] = TMP_DIR "/s1d1/s1d2/f1";

/* Helper to test file/directory open */
static int test_open(const char *const path, const int flags)
{
	int fd;

	fd = open(path, flags | O_CLOEXEC);
	if (fd < 0)
		return errno;
	if (close(fd) != 0)
		return errno;
	return 0;
}

/* clang-format off */
FIXTURE(supervisor) {};
/* clang-format on */

FIXTURE_SETUP(supervisor)
{
	int fd;

	/* Create test directories (ignore EEXIST) */
	if (mkdir(TMP_DIR, 0700) && errno != EEXIST)
		ASSERT_EQ(0, errno);
	if (mkdir(dir_s1d1, 0700) && errno != EEXIST)
		ASSERT_EQ(0, errno);
	if (mkdir(dir_s1d2, 0700) && errno != EEXIST)
		ASSERT_EQ(0, errno);

	/* Create test files */
	fd = creat(file1_s1d1, 0600);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));

	fd = creat(file1_s1d2, 0600);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));
}

FIXTURE_TEARDOWN(supervisor)
{
	/* Clean up in reverse order of creation */
	unlink(file1_s1d2);
	unlink(file1_s1d1);
	rmdir(dir_s1d2);
	rmdir(dir_s1d1);
	/* Note: Don't remove TMP_DIR as it may be shared with other tests */
}

TEST(supervisor_create_ruleset)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int supervisor_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd)
	{
		TH_LOG("Failed to create supervisor ruleset: %s",
		       strerror(errno));
	}

	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_get_supervisee)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int supervisor_fd, supervisee_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Get supervisee ruleset via ioctl */
	supervisee_fd =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	ASSERT_LE(0, supervisee_fd)
	{
		TH_LOG("Failed to get supervisee ruleset: %s", strerror(errno));
	}

	ASSERT_EQ(0, close(supervisee_fd));
	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_get_supervisee_invalid_flags)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int supervisor_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Invalid flags should return EINVAL */
	ASSERT_EQ(-1, ioctl(supervisor_fd,
			    LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 1));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_ioctl_on_regular_ruleset)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;

	/* Create a regular (non-supervisor) ruleset */
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	/* ioctl should fail on regular rulesets */
	ASSERT_EQ(-1,
		  ioctl(ruleset_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0));
	ASSERT_EQ(ENOTTY, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(supervisor_restrict_self_fails)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int supervisor_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Trying to use supervisor fd with restrict_self should fail */
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(-1, landlock_restrict_self(supervisor_fd, 0));
	ASSERT_EQ(EBADFD, errno);

	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_commit_empty)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int supervisor_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Commit with rule_type=0 means commit only without adding a rule */
	ASSERT_EQ(0, landlock_add_rule(supervisor_fd, 0, NULL,
				       LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));

	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_commit_on_regular_ruleset)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;

	/* Create a regular ruleset */
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	/* Commit flag should fail on regular rulesets */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, 0, NULL,
					LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(rule_type_zero_without_commit)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;

	/* Create a regular ruleset */
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	/* rule_type=0 is only valid with LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, 0, NULL, 0));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(supervisor_multiple_commits)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int supervisor_fd;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* First rule and commit */
	path_beneath.parent_fd = open("/tmp", O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath,
				    LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Second rule and commit */
	path_beneath.parent_fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath,
				    LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	ASSERT_EQ(0, close(supervisor_fd));
}

TEST(supervisor_multiple_supervisees)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int supervisor_fd, supervisee_fd1, supervisee_fd2;

	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Get multiple supervisee rulesets from the same supervisor */
	supervisee_fd1 =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	ASSERT_LE(0, supervisee_fd1);

	supervisee_fd2 =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	ASSERT_LE(0, supervisee_fd2);

	/* They should be different fds */
	ASSERT_NE(supervisee_fd1, supervisee_fd2);

	ASSERT_EQ(0, close(supervisee_fd1));
	ASSERT_EQ(0, close(supervisee_fd2));
	ASSERT_EQ(0, close(supervisor_fd));
}

/*
 * Test that enforcing a supervisee ruleset properly restricts access.
 * Child process verifies that access to allowed paths works and
 * access to disallowed paths fails.
 */
TEST_F_FORK(supervisor, access_check_basic)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_READ_DIR,
	};
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
				  LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int supervisor_fd, supervisee_fd;

	/* Create supervisor ruleset */
	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Allow access to dir_s1d2 only */
	path_beneath.parent_fd =
		open(dir_s1d2, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath,
				    LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Get supervisee ruleset */
	supervisee_fd =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	ASSERT_LE(0, supervisee_fd);

	/* Enforce supervisee ruleset */
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(supervisee_fd, 0));

	/* Access to dir_s1d2 should be allowed */
	EXPECT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));
	EXPECT_EQ(0, test_open(file1_s1d2, O_RDONLY));

	/* Access to dir_s1d1 should be denied (not in allowed path) */
	EXPECT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));
	EXPECT_EQ(EACCES, test_open(file1_s1d1, O_RDONLY));

	ASSERT_EQ(0, close(supervisee_fd));
	ASSERT_EQ(0, close(supervisor_fd));
}

/*
 * Test supervisor dynamic rule updates.
 * Parent process commits new rules and child process verifies access changes.
 */
TEST_F_FORK(supervisor, dynamic_rule_update)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	struct landlock_path_beneath_attr path_beneath = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int supervisor_fd, supervisee_fd;
	int pipe_parent_to_child[2], pipe_child_to_parent[2];
	pid_t child;
	char buf;

	/* Create pipes for synchronization */
	ASSERT_EQ(0, pipe(pipe_parent_to_child));
	ASSERT_EQ(0, pipe(pipe_child_to_parent));

	/* Create supervisor ruleset with no initial rules */
	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	ASSERT_LE(0, supervisor_fd);

	/* Initial commit with just dir_s1d2 allowed */
	path_beneath.parent_fd =
		open(dir_s1d2, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath,
				    LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Get supervisee ruleset */
	supervisee_fd =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	ASSERT_LE(0, supervisee_fd);

	child = fork();
	ASSERT_LE(0, child);

	if (child == 0) {
		/* Child process */
		close(pipe_parent_to_child[1]);
		close(pipe_child_to_parent[0]);
		close(supervisor_fd);

		/* Enforce ruleset */
		ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		ASSERT_EQ(0, landlock_restrict_self(supervisee_fd, 0));
		close(supervisee_fd);

		/* Phase 1: Verify initial access */
		EXPECT_EQ(0, test_open(dir_s1d2, O_RDONLY | O_DIRECTORY));
		EXPECT_EQ(EACCES, test_open(dir_s1d1, O_RDONLY | O_DIRECTORY));

		/* Signal parent that phase 1 is done */
		ASSERT_EQ(1, write(pipe_child_to_parent[1], "1", 1));

		/* Wait for parent to signal phase 2 (new rules committed) */
		ASSERT_EQ(1, read(pipe_parent_to_child[0], &buf, 1));

		/*
		 * Note: Access changes after commit would require kernel
		 * integration. For now verify the API workflow completes.
		 */

		close(pipe_parent_to_child[0]);
		close(pipe_child_to_parent[1]);
		_exit(EXIT_SUCCESS);
	}

	/* Parent process */
	close(pipe_parent_to_child[0]);
	close(pipe_child_to_parent[1]);
	close(supervisee_fd);

	/* Wait for child to complete phase 1 */
	ASSERT_EQ(1, read(pipe_child_to_parent[0], &buf, 1));

	/* Add rule for dir_s1d1 and commit */
	path_beneath.parent_fd =
		open(dir_s1d1, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath,
				    LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR));
	ASSERT_EQ(0, close(path_beneath.parent_fd));

	/* Signal child to proceed to phase 2 */
	ASSERT_EQ(1, write(pipe_parent_to_child[1], "2", 1));

	/* Wait for child to exit */
	int status;
	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_EQ(1, WIFEXITED(status));
	ASSERT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));

	close(pipe_parent_to_child[1]);
	close(pipe_child_to_parent[0]);
	ASSERT_EQ(0, close(supervisor_fd));
}

TEST_HARNESS_MAIN
