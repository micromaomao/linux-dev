// SPDX-License-Identifier: BSD-3-Clause
/*
 * File-based Landlock sandbox manager with supervisor support.
 *
 * This sandboxer reads rules from a configuration file and applies them
 * as supervisor rules. The sandboxed process runs in a forked child,
 * and the parent monitors the config file for changes and reloads rules
 * when the file is modified.
 *
 * Copyright © 2026 Tingmao Wang <m@maowtm.org>
 */

#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/landlock.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdbool.h>

#if defined(__GLIBC__)
#include <linux/prctl.h>
#endif

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#ifndef LANDLOCK_CREATE_RULESET_SUPERVISOR
#define LANDLOCK_CREATE_RULESET_SUPERVISOR (1U << 2)
#endif

#ifndef LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR
#define LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR (1U << 1)
#endif

#ifndef LANDLOCK_ADD_RULE_INTERSECT
#define LANDLOCK_ADD_RULE_INTERSECT (1U << 2)
#endif

#ifndef LANDLOCK_IOC_MAGIC
#define LANDLOCK_IOC_MAGIC 'L'
#endif

#ifndef LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET
#define LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET _IO(LANDLOCK_IOC_MAGIC, 0x20)
#endif

/* clang-format off */

#define ACCESS_FS_ROUGHLY_READ ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

/* clang-format on */

#define MAX_LINE_LENGTH 4096

/**
 * struct rule_entry - Tracks a single rule in the ruleset.
 * @access: Landlock fs access mask currently applied.
 * @pathfd: An O_PATH fd that we keep open until it is removed from the
 *          ruleset in a future config load, after which we set it to -1.
 * @should_keep: Marker to determine which rules are removed during reload.
 * @pathname: Pathname as originally given in the config file (dynamically
 *            allocated).
 */
struct rule_entry {
	__u64 access;
	int pathfd;
	bool should_keep;
	char *pathname;
};

/**
 * struct tracked_ruleset - Tracks all rules in a supervisor ruleset.
 * @len: Number of valid entries in the array.
 * @cap: Current capacity of the entries array.
 * @entries: Dynamically allocated array of rule entries.
 */
struct tracked_ruleset {
	size_t len;
	size_t cap;
	struct rule_entry *entries;
};

/**
 * tracked_ruleset_init() - Initialize a tracked ruleset.
 * @rs: Pointer to the tracked ruleset to initialize.
 */
static void tracked_ruleset_init(struct tracked_ruleset *rs)
{
	rs->len = 0;
	rs->cap = 0;
	rs->entries = NULL;
}

/**
 * tracked_ruleset_find() - Find a rule by pathname.
 * @rs: Pointer to the tracked ruleset.
 * @pathname: The pathname to search for.
 *
 * Return: Pointer to the rule_entry if found, or NULL if not found.
 */
static struct rule_entry *tracked_ruleset_find(struct tracked_ruleset *rs,
					       const char *pathname)
{
	size_t i;

	for (i = 0; i < rs->len; i++) {
		if (rs->entries[i].pathname &&
		    strcmp(rs->entries[i].pathname, pathname) == 0)
			return &rs->entries[i];
	}
	return NULL;
}

/**
 * tracked_ruleset_insert() - Insert a new rule into the tracked ruleset.
 * @rs: Pointer to the tracked ruleset.
 * @entry: The rule entry to insert.
 *
 * Expands the array in powers of 2 if needed.
 *
 * Return: 0 on success, -1 on error.
 */
static int tracked_ruleset_insert(struct tracked_ruleset *rs,
				  const struct rule_entry *entry)
{
	if (rs->len >= rs->cap) {
		size_t new_cap = rs->cap ? rs->cap * 2 : 8;
		struct rule_entry *new_entries;

		new_entries = realloc(rs->entries,
				      new_cap * sizeof(*new_entries));
		if (!new_entries) {
			fprintf(stderr, "Out of memory\n");
			return -1;
		}
		rs->entries = new_entries;
		rs->cap = new_cap;
	}
	rs->entries[rs->len++] = *entry;
	return 0;
}

/**
 * tracked_ruleset_cleanup() - Free all resources in a tracked ruleset.
 * @rs: Pointer to the tracked ruleset to clean up.
 *
 * Closes all path file descriptors and frees all allocated memory.
 */
static void tracked_ruleset_cleanup(struct tracked_ruleset *rs)
{
	size_t i;

	for (i = 0; i < rs->len; i++) {
		if (rs->entries[i].pathfd >= 0)
			close(rs->entries[i].pathfd);
		free(rs->entries[i].pathname);
	}
	free(rs->entries);
	rs->entries = NULL;
	rs->len = 0;
	rs->cap = 0;
}

/**
 * access_to_string() - Convert access mask to human-readable string.
 * @access: The access mask to convert.
 * @buf: Buffer to write the string to.
 * @buflen: Size of the buffer.
 *
 * Return: Pointer to buf.
 */
static const char *access_to_string(__u64 access, char *buf, size_t buflen)
{
	bool has_read = (access & ACCESS_FS_ROUGHLY_READ) != 0;
	bool has_write = (access & ACCESS_FS_ROUGHLY_WRITE) != 0;

	if (has_read && has_write)
		snprintf(buf, buflen, "read-write");
	else if (has_read)
		snprintf(buf, buflen, "read");
	else if (has_write)
		snprintf(buf, buflen, "write");
	else
		snprintf(buf, buflen, "no");
	return buf;
}

static volatile sig_atomic_t child_exited = 0;

static void sigchld_handler(int sig)
{
	(void)sig;
	child_exited = 1;
}

/**
 * parse_access_type() - Parse access type from config.
 * @access_type: String like "ro" or "rw".
 * @access: Output access mask.
 *
 * Return: 0 on success, -1 on error.
 */
static int parse_access_type(const char *access_type, __u64 *access)
{
	if (strcmp(access_type, "ro") == 0) {
		*access = ACCESS_FS_ROUGHLY_READ;
		return 0;
	} else if (strcmp(access_type, "rw") == 0) {
		*access = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
		return 0;
	}
	return -1;
}

/**
 * load_and_apply_config() - Load config file and apply rules to supervisor.
 * @config_fd: Open file descriptor to config file (consumed).
 * @supervisor_fd: Supervisor ruleset fd.
 * @tracked: Tracked ruleset state.
 * @handled_access_fs: Handled access mask.
 *
 * This function implements incremental rule updates:
 * 1. Mark all existing rules as should_keep=false
 * 2. For each line in config, find or create rule
 * 3. Remove rules that are no longer in config
 *
 * Return: 0 on success, -1 on error.
 */
static int load_and_apply_config(int config_fd, int supervisor_fd,
				 struct tracked_ruleset *tracked,
				 __u64 handled_access_fs)
{
	FILE *f;
	char line[MAX_LINE_LENGTH];
	size_t i, write_idx;
	char access_buf[32];

	f = fdopen(config_fd, "r");
	if (!f) {
		perror("Failed to open config file");
		close(config_fd);
		return -1;
	}

	/* Step 1: Mark all existing rules as not to keep */
	for (i = 0; i < tracked->len; i++)
		tracked->entries[i].should_keep = false;

	/* Step 2: Process each line in config */
	while (fgets(line, sizeof(line), f)) {
		char access_type[16];
		char path[PATH_MAX];
		__u64 new_access;
		int n;
		struct stat statbuf;
		struct rule_entry *entry;

		/* Skip empty lines and comments */
		if (line[0] == '\0' || line[0] == '#' || line[0] == '\n')
			continue;

		n = sscanf(line, "%15s %4095s", access_type, path);
		if (n != 2) {
			fprintf(stderr, "Invalid config line: %s", line);
			continue;
		}

		if (parse_access_type(access_type, &new_access) < 0) {
			fprintf(stderr, "Unknown access type: %s\n",
				access_type);
			continue;
		}

		new_access &= handled_access_fs;

		entry = tracked_ruleset_find(tracked, path);
		if (entry != NULL) {
			/* Existing rule - mark to keep and update if needed */
			entry->should_keep = true;

			if (entry->access != new_access) {
				struct landlock_path_beneath_attr path_beneath = {
					.parent_fd = entry->pathfd,
					.allowed_access = new_access,
				};

				if ((new_access | entry->access) !=
				    entry->access) {
					/* Adding access - use normal add */
					if (landlock_add_rule(
						    supervisor_fd,
						    LANDLOCK_RULE_PATH_BENEATH,
						    &path_beneath, 0) < 0) {
						fprintf(stderr,
							"Error expanding access on %s: landlock_add_rule failed: %s\n",
							path, strerror(errno));
					} else {
						fprintf(stderr,
							"supervisor: Added %s access for %s\n",
							access_to_string(
								new_access &
									~entry->access,
								access_buf,
								sizeof(access_buf)),
							path);
					}
				}
				if ((new_access | entry->access) !=
				    new_access) {
					/* Removing access - use intersect */
					if (landlock_add_rule(
						    supervisor_fd,
						    LANDLOCK_RULE_PATH_BENEATH,
						    &path_beneath,
						    LANDLOCK_ADD_RULE_INTERSECT) <
					    0) {
						fprintf(stderr,
							"Error removing access on %s: landlock_add_rule failed: %s\n",
							path, strerror(errno));
					} else {
						fprintf(stderr,
							"supervisor: Removed %s access for %s\n",
							access_to_string(
								entry->access &
									~new_access,
								access_buf,
								sizeof(access_buf)),
							path);
					}
				}
				entry->access = new_access;
			}
		} else {
			/* New rule - add it */
			struct rule_entry new_entry;
			struct landlock_path_beneath_attr path_beneath;
			int pathfd;

			pathfd = open(path, O_PATH | O_CLOEXEC);
			if (pathfd < 0) {
				fprintf(stderr,
					"Warning: Failed to open \"%s\": %s\n",
					path, strerror(errno));
				continue;
			}

			if (fstat(pathfd, &statbuf)) {
				fprintf(stderr,
					"Warning: Failed to stat \"%s\": %s\n",
					path, strerror(errno));
				close(pathfd);
				continue;
			}

			/* Restrict file access rights for non-directories */
			if (!S_ISDIR(statbuf.st_mode))
				new_access &= ACCESS_FILE;

			new_entry.access = new_access;
			new_entry.pathfd = pathfd;
			new_entry.should_keep = true;
			new_entry.pathname = strdup(path);
			if (!new_entry.pathname) {
				fprintf(stderr, "Out of memory\n");
				close(pathfd);
				continue;
			}

			path_beneath.parent_fd = pathfd;
			path_beneath.allowed_access = new_access;

			if (landlock_add_rule(supervisor_fd,
					      LANDLOCK_RULE_PATH_BENEATH,
					      &path_beneath, 0) < 0) {
				fprintf(stderr,
					"Error adding access on %s: landlock_add_rule failed: %s\n",
					path, strerror(errno));
			} else {
				fprintf(stderr,
					"supervisor: Added %s access for %s\n",
					access_to_string(new_access, access_buf,
							 sizeof(access_buf)),
					path);
			}

			tracked_ruleset_insert(tracked, &new_entry);
		}
	}

	fclose(f);

	/* Step 3: Remove rules that are no longer in config */
	write_idx = 0;
	for (i = 0; i < tracked->len; i++) {
		struct rule_entry *entry = &tracked->entries[i];

		if (!entry->should_keep) {
			/* Remove this rule by intersecting with 0 */
			struct landlock_path_beneath_attr path_beneath = {
				.parent_fd = entry->pathfd,
				.allowed_access = 0,
			};

			if (landlock_add_rule(supervisor_fd,
					      LANDLOCK_RULE_PATH_BENEATH,
					      &path_beneath,
					      LANDLOCK_ADD_RULE_INTERSECT) ==
			    0) {
				fprintf(stderr,
					"supervisor: Removed all access for %s\n",
					entry->pathname);
			}

			/* Clean up */
			if (entry->pathfd >= 0)
				close(entry->pathfd);
			free(entry->pathname);
		} else {
			/* Keep this rule - compact the array */
			if (write_idx != i)
				tracked->entries[write_idx] = *entry;
			write_idx++;
		}
	}
	tracked->len = write_idx;

	/* Commit the rules */
	if (landlock_add_rule(supervisor_fd, 0, NULL,
			      LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR)) {
		perror("Failed to commit supervisor rules");
		return -1;
	}

	fprintf(stderr, "supervisor: Config reloaded, %zu rules active\n",
		tracked->len);
	return 0;
}

/*
 * Watch for config file changes using inotify.
 */
static int wait_config_file(const char *config_path, int inotify_fd, bool init)
{
	int watchd, fd;

	while (true) {
		watchd = inotify_add_watch(inotify_fd, config_path,
					   IN_CLOSE_WRITE | IN_MODIFY |
						   IN_MOVE_SELF |
						   IN_DELETE_SELF | IN_ONESHOT);
		if (watchd < 0 && !init && errno == ENOENT) {
			fprintf(stderr,
				"Waiting for config file \"%s\" to appear...\n",
				config_path);
			usleep(100000);
			continue;
		} else if (watchd < 0) {
			perror("inotify_add_watch");
			return -1;
		}

		fd = open(config_path, O_RDONLY | O_CLOEXEC);

		if (fd < 0 && !init && errno == ENOENT) {
			inotify_rm_watch(inotify_fd, watchd);
			fprintf(stderr,
				"Waiting for config file \"%s\" to appear...\n",
				config_path);
			usleep(100000);
			continue;
		} else if (fd < 0) {
			inotify_rm_watch(inotify_fd, watchd);
			perror("Failed to open config file for watching");
			return -1;
		} else {
			return fd;
		}
	}
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <config_file> <command> [args...]\n"
		"\n"
		"Run <command> in a Landlock sandbox with rules from <config_file>.\n"
		"The sandboxer monitors the config file and reloads rules on changes.\n"
		"\n"
		"Config file format (one rule per line):\n"
		"  <access_type> <path>\n"
		"\n"
		"Where access_type is one of:\n"
		"  ro  - read-only access\n"
		"  rw  - read-write access\n"
		"\n"
		"Lines starting with # are comments.\n"
		"\n"
		"Example config file:\n"
		"  # Allow read-only access to system paths\n"
		"  ro /usr\n"
		"  ro /lib\n"
		"  ro /etc\n"
		"  # Allow read-write access to tmp\n"
		"  rw /tmp\n",
		prog);
}

/**
 * wait_for_child() - Wait for child process to exit and return exit status.
 * @child: PID of the child process.
 *
 * Waits for the child process, prints a message indicating how it exited,
 * and returns an appropriate exit code.
 *
 * Return: 0 on normal exit, child's exit status otherwise.
 */
static int wait_for_child(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status)) {
		fprintf(stderr, "Supervisor: Child exited with status %d\n",
			WEXITSTATUS(status));
		return WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "Supervisor: Child killed by signal %d\n",
			WTERMSIG(status));
		return 128 + WTERMSIG(status);
	}

	return 0;
}

#define LANDLOCK_ABI_LAST 10

int main(int argc, char *const argv[], char *const *const envp)
{
	const char *config_path;
	const char *cmd_path;
	char *const *cmd_argv;
	int supervisor_fd, supervisee_fd;
	int inotify_fd;
	int abi;
	pid_t child;
	int config_fd;
	struct tracked_ruleset tracked;

	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
	};

	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	config_path = argv[1];
	cmd_path = argv[2];
	cmd_argv = argv + 2;

	tracked_ruleset_init(&tracked);

	/* Check Landlock ABI version */
	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		const int err = errno;

		perror("Failed to check Landlock compatibility");
		switch (err) {
		case ENOSYS:
			fprintf(stderr,
				"Hint: Landlock is not supported by the current kernel.\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr,
				"Hint: Landlock is currently disabled.\n");
			break;
		}
		return 1;
	}

	if (abi < 10) {
		fprintf(stderr,
			"Error: Supervisor support requires ABI version 10 or later.\n");
		fprintf(stderr, "Current ABI version: %d\n", abi);
		return 1;
	}

	/* Apply ABI restrictions */
	switch (abi) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
		fprintf(stderr,
			"Error: Supervisor support requires ABI version 10 or later.\n");
		fprintf(stderr, "Current ABI version: %d\n", abi);
		return 1;
	case LANDLOCK_ABI_LAST:
		break;
	default:
		fprintf(stderr,
			"Hint: Update this sandboxer to leverage features "
			"in ABI version %d (instead of %d).\n",
			abi, LANDLOCK_ABI_LAST);
	}

	/* Create supervisor ruleset */
	supervisor_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					LANDLOCK_CREATE_RULESET_SUPERVISOR);
	if (supervisor_fd < 0) {
		perror("Failed to create supervisor ruleset");
		return 1;
	}

	/* Get supervisee ruleset */
	supervisee_fd =
		ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	if (supervisee_fd < 0) {
		perror("Failed to get supervisee ruleset");
		close(supervisor_fd);
		return 1;
	}

	inotify_fd = inotify_init1(IN_CLOEXEC);
	if (inotify_fd < 0) {
		perror("inotify_init1");
		close(supervisor_fd);
		close(supervisee_fd);
		return 1;
	}

	config_fd = wait_config_file(config_path, inotify_fd, true);
	if (config_fd < 0) {
		close(supervisor_fd);
		close(supervisee_fd);
		return 1;
	}

	/* Load and apply initial rules */
	if (load_and_apply_config(config_fd, supervisor_fd, &tracked,
				  ruleset_attr.handled_access_fs) < 0) {
		close(supervisor_fd);
		close(supervisee_fd);
		return 1;
	}

	/* Set up signal handler for child exit (no SA_RESTART so
	 * SIGCHLD interrupts blocking read/poll calls). */
	{
		struct sigaction sa = {
			.sa_handler = sigchld_handler,
			.sa_flags = 0, /* no SA_RESTART */
		};
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGCHLD, &sa, NULL) < 0) {
			perror("sigaction");
			close(supervisor_fd);
			close(supervisee_fd);
			close(inotify_fd);
			return 1;
		}
	}

	/* Fork the child process */
	child = fork();
	if (child < 0) {
		perror("fork");
		close(supervisor_fd);
		close(supervisee_fd);
		close(inotify_fd);
		return 1;
	}

	if (child == 0) {
		/* Child process */
		close(supervisor_fd);
		close(inotify_fd);

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			perror("Failed to restrict privileges");
			_exit(1);
		}

		if (landlock_restrict_self(supervisee_fd, 0)) {
			perror("Failed to enforce ruleset");
			_exit(1);
		}

		close(supervisee_fd);

		fprintf(stderr, "Executing the sandboxed command...\n");
		execvpe(cmd_path, cmd_argv, envp);
		fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
			strerror(errno));
		_exit(1);
	}

	/* Parent process - close supervisee fd, keep supervisor */
	close(supervisee_fd);

	fprintf(stderr, "Supervisor: Child process started (PID %d)\n", child);
	fprintf(stderr, "Supervisor: Monitoring config file for changes...\n");

	/* Monitor for file changes and child exit */
	while (!child_exited) {
		char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
		ssize_t len;

		if (child_exited)
			break;
		/* Drain inotify events */
		len = read(inotify_fd, buf, sizeof(buf));
		if (child_exited)
			break;
		if (len < 0 && errno != EAGAIN) {
			perror("read inotify");
			break;
		}

		fprintf(stderr,
			"\nSupervisor: Config file changed, reloading rules...\n");

		config_fd = wait_config_file(config_path, inotify_fd, false);
		if (config_fd < 0) {
			break;
		}

		/* Load and apply new rules */
		if (load_and_apply_config(config_fd, supervisor_fd, &tracked,
					  ruleset_attr.handled_access_fs) < 0) {
			break;
		}
	}

	/* Clean up tracked ruleset */
	tracked_ruleset_cleanup(&tracked);

	/* Clean up */
	close(inotify_fd);
	close(supervisor_fd);

	/* Wait for child to exit */
	return wait_for_child(child);
}
