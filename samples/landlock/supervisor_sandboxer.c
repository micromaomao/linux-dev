// SPDX-License-Identifier: BSD-3-Clause
/*
 * File-based Landlock sandbox manager with supervisor support.
 *
 * This sandboxer reads rules from a configuration file and applies them
 * as supervisor rules. The sandboxed process runs in a forked child,
 * and the parent monitors the config file for changes and reloads rules
 * when the file is modified.
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
#define MAX_RULES 1024

struct rule_entry {
	char path[PATH_MAX];
	__u64 access;
};

static struct rule_entry rules[MAX_RULES];
static int num_rules = 0;

static volatile sig_atomic_t child_exited = 0;

static void sigchld_handler(int sig)
{
	(void)sig;
	child_exited = 1;
}

/*
 * Parse a line from the config file.
 * Format: <access_type> <path>
 * Where access_type is one of: ro, rw
 */
static int parse_config_line(const char *line, struct rule_entry *entry)
{
	char access_type[16];
	char path[PATH_MAX];
	int n;

	/* Skip empty lines and comments */
	if (line[0] == '\0' || line[0] == '#' || line[0] == '\n')
		return -1;

	n = sscanf(line, "%15s %4095s", access_type, path);
	if (n != 2) {
		fprintf(stderr, "Invalid config line: %s", line);
		return -1;
	}

	/* Use snprintf for safe string copying with guaranteed null-termination */
	if (snprintf(entry->path, sizeof(entry->path), "%s", path) >=
	    (int)sizeof(entry->path)) {
		fprintf(stderr, "Path too long: %s\n", path);
		return -1;
	}

	if (strcmp(access_type, "ro") == 0) {
		entry->access = ACCESS_FS_ROUGHLY_READ;
	} else if (strcmp(access_type, "rw") == 0) {
		entry->access = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;
	} else {
		fprintf(stderr, "Unknown access type: %s\n", access_type);
		return -1;
	}

	return 0;
}

/*
 * Load rules from configuration file.
 */
static int load_rules_from_file(const char *config_path)
{
	FILE *f;
	char line[MAX_LINE_LENGTH];

	f = fopen(config_path, "r");
	if (!f) {
		perror("Failed to open config file");
		return -1;
	}

	num_rules = 0;

	while (fgets(line, sizeof(line), f) && num_rules < MAX_RULES) {
		struct rule_entry entry;

		if (parse_config_line(line, &entry) == 0) {
			rules[num_rules++] = entry;
		}
	}

	fclose(f);

	fprintf(stderr, "Loaded %d rules from %s\n", num_rules, config_path);
	return 0;
}

/*
 * Apply loaded rules to a supervisor ruleset and commit.
 */
static int apply_rules_to_supervisor(int supervisor_fd, __u64 access_fs_rw)
{
	int i;

	for (i = 0; i < num_rules; i++) {
		struct stat statbuf;
		struct landlock_path_beneath_attr path_beneath = {
			.allowed_access = rules[i].access & access_fs_rw,
		};

		path_beneath.parent_fd = open(rules[i].path, O_PATH | O_CLOEXEC);
		if (path_beneath.parent_fd < 0) {
			fprintf(stderr, "Warning: Failed to open \"%s\": %s\n",
				rules[i].path, strerror(errno));
			continue;
		}

		if (fstat(path_beneath.parent_fd, &statbuf)) {
			fprintf(stderr, "Warning: Failed to stat \"%s\": %s\n",
				rules[i].path, strerror(errno));
			close(path_beneath.parent_fd);
			continue;
		}

		/* Restrict file access rights for non-directories */
		if (!S_ISDIR(statbuf.st_mode))
			path_beneath.allowed_access &= ACCESS_FILE;

		if (landlock_add_rule(supervisor_fd, LANDLOCK_RULE_PATH_BENEATH,
				      &path_beneath, 0)) {
			fprintf(stderr,
				"Warning: Failed to add rule for \"%s\": %s\n",
				rules[i].path, strerror(errno));
		}

		close(path_beneath.parent_fd);
	}

	/* Commit the rules (rule_type = 0 means commit only) */
	if (landlock_add_rule(supervisor_fd, 0, NULL,
			      LANDLOCK_ADD_RULE_COMMIT_SUPERVISOR)) {
		perror("Failed to commit supervisor rules");
		return -1;
	}

	return 0;
}

/*
 * Watch for config file changes using inotify.
 */
static int setup_file_watch(const char *config_path)
{
	int inotify_fd;
	int watch_fd;

	inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
	if (inotify_fd < 0) {
		perror("inotify_init1");
		return -1;
	}

	watch_fd = inotify_add_watch(inotify_fd, config_path,
				     IN_MODIFY | IN_CLOSE_WRITE);
	if (watch_fd < 0) {
		perror("inotify_add_watch");
		close(inotify_fd);
		return -1;
	}

	return inotify_fd;
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

#define LANDLOCK_ABI_LAST 9

int main(int argc, char *const argv[], char *const *const envp)
{
	const char *config_path;
	const char *cmd_path;
	char *const *cmd_argv;
	int supervisor_fd, supervisee_fd;
	int inotify_fd;
	int abi;
	pid_t child;
	__u64 access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;

	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = access_fs_rw,
	};

	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	config_path = argv[1];
	cmd_path = argv[2];
	cmd_argv = argv + 2;

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
			fprintf(stderr, "Hint: Landlock is currently disabled.\n");
			break;
		}
		return 1;
	}

	if (abi < 9) {
		fprintf(stderr, "Error: Supervisor support requires ABI version 9 or later.\n");
		fprintf(stderr, "Current ABI version: %d\n", abi);
		return 1;
	}

	/* Apply ABI restrictions */
	switch (abi) {
	case 1:
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
		__attribute__((fallthrough));
	case 2:
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
		__attribute__((fallthrough));
	case 3:
	case 4:
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
		__attribute__((fallthrough));
	case 5:
	case 6:
	case 7:
	case 8:
	case LANDLOCK_ABI_LAST:
		break;
	default:
		fprintf(stderr,
			"Hint: Update this sandboxer to leverage features "
			"in ABI version %d (instead of %d).\n",
			abi, LANDLOCK_ABI_LAST);
	}
	access_fs_rw &= ruleset_attr.handled_access_fs;

	/* Load initial rules */
	if (load_rules_from_file(config_path) < 0)
		return 1;

	/* Create supervisor ruleset */
	supervisor_fd = landlock_create_ruleset(&ruleset_attr,
						sizeof(ruleset_attr),
						LANDLOCK_CREATE_RULESET_SUPERVISOR);
	if (supervisor_fd < 0) {
		perror("Failed to create supervisor ruleset");
		return 1;
	}

	/* Apply initial rules */
	if (apply_rules_to_supervisor(supervisor_fd, access_fs_rw) < 0) {
		close(supervisor_fd);
		return 1;
	}

	/* Get supervisee ruleset */
	supervisee_fd = ioctl(supervisor_fd, LANDLOCK_IOCTL_GET_SUPERVISEE_RULESET, 0);
	if (supervisee_fd < 0) {
		perror("Failed to get supervisee ruleset");
		close(supervisor_fd);
		return 1;
	}

	/* Set up file watching */
	inotify_fd = setup_file_watch(config_path);
	if (inotify_fd < 0) {
		fprintf(stderr, "Warning: File watching not available\n");
	}

	/* Set up signal handler for child exit */
	signal(SIGCHLD, sigchld_handler);

	/* Fork the child process */
	child = fork();
	if (child < 0) {
		perror("fork");
		close(supervisor_fd);
		close(supervisee_fd);
		if (inotify_fd >= 0)
			close(inotify_fd);
		return 1;
	}

	if (child == 0) {
		/* Child process */
		close(supervisor_fd);
		if (inotify_fd >= 0)
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
		struct pollfd pfd = {
			.fd = inotify_fd,
			.events = POLLIN,
		};
		int ret;

		if (inotify_fd < 0) {
			/* No file watching, just wait for child */
			pause();
			break;
		}

		ret = poll(&pfd, 1, 1000);  /* 1 second timeout */
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		if (ret > 0 && (pfd.revents & POLLIN)) {
			char buf[4096];
			ssize_t len;

			/* Drain inotify events */
			len = read(inotify_fd, buf, sizeof(buf));
			if (len < 0 && errno != EAGAIN) {
				perror("read inotify");
				break;
			}

			fprintf(stderr, "\nSupervisor: Config file changed, reloading rules...\n");

			/* Reload rules */
			if (load_rules_from_file(config_path) < 0) {
				fprintf(stderr, "Warning: Failed to reload rules\n");
				continue;
			}

			/* Apply new rules to supervisor */
			if (apply_rules_to_supervisor(supervisor_fd, access_fs_rw) < 0) {
				fprintf(stderr, "Warning: Failed to apply rules\n");
				continue;
			}

			fprintf(stderr, "Supervisor: Rules reloaded and committed\n");
		}
	}

	/* Clean up */
	if (inotify_fd >= 0)
		close(inotify_fd);
	close(supervisor_fd);

	/* Wait for child to exit */
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
