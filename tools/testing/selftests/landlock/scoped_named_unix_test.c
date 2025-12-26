// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Named (filesystem path) UNIX socket
 *
 * Copyright © 2024 Tahera Fahimi <fahimitahera@gmail.com>
 * Copyright © 2025 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "scoped_common.h"

/* Number of pending connections queue to be hold. */
const short backlog = 10;

static void create_fs_domain(struct __test_metadata *const _metadata)
{
	int ruleset_fd;
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR,
	};

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	EXPECT_LE(0, ruleset_fd)
	{
		TH_LOG("Failed to create a ruleset: %s", strerror(errno));
	}
	EXPECT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	EXPECT_EQ(0, landlock_restrict_self(ruleset_fd, 0));
	EXPECT_EQ(0, close(ruleset_fd));
}

static void create_named_scoped_domain(struct __test_metadata *const _metadata)
{
	int ruleset_fd;
	const struct landlock_ruleset_attr ruleset_attr = {
		.scoped = LANDLOCK_SCOPE_NAMED_UNIX_SOCKET,
	};

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd)
	{
		TH_LOG("Failed to create a ruleset: %s", strerror(errno));
	}
	enforce_ruleset(_metadata, ruleset_fd);
	EXPECT_EQ(0, close(ruleset_fd));
}

#define NAMED_TMP_DIR TMP_DIR "/named_unix"

static const char stream_path[] = NAMED_TMP_DIR "/stream.sock";
static const char dgram_path[] = NAMED_TMP_DIR "/dgram.sock";

struct named_service_fixture {
	struct sockaddr_un unix_addr;
	socklen_t unix_addr_len;
};

static void set_named_address(struct named_service_fixture *const srv,
			      const char *const path)
{
	srv->unix_addr.sun_family = AF_UNIX;
	snprintf(srv->unix_addr.sun_path, sizeof(srv->unix_addr.sun_path),
		 "%s", path);
	srv->unix_addr_len = sizeof(srv->unix_addr);
}

FIXTURE(scoped_named_domains)
{
	struct named_service_fixture stream_address, dgram_address;
};

FIXTURE_VARIANT(scoped_named_domains)
{
	bool domain_both;
	bool domain_parent;
	bool domain_child;
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, without_domain) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = false,
	.domain_child = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, child_domain) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = false,
	.domain_child = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, parent_domain) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = true,
	.domain_child = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, sibling_domain) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = true,
	.domain_child = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, inherited_domain) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = false,
	.domain_child = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, nested_domain) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = false,
	.domain_child = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, nested_and_parent_domain) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = true,
	.domain_child = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_domains, forked_domains) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = true,
	.domain_child = true,
};

FIXTURE_SETUP(scoped_named_domains)
{
	drop_caps(_metadata);

	umask(0077);
	ASSERT_EQ(0, mkdir(NAMED_TMP_DIR, 0700));

	memset(&self->stream_address, 0, sizeof(self->stream_address));
	memset(&self->dgram_address, 0, sizeof(self->dgram_address));
	set_named_address(&self->stream_address, stream_path);
	set_named_address(&self->dgram_address, dgram_path);
}

FIXTURE_TEARDOWN(scoped_named_domains)
{
	unlink(stream_path);
	unlink(dgram_path);
	rmdir(NAMED_TMP_DIR);
}

/*
 * Test unix_stream_connect() and unix_may_send() for a child connecting to its
 * parent, when they have scoped domain or no domain.
 */
TEST_F(scoped_named_domains, connect_to_parent)
{
	pid_t child;
	bool can_connect_to_parent;
	int status;
	int pipe_parent[2];
	int stream_server, dgram_server;

	/*
	 * can_connect_to_parent is true if a child process can connect to its
	 * parent process. This depends on the child process not being isolated
	 * from the parent with a dedicated Landlock domain.
	 */
	can_connect_to_parent = !variant->domain_child;

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	if (variant->domain_both) {
		create_named_scoped_domain(_metadata);
		if (!__test_passed(_metadata))
			return;
	}

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int err;
		int stream_client, dgram_client;
		char buf_child;

		EXPECT_EQ(0, close(pipe_parent[1]));
		if (variant->domain_child)
			create_named_scoped_domain(_metadata);

		stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_client);
		dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_client);

		/* Waits for the server. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));

		err = connect(stream_client,
			      (struct sockaddr *)&self->stream_address.unix_addr,
			      self->stream_address.unix_addr_len);
		if (can_connect_to_parent) {
			EXPECT_EQ(0, err);
		} else {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		}
		EXPECT_EQ(0, close(stream_client));

		err = connect(dgram_client,
			      (struct sockaddr *)&self->dgram_address.unix_addr,
			      self->dgram_address.unix_addr_len);
		if (can_connect_to_parent) {
			EXPECT_EQ(0, err);
		} else {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		}
		EXPECT_EQ(0, close(dgram_client));
		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_parent[0]));
	if (variant->domain_parent)
		create_named_scoped_domain(_metadata);

	stream_server = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_server);
	dgram_server = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_server);
	ASSERT_EQ(0, bind(stream_server,
			  (struct sockaddr *)&self->stream_address.unix_addr,
			  self->stream_address.unix_addr_len));
	ASSERT_EQ(0, bind(dgram_server,
			  (struct sockaddr *)&self->dgram_address.unix_addr,
			  self->dgram_address.unix_addr_len));
	ASSERT_EQ(0, listen(stream_server, backlog));

	/* Signals to child that the parent is listening. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(stream_server));
	EXPECT_EQ(0, close(dgram_server));

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

/*
 * Test unix_stream_connect() and unix_may_send() for a parent connecting to
 * its child, when they have scoped domain or no domain.
 */
TEST_F(scoped_named_domains, connect_to_child)
{
	pid_t child;
	bool can_connect_to_child;
	int err_stream, err_dgram, errno_stream, errno_dgram, status;
	int pipe_child[2], pipe_parent[2];
	char buf;
	int stream_client, dgram_client;

	/*
	 * can_connect_to_child is true if a parent process can connect to its
	 * child process. The parent process is not isolated from the child
	 * with a dedicated Landlock domain.
	 */
	can_connect_to_child = !variant->domain_parent;

	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	if (variant->domain_both) {
		create_named_scoped_domain(_metadata);
		if (!__test_passed(_metadata))
			return;
	}

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int stream_server, dgram_server;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));
		if (variant->domain_child)
			create_named_scoped_domain(_metadata);

		/* Waits for the parent to be in a domain, if any. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));

		stream_server = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_server);
		dgram_server = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_server);
		ASSERT_EQ(0,
			  bind(stream_server,
			       (struct sockaddr *)&self->stream_address.unix_addr,
			       self->stream_address.unix_addr_len));
		ASSERT_EQ(0, bind(dgram_server,
				  (struct sockaddr *)&self->dgram_address.unix_addr,
				  self->dgram_address.unix_addr_len));
		ASSERT_EQ(0, listen(stream_server, backlog));

		/* Signals to the parent that child is listening. */
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		/* Waits to connect. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));
		EXPECT_EQ(0, close(stream_server));
		EXPECT_EQ(0, close(dgram_server));
		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_child[1]));
	EXPECT_EQ(0, close(pipe_parent[0]));

	if (variant->domain_parent)
		create_named_scoped_domain(_metadata);

	/* Signals that the parent is in a domain, if any. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_client);
	dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_client);

	/* Waits for the child to listen */
	ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
	err_stream = connect(stream_client,
			     (struct sockaddr *)&self->stream_address.unix_addr,
			     self->stream_address.unix_addr_len);
	errno_stream = errno;
	err_dgram = connect(dgram_client,
			    (struct sockaddr *)&self->dgram_address.unix_addr,
			    self->dgram_address.unix_addr_len);
	errno_dgram = errno;
	if (can_connect_to_child) {
		EXPECT_EQ(0, err_stream);
		EXPECT_EQ(0, err_dgram);
	} else {
		EXPECT_EQ(-1, err_stream);
		EXPECT_EQ(-1, err_dgram);
		EXPECT_EQ(EPERM, errno_stream);
		EXPECT_EQ(EPERM, errno_dgram);
	}
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	EXPECT_EQ(0, close(stream_client));
	EXPECT_EQ(0, close(dgram_client));

	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

enum named_sandbox_type {
	NAMED_NO_SANDBOX,
	NAMED_SCOPE_SANDBOX,
	NAMED_OTHER_SANDBOX,
};

FIXTURE(scoped_named_vs_unscoped)
{
	struct named_service_fixture parent_stream_address, parent_dgram_address,
		child_stream_address, child_dgram_address;
};

FIXTURE_VARIANT(scoped_named_vs_unscoped)
{
	const int domain_all;
	const int domain_parent;
	const int domain_children;
	const int domain_child;
	const int domain_grand_child;
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, deny_scoped) {
	.domain_all = NAMED_OTHER_SANDBOX,
	.domain_parent = NAMED_NO_SANDBOX,
	.domain_children = NAMED_SCOPE_SANDBOX,
	.domain_child = NAMED_NO_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, all_scoped) {
	.domain_all = NAMED_SCOPE_SANDBOX,
	.domain_parent = NAMED_NO_SANDBOX,
	.domain_children = NAMED_SCOPE_SANDBOX,
	.domain_child = NAMED_NO_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, allow_with_other_domain) {
	.domain_all = NAMED_OTHER_SANDBOX,
	.domain_parent = NAMED_NO_SANDBOX,
	.domain_children = NAMED_OTHER_SANDBOX,
	.domain_child = NAMED_NO_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, allow_with_one_domain) {
	.domain_all = NAMED_NO_SANDBOX,
	.domain_parent = NAMED_OTHER_SANDBOX,
	.domain_children = NAMED_NO_SANDBOX,
	.domain_child = NAMED_SCOPE_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, allow_with_grand_parent_scoped) {
	.domain_all = NAMED_NO_SANDBOX,
	.domain_parent = NAMED_SCOPE_SANDBOX,
	.domain_children = NAMED_NO_SANDBOX,
	.domain_child = NAMED_OTHER_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, allow_with_parents_domain) {
	.domain_all = NAMED_NO_SANDBOX,
	.domain_parent = NAMED_SCOPE_SANDBOX,
	.domain_children = NAMED_NO_SANDBOX,
	.domain_child = NAMED_SCOPE_SANDBOX,
	.domain_grand_child = NAMED_NO_SANDBOX,
	/* clang-format on */
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_named_vs_unscoped, deny_with_self_and_grandparent_domain) {
	.domain_all = NAMED_NO_SANDBOX,
	.domain_parent = NAMED_SCOPE_SANDBOX,
	.domain_children = NAMED_NO_SANDBOX,
	.domain_child = NAMED_NO_SANDBOX,
	.domain_grand_child = NAMED_SCOPE_SANDBOX,
	/* clang-format on */
};

#define NAMED_PARENT_STREAM_PATH NAMED_TMP_DIR "/parent_stream.sock"
#define NAMED_PARENT_DGRAM_PATH NAMED_TMP_DIR "/parent_dgram.sock"
#define NAMED_CHILD_STREAM_PATH NAMED_TMP_DIR "/child_stream.sock"
#define NAMED_CHILD_DGRAM_PATH NAMED_TMP_DIR "/child_dgram.sock"

FIXTURE_SETUP(scoped_named_vs_unscoped)
{
	drop_caps(_metadata);

	umask(0077);
	ASSERT_EQ(0, mkdir(NAMED_TMP_DIR, 0700));

	memset(&self->parent_stream_address, 0,
	       sizeof(self->parent_stream_address));
	set_named_address(&self->parent_stream_address, NAMED_PARENT_STREAM_PATH);
	memset(&self->parent_dgram_address, 0,
	       sizeof(self->parent_dgram_address));
	set_named_address(&self->parent_dgram_address, NAMED_PARENT_DGRAM_PATH);
	memset(&self->child_stream_address, 0,
	       sizeof(self->child_stream_address));
	set_named_address(&self->child_stream_address, NAMED_CHILD_STREAM_PATH);
	memset(&self->child_dgram_address, 0,
	       sizeof(self->child_dgram_address));
	set_named_address(&self->child_dgram_address, NAMED_CHILD_DGRAM_PATH);
}

FIXTURE_TEARDOWN(scoped_named_vs_unscoped)
{
	unlink(NAMED_PARENT_STREAM_PATH);
	unlink(NAMED_PARENT_DGRAM_PATH);
	unlink(NAMED_CHILD_STREAM_PATH);
	unlink(NAMED_CHILD_DGRAM_PATH);
	rmdir(NAMED_TMP_DIR);
}

/*
 * Test unix_stream_connect and unix_may_send for parent, child and
 * grand child processes when they can have scoped or non-scoped domains.
 */
TEST_F(scoped_named_vs_unscoped, named_unix_scoping)
{
	pid_t child;
	int status;
	bool can_connect_to_parent, can_connect_to_child;
	int pipe_parent[2];
	int stream_server_parent, dgram_server_parent;

	can_connect_to_child = (variant->domain_grand_child != NAMED_SCOPE_SANDBOX);
	can_connect_to_parent = (can_connect_to_child &&
				 (variant->domain_children != NAMED_SCOPE_SANDBOX));

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	if (variant->domain_all == NAMED_OTHER_SANDBOX)
		create_fs_domain(_metadata);
	else if (variant->domain_all == NAMED_SCOPE_SANDBOX)
		create_named_scoped_domain(_metadata);

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int stream_server_child, dgram_server_child;
		int pipe_child[2];
		pid_t grand_child;

		ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));

		if (variant->domain_children == NAMED_OTHER_SANDBOX)
			create_fs_domain(_metadata);
		else if (variant->domain_children == NAMED_SCOPE_SANDBOX)
			create_named_scoped_domain(_metadata);

		grand_child = fork();
		ASSERT_LE(0, grand_child);
		if (grand_child == 0) {
			char buf;
			int stream_err, dgram_err, stream_errno, dgram_errno;
			int stream_client, dgram_client;

			EXPECT_EQ(0, close(pipe_parent[1]));
			EXPECT_EQ(0, close(pipe_child[1]));

			if (variant->domain_grand_child == NAMED_OTHER_SANDBOX)
				create_fs_domain(_metadata);
			else if (variant->domain_grand_child == NAMED_SCOPE_SANDBOX)
				create_named_scoped_domain(_metadata);

			stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
			ASSERT_LE(0, stream_client);
			dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
			ASSERT_LE(0, dgram_client);

			ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
			stream_err = connect(
				stream_client,
				(struct sockaddr *)&self->child_stream_address.unix_addr,
				self->child_stream_address.unix_addr_len);
			stream_errno = errno;
			dgram_err = connect(
				dgram_client,
				(struct sockaddr *)&self->child_dgram_address.unix_addr,
				self->child_dgram_address.unix_addr_len);
			dgram_errno = errno;
			if (can_connect_to_child) {
				EXPECT_EQ(0, stream_err);
				EXPECT_EQ(0, dgram_err);
			} else {
				EXPECT_EQ(-1, stream_err);
				EXPECT_EQ(-1, dgram_err);
				EXPECT_EQ(EPERM, stream_errno);
				EXPECT_EQ(EPERM, dgram_errno);
			}

			EXPECT_EQ(0, close(stream_client));
			stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
			ASSERT_LE(0, stream_client);
			/* Datagram sockets can "reconnect". */

			ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));
			stream_err = connect(
				stream_client,
				(struct sockaddr *)&self->parent_stream_address.unix_addr,
				self->parent_stream_address.unix_addr_len);
			stream_errno = errno;
			dgram_err = connect(
				dgram_client,
				(struct sockaddr *)&self->parent_dgram_address.unix_addr,
				self->parent_dgram_address.unix_addr_len);
			dgram_errno = errno;
			if (can_connect_to_parent) {
				EXPECT_EQ(0, stream_err);
				EXPECT_EQ(0, dgram_err);
			} else {
				EXPECT_EQ(-1, stream_err);
				EXPECT_EQ(-1, dgram_err);
				EXPECT_EQ(EPERM, stream_errno);
				EXPECT_EQ(EPERM, dgram_errno);
			}
			EXPECT_EQ(0, close(stream_client));
			EXPECT_EQ(0, close(dgram_client));

			_exit(_metadata->exit_code);
			return;
		}
		EXPECT_EQ(0, close(pipe_child[0]));
		if (variant->domain_child == NAMED_OTHER_SANDBOX)
			create_fs_domain(_metadata);
		else if (variant->domain_child == NAMED_SCOPE_SANDBOX)
			create_named_scoped_domain(_metadata);

		stream_server_child = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_server_child);
		dgram_server_child = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_server_child);

		ASSERT_EQ(0, bind(stream_server_child,
				  (struct sockaddr *)&self->child_stream_address.unix_addr,
				  self->child_stream_address.unix_addr_len));
		ASSERT_EQ(0, bind(dgram_server_child,
				  (struct sockaddr *)&self->child_dgram_address.unix_addr,
				  self->child_dgram_address.unix_addr_len));
		ASSERT_EQ(0, listen(stream_server_child, backlog));

		ASSERT_EQ(1, write(pipe_child[1], ".", 1));
		ASSERT_EQ(grand_child, waitpid(grand_child, &status, 0));
		EXPECT_EQ(0, close(stream_server_child));
		EXPECT_EQ(0, close(dgram_server_child));
		return;
	}
	EXPECT_EQ(0, close(pipe_parent[0]));

	if (variant->domain_parent == NAMED_OTHER_SANDBOX)
		create_fs_domain(_metadata);
	else if (variant->domain_parent == NAMED_SCOPE_SANDBOX)
		create_named_scoped_domain(_metadata);

	stream_server_parent = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_server_parent);
	dgram_server_parent = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_server_parent);
	ASSERT_EQ(0, bind(stream_server_parent,
			  (struct sockaddr *)&self->parent_stream_address.unix_addr,
			  self->parent_stream_address.unix_addr_len));
	ASSERT_EQ(0, bind(dgram_server_parent,
			  (struct sockaddr *)&self->parent_dgram_address.unix_addr,
			  self->parent_dgram_address.unix_addr_len));

	ASSERT_EQ(0, listen(stream_server_parent, backlog));

	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(stream_server_parent));
	EXPECT_EQ(0, close(dgram_server_parent));

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST(named_datagram_sockets)
{
	struct named_service_fixture connected_addr, non_connected_addr;
	int server_conn_socket, server_unconn_socket;
	int pipe_parent[2], pipe_child[2];
	int status;
	char buf;
	pid_t child;

	drop_caps(_metadata);

	umask(0077);
	ASSERT_EQ(0, mkdir(NAMED_TMP_DIR, 0700));

	memset(&connected_addr, 0, sizeof(connected_addr));
	set_named_address(&connected_addr, NAMED_TMP_DIR "/conn_dgram.sock");
	memset(&non_connected_addr, 0, sizeof(non_connected_addr));
	set_named_address(&non_connected_addr, NAMED_TMP_DIR "/non_conn_dgram.sock");

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int client_conn_socket, client_unconn_socket;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));

		client_conn_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		client_unconn_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, client_conn_socket);
		ASSERT_LE(0, client_unconn_socket);

		/* Waits for parent to listen. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));
		ASSERT_EQ(0,
			  connect(client_conn_socket,
				  (struct sockaddr *)&connected_addr.unix_addr,
				  connected_addr.unix_addr_len));

		/*
		 * Both connected and non-connected sockets can send data when
		 * the domain is not scoped.
		 */
		ASSERT_EQ(1, send(client_conn_socket, ".", 1, 0));
		ASSERT_EQ(1, sendto(client_unconn_socket, ".", 1, 0,
				    (struct sockaddr *)&non_connected_addr.unix_addr,
				    non_connected_addr.unix_addr_len));
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		/* Scopes the domain. */
		create_named_scoped_domain(_metadata);

		/*
		 * Connected socket sends data to the receiver, but the
		 * non-connected socket must fail to send data.
		 */
		ASSERT_EQ(1, send(client_conn_socket, ".", 1, 0));
		ASSERT_EQ(-1, sendto(client_unconn_socket, ".", 1, 0,
				     (struct sockaddr *)&non_connected_addr.unix_addr,
				     non_connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		EXPECT_EQ(0, close(client_conn_socket));
		EXPECT_EQ(0, close(client_unconn_socket));
		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_parent[0]));
	EXPECT_EQ(0, close(pipe_child[1]));

	server_conn_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	server_unconn_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, server_conn_socket);
	ASSERT_LE(0, server_unconn_socket);

	ASSERT_EQ(0, bind(server_conn_socket,
			  (struct sockaddr *)&connected_addr.unix_addr,
			  connected_addr.unix_addr_len));
	ASSERT_EQ(0, bind(server_unconn_socket,
			  (struct sockaddr *)&non_connected_addr.unix_addr,
			  non_connected_addr.unix_addr_len));
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	/* Waits for child to test. */
	ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
	ASSERT_EQ(1, recv(server_conn_socket, &buf, 1, 0));
	ASSERT_EQ(1, recv(server_unconn_socket, &buf, 1, 0));

	/*
	 * Connected datagram socket will receive data, but
	 * non-connected datagram socket does not receive data.
	 */
	ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
	ASSERT_EQ(1, recv(server_conn_socket, &buf, 1, 0));

	/* Waits for all tests to finish. */
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(server_conn_socket));
	EXPECT_EQ(0, close(server_unconn_socket));

	/* Cleanup */
	unlink(NAMED_TMP_DIR "/conn_dgram.sock");
	unlink(NAMED_TMP_DIR "/non_conn_dgram.sock");
	rmdir(NAMED_TMP_DIR);

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST(named_self_connect)
{
	struct named_service_fixture connected_addr, non_connected_addr;
	int connected_socket, non_connected_socket, status;
	pid_t child;

	drop_caps(_metadata);

	umask(0077);
	ASSERT_EQ(0, mkdir(NAMED_TMP_DIR, 0700));

	memset(&connected_addr, 0, sizeof(connected_addr));
	set_named_address(&connected_addr, NAMED_TMP_DIR "/self_conn.sock");
	memset(&non_connected_addr, 0, sizeof(non_connected_addr));
	set_named_address(&non_connected_addr, NAMED_TMP_DIR "/self_non_conn.sock");

	connected_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	non_connected_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, connected_socket);
	ASSERT_LE(0, non_connected_socket);

	ASSERT_EQ(0, bind(connected_socket,
			  (struct sockaddr *)&connected_addr.unix_addr,
			  connected_addr.unix_addr_len));
	ASSERT_EQ(0, bind(non_connected_socket,
			  (struct sockaddr *)&non_connected_addr.unix_addr,
			  non_connected_addr.unix_addr_len));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		/* Child's domain is scoped. */
		create_named_scoped_domain(_metadata);

		/*
		 * The child inherits the sockets, and cannot connect or
		 * send data to them.
		 */
		ASSERT_EQ(-1,
			  connect(connected_socket,
				  (struct sockaddr *)&connected_addr.unix_addr,
				  connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);

		ASSERT_EQ(-1, sendto(connected_socket, ".", 1, 0,
				     (struct sockaddr *)&connected_addr.unix_addr,
				     connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);

		ASSERT_EQ(-1, sendto(non_connected_socket, ".", 1, 0,
				     (struct sockaddr *)&non_connected_addr.unix_addr,
				     non_connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);

		EXPECT_EQ(0, close(connected_socket));
		EXPECT_EQ(0, close(non_connected_socket));
		_exit(_metadata->exit_code);
		return;
	}

	/* Waits for all tests to finish. */
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(connected_socket));
	EXPECT_EQ(0, close(non_connected_socket));

	/* Cleanup */
	unlink(NAMED_TMP_DIR "/self_conn.sock");
	unlink(NAMED_TMP_DIR "/self_non_conn.sock");
	rmdir(NAMED_TMP_DIR);

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST_HARNESS_MAIN
