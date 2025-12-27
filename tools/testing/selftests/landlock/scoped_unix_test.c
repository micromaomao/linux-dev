// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Scoped access checks for UNIX socket (abstract and
 * pathname)
 *
 * Copyright © 2024 Tahera Fahimi <fahimitahera@gmail.com>
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

#include "audit.h"
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

FIXTURE(scoped_domains)
{
	struct service_fixture stream_address_abstract, dgram_address_abstract,
		stream_address_pathname, dgram_address_pathname;
};

#include "scoped_base_variants.h"

FIXTURE_SETUP(scoped_domains)
{
	drop_caps(_metadata);

	umask(0077);
	/* Clean up any leftover directory from previous tests. */
	rmdir(PATHNAME_UNIX_SOCK_DIR);
	ASSERT_EQ(0, mkdir(PATHNAME_UNIX_SOCK_DIR, 0700));

	memset(&self->stream_address_abstract, 0, sizeof(self->stream_address_abstract));
	memset(&self->dgram_address_abstract, 0, sizeof(self->dgram_address_abstract));
	memset(&self->stream_address_pathname, 0, sizeof(self->stream_address_pathname));
	memset(&self->dgram_address_pathname, 0, sizeof(self->dgram_address_pathname));
	set_unix_address(&self->stream_address_abstract, 0, true);
	set_unix_address(&self->dgram_address_abstract, 1, true);
	set_unix_address(&self->stream_address_pathname, 0, false);
	set_unix_address(&self->dgram_address_pathname, 1, false);
}

FIXTURE_TEARDOWN(scoped_domains)
{
	unlink(self->stream_address_pathname.unix_addr.sun_path);
	unlink(self->dgram_address_pathname.unix_addr.sun_path);
	rmdir(PATHNAME_UNIX_SOCK_DIR);
}

/*
 * Helper for connect_to_parent test. Tests unix_stream_connect() and
 * unix_may_send() for a child connecting to its parent.
 */
static void test_connect_to_parent(struct __test_metadata *const _metadata,
				   FIXTURE_DATA(scoped_domains) * self,
				   const FIXTURE_VARIANT(scoped_domains) *
					   variant,
				   const bool abstract)
{
	pid_t child;
	bool can_connect_to_parent;
	int status;
	int pipe_parent[2];
	int stream_server, dgram_server;
	const __u16 scope = abstract ? LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
				       LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;
	const struct service_fixture *stream_address =
		abstract ? &self->stream_address_abstract :
			   &self->stream_address_pathname;
	const struct service_fixture *dgram_address =
		abstract ? &self->dgram_address_abstract :
			   &self->dgram_address_pathname;

	/*
	 * can_connect_to_parent is true if a child process can connect to its
	 * parent process. This depends on the child process not being isolated
	 * from the parent with a dedicated Landlock domain.
	 */
	can_connect_to_parent = !variant->domain_child;

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	if (variant->domain_both) {
		create_scoped_domain(_metadata, scope);
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
			create_scoped_domain(_metadata, scope);

		stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_client);
		dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_client);

		/* Waits for the server. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));

		err = connect(stream_client, &stream_address->unix_addr,
			      stream_address->unix_addr_len);
		if (can_connect_to_parent) {
			EXPECT_EQ(0, err);
		} else {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		}
		EXPECT_EQ(0, close(stream_client));

		err = connect(dgram_client, &dgram_address->unix_addr,
			      dgram_address->unix_addr_len);
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
		create_scoped_domain(_metadata, scope);

	stream_server = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_server);
	dgram_server = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_server);
	ASSERT_EQ(0, bind(stream_server, &stream_address->unix_addr,
			  stream_address->unix_addr_len));
	ASSERT_EQ(0, bind(dgram_server, &dgram_address->unix_addr,
			  dgram_address->unix_addr_len));
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
 * Helper for connect_to_child test. Tests unix_stream_connect() and
 * unix_may_send() for a parent connecting to its child.
 */
static void test_connect_to_child(struct __test_metadata *const _metadata,
				  FIXTURE_DATA(scoped_domains) * self,
				  const FIXTURE_VARIANT(scoped_domains) *
					  variant,
				  const bool abstract)
{
	pid_t child;
	bool can_connect_to_child;
	int err_stream, err_dgram, errno_stream, errno_dgram, status;
	int pipe_child[2], pipe_parent[2];
	char buf;
	int stream_client, dgram_client;
	const __u16 scope = abstract ? LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
				       LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;
	const struct service_fixture *stream_address =
		abstract ? &self->stream_address_abstract :
			   &self->stream_address_pathname;
	const struct service_fixture *dgram_address =
		abstract ? &self->dgram_address_abstract :
			   &self->dgram_address_pathname;

	/*
	 * can_connect_to_child is true if a parent process can connect to its
	 * child process. The parent process is not isolated from the child
	 * with a dedicated Landlock domain.
	 */
	can_connect_to_child = !variant->domain_parent;

	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));
	if (variant->domain_both) {
		create_scoped_domain(_metadata, scope);
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
			create_scoped_domain(_metadata, scope);

		/* Waits for the parent to be in a domain, if any. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));

		stream_server = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_server);
		dgram_server = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_server);
		ASSERT_EQ(0,
			  bind(stream_server, &stream_address->unix_addr,
			       stream_address->unix_addr_len));
		ASSERT_EQ(0, bind(dgram_server, &dgram_address->unix_addr,
				  dgram_address->unix_addr_len));
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
		create_scoped_domain(_metadata, scope);

	/* Signals that the parent is in a domain, if any. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_client);
	dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_client);

	/* Waits for the child to listen */
	ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
	err_stream = connect(stream_client, &stream_address->unix_addr,
			     stream_address->unix_addr_len);
	errno_stream = errno;
	err_dgram = connect(dgram_client, &dgram_address->unix_addr,
			    dgram_address->unix_addr_len);
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

/*
 * Test unix_stream_connect() and unix_may_send() for a child connecting to its
 * parent, when they have scoped domain or no domain.
 */
TEST_F(scoped_domains, abstract_connect_to_parent)
{
	test_connect_to_parent(_metadata, self, variant, true);
}

/*
 * Test unix_stream_connect() and unix_may_send() for a parent connecting to
 * its child, when they have scoped domain or no domain.
 */
TEST_F(scoped_domains, abstract_connect_to_child)
{
	test_connect_to_child(_metadata, self, variant, true);
}

/*
 * Test unix_stream_connect() and unix_may_send() for a child connecting to its
 * parent with pathname sockets.
 */
TEST_F(scoped_domains, pathname_connect_to_parent)
{
	test_connect_to_parent(_metadata, self, variant, false);
}

/*
 * Test unix_stream_connect() and unix_may_send() for a parent connecting to
 * its child with pathname sockets.
 */
TEST_F(scoped_domains, pathname_connect_to_child)
{
	test_connect_to_child(_metadata, self, variant, false);
}

FIXTURE(scoped_audit)
{
	struct service_fixture dgram_address_abstract, dgram_address_pathname;
	struct audit_filter audit_filter;
	int audit_fd;
};

FIXTURE_VARIANT(scoped_audit)
{
	const bool abstract_socket;
};

// clang-format off
FIXTURE_VARIANT_ADD(scoped_audit, abstract_socket)
{
	// clang-format on
	.abstract_socket = true,
};

// clang-format off
FIXTURE_VARIANT_ADD(scoped_audit, pathname_socket)
{
	// clang-format on
	.abstract_socket = false,
};

FIXTURE_SETUP(scoped_audit)
{
	disable_caps(_metadata);

	memset(&self->dgram_address_abstract, 0, sizeof(self->dgram_address_abstract));
	memset(&self->dgram_address_pathname, 0, sizeof(self->dgram_address_pathname));
	set_unix_address(&self->dgram_address_abstract, 1, true);
	set_unix_address(&self->dgram_address_pathname, 1, false);

	set_cap(_metadata, CAP_AUDIT_CONTROL);
	self->audit_fd = audit_init_with_exe_filter(&self->audit_filter);
	EXPECT_LE(0, self->audit_fd);
	drop_caps(_metadata);
}

FIXTURE_TEARDOWN_PARENT(scoped_audit)
{
	EXPECT_EQ(0, audit_cleanup(-1, NULL));
}

/* python -c 'print(b"\0selftests-landlock-abstract-unix-".hex().upper())' */
#define ABSTRACT_SOCKET_PATH_PREFIX \
	"0073656C6674657374732D6C616E646C6F636B2D61627374726163742D756E69782D"

/*
 * Simpler version of scoped_domains.connect_to_child, but with audit tests.
 */
TEST_F(scoped_audit, connect_to_child)
{
	pid_t child;
	int err_dgram, status;
	int pipe_child[2], pipe_parent[2];
	char buf;
	int dgram_client;
	struct audit_records records;
	struct service_fixture *const dgram_address =
		variant->abstract_socket ? &self->dgram_address_abstract :
					   &self->dgram_address_pathname;
	const char *audit_match_str;

	/* Makes sure there is no superfluous logged records. */
	EXPECT_EQ(0, audit_count_records(self->audit_fd, &records));
	EXPECT_EQ(0, records.access);
	EXPECT_EQ(0, records.domain);

	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int dgram_server;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));

		/* Waits for the parent to be in a domain. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));

		dgram_server = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_server);
		ASSERT_EQ(0, bind(dgram_server, &dgram_address->unix_addr,
				  dgram_address->unix_addr_len));

		/* Signals to the parent that child is listening. */
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		/* Waits to connect. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf, 1));
		EXPECT_EQ(0, close(dgram_server));
		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_child[1]));
	EXPECT_EQ(0, close(pipe_parent[0]));

	create_scoped_domain(_metadata,
			     LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
				     LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET);

	/* Signals that the parent is in a domain, if any. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_client);

	/* Waits for the child to listen */
	ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
	err_dgram = connect(dgram_client, &dgram_address->unix_addr,
			    dgram_address->unix_addr_len);
	EXPECT_EQ(-1, err_dgram);
	EXPECT_EQ(EPERM, errno);

	if (variant->abstract_socket)
		audit_match_str = REGEX_LANDLOCK_PREFIX
			" blockers=scope\\.abstract_unix_socket path=" ABSTRACT_SOCKET_PATH_PREFIX
			"[0-9A-F]\\+$";
	else
		audit_match_str = REGEX_LANDLOCK_PREFIX
			" blockers=scope\\.pathname_unix_socket path=" ABSTRACT_SOCKET_PATH_PREFIX
			"[0-9A-F]\\+$";

	EXPECT_EQ(
		0,
		audit_match_record(
			self->audit_fd, AUDIT_LANDLOCK_ACCESS,
			audit_match_str,
			NULL));

	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	EXPECT_EQ(0, close(dgram_client));

	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

FIXTURE(scoped_vs_unscoped)
{
	struct service_fixture parent_stream_address_abstract,
		parent_dgram_address_abstract, child_stream_address_abstract,
		child_dgram_address_abstract;
	struct service_fixture parent_stream_address_pathname,
		parent_dgram_address_pathname, child_stream_address_pathname,
		child_dgram_address_pathname;
};

#include "scoped_multiple_domain_variants.h"

FIXTURE_SETUP(scoped_vs_unscoped)
{
	drop_caps(_metadata);

	umask(0077);
	/* Clean up any leftover directory from previous tests. */
	rmdir(TMP_DIR);
	ASSERT_EQ(0, mkdir(TMP_DIR, 0700));

	/* Abstract addresses. */
	memset(&self->parent_stream_address_abstract, 0,
	       sizeof(self->parent_stream_address_abstract));
	set_unix_address(&self->parent_stream_address_abstract, 0, true);
	memset(&self->parent_dgram_address_abstract, 0,
	       sizeof(self->parent_dgram_address_abstract));
	set_unix_address(&self->parent_dgram_address_abstract, 1, true);
	memset(&self->child_stream_address_abstract, 0,
	       sizeof(self->child_stream_address_abstract));
	set_unix_address(&self->child_stream_address_abstract, 2, true);
	memset(&self->child_dgram_address_abstract, 0,
	       sizeof(self->child_dgram_address_abstract));
	set_unix_address(&self->child_dgram_address_abstract, 3, true);

	/* Pathname addresses. */
	memset(&self->parent_stream_address_pathname, 0,
	       sizeof(self->parent_stream_address_pathname));
	set_unix_address(&self->parent_stream_address_pathname, 4, false);
	memset(&self->parent_dgram_address_pathname, 0,
	       sizeof(self->parent_dgram_address_pathname));
	set_unix_address(&self->parent_dgram_address_pathname, 5, false);
	memset(&self->child_stream_address_pathname, 0,
	       sizeof(self->child_stream_address_pathname));
	set_unix_address(&self->child_stream_address_pathname, 6, false);
	memset(&self->child_dgram_address_pathname, 0,
	       sizeof(self->child_dgram_address_pathname));
	set_unix_address(&self->child_dgram_address_pathname, 7, false);
}

FIXTURE_TEARDOWN(scoped_vs_unscoped)
{
	unlink(self->parent_stream_address_pathname.unix_addr.sun_path);
	unlink(self->parent_dgram_address_pathname.unix_addr.sun_path);
	unlink(self->child_stream_address_pathname.unix_addr.sun_path);
	unlink(self->child_dgram_address_pathname.unix_addr.sun_path);
	rmdir(TMP_DIR);
}

/*
 * Helper function for testing unix_stream_connect and unix_may_send for parent,
 * child and grand child processes when they can have scoped or non-scoped
 * domains.
 */
static void test_scoped_vs_unscoped_impl(
	struct __test_metadata *const _metadata,
	FIXTURE_DATA(scoped_vs_unscoped) *self,
	const FIXTURE_VARIANT(scoped_vs_unscoped) *variant,
	const bool abstract)
{
	pid_t child;
	int status;
	bool can_connect_to_parent, can_connect_to_child;
	int pipe_parent[2];
	int stream_server_parent, dgram_server_parent;
	const __u64 scope = abstract ? LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
				       LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;
	const struct service_fixture *parent_stream_address =
		abstract ? &self->parent_stream_address_abstract :
			   &self->parent_stream_address_pathname;
	const struct service_fixture *parent_dgram_address =
		abstract ? &self->parent_dgram_address_abstract :
			   &self->parent_dgram_address_pathname;
	const struct service_fixture *child_stream_address =
		abstract ? &self->child_stream_address_abstract :
			   &self->child_stream_address_pathname;
	const struct service_fixture *child_dgram_address =
		abstract ? &self->child_dgram_address_abstract :
			   &self->child_dgram_address_pathname;

	can_connect_to_child = (variant->domain_grand_child != SCOPE_SANDBOX);
	can_connect_to_parent = (can_connect_to_child &&
				 (variant->domain_children != SCOPE_SANDBOX));

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	if (variant->domain_all == OTHER_SANDBOX)
		create_fs_domain(_metadata);
	else if (variant->domain_all == SCOPE_SANDBOX)
		create_scoped_domain(_metadata, scope);

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int stream_server_child, dgram_server_child;
		int pipe_child[2];
		pid_t grand_child;

		ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));

		if (variant->domain_children == OTHER_SANDBOX)
			create_fs_domain(_metadata);
		else if (variant->domain_children == SCOPE_SANDBOX)
			create_scoped_domain(_metadata, scope);

		grand_child = fork();
		ASSERT_LE(0, grand_child);
		if (grand_child == 0) {
			char buf;
			int stream_err, dgram_err, stream_errno, dgram_errno;
			int stream_client, dgram_client;

			EXPECT_EQ(0, close(pipe_parent[1]));
			EXPECT_EQ(0, close(pipe_child[1]));

			if (variant->domain_grand_child == OTHER_SANDBOX)
				create_fs_domain(_metadata);
			else if (variant->domain_grand_child == SCOPE_SANDBOX)
				create_scoped_domain(_metadata, scope);

			stream_client = socket(AF_UNIX, SOCK_STREAM, 0);
			ASSERT_LE(0, stream_client);
			dgram_client = socket(AF_UNIX, SOCK_DGRAM, 0);
			ASSERT_LE(0, dgram_client);

			ASSERT_EQ(1, read(pipe_child[0], &buf, 1));
			stream_err = connect(stream_client,
					     &child_stream_address->unix_addr,
					     child_stream_address->unix_addr_len);
			stream_errno = errno;
			dgram_err = connect(dgram_client,
					    &child_dgram_address->unix_addr,
					    child_dgram_address->unix_addr_len);
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
				stream_client, &parent_stream_address->unix_addr,
				parent_stream_address->unix_addr_len);
			stream_errno = errno;
			dgram_err = connect(
				dgram_client, &parent_dgram_address->unix_addr,
				parent_dgram_address->unix_addr_len);
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
		if (variant->domain_child == OTHER_SANDBOX)
			create_fs_domain(_metadata);
		else if (variant->domain_child == SCOPE_SANDBOX)
			create_scoped_domain(_metadata, scope);

		stream_server_child = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_server_child);
		dgram_server_child = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_server_child);

		ASSERT_EQ(0, bind(stream_server_child,
				  &child_stream_address->unix_addr,
				  child_stream_address->unix_addr_len));
		ASSERT_EQ(0,
			  bind(dgram_server_child, &child_dgram_address->unix_addr,
			       child_dgram_address->unix_addr_len));
		ASSERT_EQ(0, listen(stream_server_child, backlog));

		ASSERT_EQ(1, write(pipe_child[1], ".", 1));
		ASSERT_EQ(grand_child, waitpid(grand_child, &status, 0));
		EXPECT_EQ(0, close(stream_server_child));
		EXPECT_EQ(0, close(dgram_server_child));
		return;
	}
	EXPECT_EQ(0, close(pipe_parent[0]));

	if (variant->domain_parent == OTHER_SANDBOX)
		create_fs_domain(_metadata);
	else if (variant->domain_parent == SCOPE_SANDBOX)
		create_scoped_domain(_metadata, scope);

	stream_server_parent = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_server_parent);
	dgram_server_parent = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_server_parent);
	ASSERT_EQ(0, bind(stream_server_parent, &parent_stream_address->unix_addr,
			  parent_stream_address->unix_addr_len));
	ASSERT_EQ(0, bind(dgram_server_parent, &parent_dgram_address->unix_addr,
			  parent_dgram_address->unix_addr_len));

	ASSERT_EQ(0, listen(stream_server_parent, backlog));

	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(stream_server_parent));
	EXPECT_EQ(0, close(dgram_server_parent));

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST_F(scoped_vs_unscoped, unix_scoping_abstract)
{
	test_scoped_vs_unscoped_impl(_metadata, self, variant, true);
}

TEST_F(scoped_vs_unscoped, unix_scoping_pathname)
{
	test_scoped_vs_unscoped_impl(_metadata, self, variant, false);
}

FIXTURE(outside_socket)
{
	struct service_fixture address_abstract, transit_address_abstract;
	struct service_fixture address_pathname, transit_address_pathname;
};

FIXTURE_VARIANT(outside_socket)
{
	const bool child_socket;
	const int type;
	const bool abstract;
};

/* Abstract socket variants */
/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, abstract_allow_dgram_child) {
	/* clang-format on */
	.child_socket = true,
	.type = SOCK_DGRAM,
	.abstract = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, abstract_deny_dgram_server) {
	/* clang-format on */
	.child_socket = false,
	.type = SOCK_DGRAM,
	.abstract = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, abstract_allow_stream_child) {
	/* clang-format on */
	.child_socket = true,
	.type = SOCK_STREAM,
	.abstract = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, abstract_deny_stream_server) {
	/* clang-format on */
	.child_socket = false,
	.type = SOCK_STREAM,
	.abstract = true,
};

/* Pathname socket variants */
/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, pathname_allow_dgram_child) {
	/* clang-format on */
	.child_socket = true,
	.type = SOCK_DGRAM,
	.abstract = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, pathname_deny_dgram_server) {
	/* clang-format on */
	.child_socket = false,
	.type = SOCK_DGRAM,
	.abstract = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, pathname_allow_stream_child) {
	/* clang-format on */
	.child_socket = true,
	.type = SOCK_STREAM,
	.abstract = false,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(outside_socket, pathname_deny_stream_server) {
	/* clang-format on */
	.child_socket = false,
	.type = SOCK_STREAM,
	.abstract = false,
};

FIXTURE_SETUP(outside_socket)
{
	drop_caps(_metadata);

	umask(0077);
	/* Clean up any leftover directory from previous tests. */
	rmdir(TMP_DIR);
	ASSERT_EQ(0, mkdir(TMP_DIR, 0700));

	/* Abstract addresses. */
	memset(&self->transit_address_abstract, 0,
	       sizeof(self->transit_address_abstract));
	set_unix_address(&self->transit_address_abstract, 0, true);
	memset(&self->address_abstract, 0, sizeof(self->address_abstract));
	set_unix_address(&self->address_abstract, 1, true);

	/* Pathname addresses. */
	memset(&self->transit_address_pathname, 0,
	       sizeof(self->transit_address_pathname));
	set_unix_address(&self->transit_address_pathname, 2, false);
	memset(&self->address_pathname, 0, sizeof(self->address_pathname));
	set_unix_address(&self->address_pathname, 3, false);
}

FIXTURE_TEARDOWN(outside_socket)
{
	unlink(self->transit_address_pathname.unix_addr.sun_path);
	unlink(self->address_pathname.unix_addr.sun_path);
	rmdir(TMP_DIR);
}

/*
 * Test unix_stream_connect and unix_may_send for parent and child processes
 * when connecting socket has different domain than the process using it.
 */
TEST_F(outside_socket, socket_with_different_domain)
{
	pid_t child;
	int err, status;
	int pipe_child[2], pipe_parent[2];
	char buf_parent;
	int server_socket;
	const __u64 scope = variant->abstract ?
		LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
		LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;
	const struct service_fixture *transit_address =
		variant->abstract ? &self->transit_address_abstract :
				    &self->transit_address_pathname;
	const struct service_fixture *address =
		variant->abstract ? &self->address_abstract :
				    &self->address_pathname;

	ASSERT_EQ(0, pipe2(pipe_child, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int client_socket;
		char buf_child;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(pipe_child[0]));

		/* Client always has a domain. */
		create_scoped_domain(_metadata, scope);

		if (variant->child_socket) {
			int data_socket, passed_socket, stream_server;

			passed_socket = socket(AF_UNIX, variant->type, 0);
			ASSERT_LE(0, passed_socket);
			stream_server = socket(AF_UNIX, SOCK_STREAM, 0);
			ASSERT_LE(0, stream_server);
			ASSERT_EQ(0, bind(stream_server,
					  &transit_address->unix_addr,
					  transit_address->unix_addr_len));
			ASSERT_EQ(0, listen(stream_server, backlog));
			ASSERT_EQ(1, write(pipe_child[1], ".", 1));
			data_socket = accept(stream_server, NULL, NULL);
			ASSERT_LE(0, data_socket);
			ASSERT_EQ(0, send_fd(data_socket, passed_socket));
			EXPECT_EQ(0, close(passed_socket));
			EXPECT_EQ(0, close(stream_server));
		}

		client_socket = socket(AF_UNIX, variant->type, 0);
		ASSERT_LE(0, client_socket);

		/* Waits for parent signal for connection. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));
		err = connect(client_socket, &address->unix_addr,
			      address->unix_addr_len);
		if (variant->child_socket) {
			EXPECT_EQ(0, err);
		} else {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		}
		EXPECT_EQ(0, close(client_socket));
		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_child[1]));
	EXPECT_EQ(0, close(pipe_parent[0]));

	if (variant->child_socket) {
		int client_child = socket(AF_UNIX, SOCK_STREAM, 0);

		ASSERT_LE(0, client_child);
		ASSERT_EQ(1, read(pipe_child[0], &buf_parent, 1));
		ASSERT_EQ(0, connect(client_child, &transit_address->unix_addr,
				     transit_address->unix_addr_len));
		server_socket = recv_fd(client_child);
		EXPECT_EQ(0, close(client_child));
	} else {
		server_socket = socket(AF_UNIX, variant->type, 0);
	}
	ASSERT_LE(0, server_socket);

	/* Server always has a domain. */
	create_scoped_domain(_metadata, scope);

	ASSERT_EQ(0,
		  bind(server_socket, &address->unix_addr, address->unix_addr_len));
	if (variant->type == SOCK_STREAM)
		ASSERT_EQ(0, listen(server_socket, backlog));

	/* Signals to child that the parent is listening. */
	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));

	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(0, close(server_socket));

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

/* Sandbox types for various_address_sockets */
enum various_socket_sandbox_type {
	SCOPE_ABSTRACT_SANDBOX,
	SCOPE_PATHNAME_SANDBOX,
	SCOPE_BOTH_SANDBOX,
	VARIOUS_OTHER_SANDBOX,
	VARIOUS_NO_SANDBOX,
};

/* clang-format off */
FIXTURE(various_address_sockets) {
	struct service_fixture stream_pathname_addr, dgram_pathname_addr;
	struct service_fixture stream_abstract_addr, dgram_abstract_addr;
};
/* clang-format on */

FIXTURE_VARIANT(various_address_sockets)
{
	const int domain;
};

/* clang-format off */
FIXTURE_VARIANT_ADD(various_address_sockets, scope_abstract) {
	/* clang-format on */
	.domain = SCOPE_ABSTRACT_SANDBOX,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(various_address_sockets, scope_pathname) {
	/* clang-format on */
	.domain = SCOPE_PATHNAME_SANDBOX,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(various_address_sockets, scope_both) {
	/* clang-format on */
	.domain = SCOPE_BOTH_SANDBOX,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(various_address_sockets, other_domain) {
	/* clang-format on */
	.domain = VARIOUS_OTHER_SANDBOX,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(various_address_sockets, no_domain) {
	/* clang-format on */
	.domain = VARIOUS_NO_SANDBOX,
};

FIXTURE_SETUP(various_address_sockets)
{
	drop_caps(_metadata);

	umask(0077);
	/* Clean up any leftover directory from previous tests. */
	rmdir(TMP_DIR);
	ASSERT_EQ(0, mkdir(TMP_DIR, 0700));

	/* Set up pathname addresses. */
	memset(&self->stream_pathname_addr, 0, sizeof(self->stream_pathname_addr));
	set_unix_address(&self->stream_pathname_addr, 0, false);
	memset(&self->dgram_pathname_addr, 0, sizeof(self->dgram_pathname_addr));
	set_unix_address(&self->dgram_pathname_addr, 1, false);

	/* Set up abstract addresses. */
	memset(&self->stream_abstract_addr, 0, sizeof(self->stream_abstract_addr));
	set_unix_address(&self->stream_abstract_addr, 2, true);
	memset(&self->dgram_abstract_addr, 0, sizeof(self->dgram_abstract_addr));
	set_unix_address(&self->dgram_abstract_addr, 3, true);
}

FIXTURE_TEARDOWN(various_address_sockets)
{
	unlink(self->stream_pathname_addr.unix_addr.sun_path);
	unlink(self->dgram_pathname_addr.unix_addr.sun_path);
	rmdir(TMP_DIR);
}

/*
 * Test interaction of various scope flags (controlled by variant->domain)
 * with pathname and abstract sockets in a parent-child setup.
 */
TEST_F(various_address_sockets, scoped_sockets)
{
	pid_t child;
	int status;
	char buf_child, buf_parent;
	int pipe_parent[2];
	int unnamed_sockets[2];
	int stream_pathname_socket, dgram_pathname_socket,
		stream_abstract_socket, dgram_abstract_socket, data_socket;
	bool pathname_restricted, abstract_restricted;

	/* Determine what should be restricted based on sandbox type. */
	pathname_restricted = (variant->domain == SCOPE_PATHNAME_SANDBOX ||
			       variant->domain == SCOPE_BOTH_SANDBOX);
	abstract_restricted = (variant->domain == SCOPE_ABSTRACT_SANDBOX ||
			       variant->domain == SCOPE_BOTH_SANDBOX);

	/* Unnamed address for datagram socket. */
	ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, unnamed_sockets));

	ASSERT_EQ(0, pipe2(pipe_parent, O_CLOEXEC));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		int err;

		EXPECT_EQ(0, close(pipe_parent[1]));
		EXPECT_EQ(0, close(unnamed_sockets[1]));

		/* Create domain based on variant. */
		if (variant->domain == SCOPE_ABSTRACT_SANDBOX)
			create_scoped_domain(
				_metadata, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
		else if (variant->domain == SCOPE_PATHNAME_SANDBOX)
			create_scoped_domain(
				_metadata, LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET);
		else if (variant->domain == SCOPE_BOTH_SANDBOX)
			create_scoped_domain(
				_metadata, LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
					   LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET);
		else if (variant->domain == VARIOUS_OTHER_SANDBOX)
			create_fs_domain(_metadata);

		/* Waits for parent to listen. */
		ASSERT_EQ(1, read(pipe_parent[0], &buf_child, 1));
		EXPECT_EQ(0, close(pipe_parent[0]));

		/* Checks that we can send data through unnamed socket. */
		ASSERT_EQ(1, write(unnamed_sockets[0], "a", 1));
		EXPECT_EQ(0, close(unnamed_sockets[0]));

		/* Connects with pathname sockets. */
		stream_pathname_socket = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_pathname_socket);
		err = connect(stream_pathname_socket,
			      &self->stream_pathname_addr.unix_addr,
			      self->stream_pathname_addr.unix_addr_len);
		if (pathname_restricted) {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(0, err);
			ASSERT_EQ(1, write(stream_pathname_socket, "b", 1));
		}
		EXPECT_EQ(0, close(stream_pathname_socket));

		/* Sends without connection (pathname). */
		dgram_pathname_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_pathname_socket);
		err = sendto(dgram_pathname_socket, "c", 1, 0,
			     &self->dgram_pathname_addr.unix_addr,
			     self->dgram_pathname_addr.unix_addr_len);
		if (pathname_restricted) {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(1, err);
		}
		EXPECT_EQ(0, close(dgram_pathname_socket));

		/* Connects with abstract sockets. */
		stream_abstract_socket = socket(AF_UNIX, SOCK_STREAM, 0);
		ASSERT_LE(0, stream_abstract_socket);
		err = connect(stream_abstract_socket,
			      &self->stream_abstract_addr.unix_addr,
			      self->stream_abstract_addr.unix_addr_len);
		if (abstract_restricted) {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(0, err);
			ASSERT_EQ(1, write(stream_abstract_socket, "d", 1));
		}
		EXPECT_EQ(0, close(stream_abstract_socket));

		/* Sends without connection (abstract). */
		dgram_abstract_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
		ASSERT_LE(0, dgram_abstract_socket);
		err = sendto(dgram_abstract_socket, "e", 1, 0,
			     &self->dgram_abstract_addr.unix_addr,
			     self->dgram_abstract_addr.unix_addr_len);
		if (abstract_restricted) {
			EXPECT_EQ(-1, err);
			EXPECT_EQ(EPERM, errno);
		} else {
			EXPECT_EQ(1, err);
		}
		EXPECT_EQ(0, close(dgram_abstract_socket));

		_exit(_metadata->exit_code);
		return;
	}
	EXPECT_EQ(0, close(pipe_parent[0]));
	EXPECT_EQ(0, close(unnamed_sockets[0]));

	/* Sets up pathname servers. */
	stream_pathname_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_pathname_socket);
	ASSERT_EQ(0, bind(stream_pathname_socket,
			  &self->stream_pathname_addr.unix_addr,
			  self->stream_pathname_addr.unix_addr_len));
	ASSERT_EQ(0, listen(stream_pathname_socket, backlog));

	dgram_pathname_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_pathname_socket);
	ASSERT_EQ(0, bind(dgram_pathname_socket,
			  &self->dgram_pathname_addr.unix_addr,
			  self->dgram_pathname_addr.unix_addr_len));

	/* Sets up abstract servers. */
	stream_abstract_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LE(0, stream_abstract_socket);
	ASSERT_EQ(0, bind(stream_abstract_socket,
			  &self->stream_abstract_addr.unix_addr,
			  self->stream_abstract_addr.unix_addr_len));
	ASSERT_EQ(0, listen(stream_abstract_socket, backlog));

	dgram_abstract_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, dgram_abstract_socket);
	ASSERT_EQ(0, bind(dgram_abstract_socket,
			  &self->dgram_abstract_addr.unix_addr,
			  self->dgram_abstract_addr.unix_addr_len));

	ASSERT_EQ(1, write(pipe_parent[1], ".", 1));
	EXPECT_EQ(0, close(pipe_parent[1]));

	/* Reads from unnamed socket. */
	ASSERT_EQ(1, read(unnamed_sockets[1], &buf_parent, sizeof(buf_parent)));
	ASSERT_EQ('a', buf_parent);
	EXPECT_LE(0, close(unnamed_sockets[1]));

	/* Reads from pathname sockets if not restricted. */
	if (!pathname_restricted) {
		data_socket = accept(stream_pathname_socket, NULL, NULL);
		ASSERT_LE(0, data_socket);
		ASSERT_EQ(1,
			  read(data_socket, &buf_parent, sizeof(buf_parent)));
		ASSERT_EQ('b', buf_parent);
		EXPECT_EQ(0, close(data_socket));

		ASSERT_EQ(1, read(dgram_pathname_socket, &buf_parent,
				  sizeof(buf_parent)));
		ASSERT_EQ('c', buf_parent);
	}
	EXPECT_EQ(0, close(stream_pathname_socket));
	EXPECT_EQ(0, close(dgram_pathname_socket));

	/* Reads from abstract sockets if not restricted. */
	if (!abstract_restricted) {
		data_socket = accept(stream_abstract_socket, NULL, NULL);
		ASSERT_LE(0, data_socket);
		ASSERT_EQ(1,
			  read(data_socket, &buf_parent, sizeof(buf_parent)));
		ASSERT_EQ('d', buf_parent);
		EXPECT_EQ(0, close(data_socket));

		ASSERT_EQ(1, read(dgram_abstract_socket, &buf_parent,
				  sizeof(buf_parent)));
		ASSERT_EQ('e', buf_parent);
	}
	EXPECT_EQ(0, close(stream_abstract_socket));
	EXPECT_EQ(0, close(dgram_abstract_socket));

	/* Waits for child to complete. */
	ASSERT_EQ(child, waitpid(child, &status, 0));

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

/* Fixture for datagram_sockets and self_connect tests */
FIXTURE(socket_type_test)
{
	struct service_fixture connected_addr, non_connected_addr;
};

FIXTURE_VARIANT(socket_type_test)
{
	const bool abstract;
};

/* clang-format off */
FIXTURE_VARIANT_ADD(socket_type_test, abstract) {
	/* clang-format on */
	.abstract = true,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(socket_type_test, pathname) {
	/* clang-format on */
	.abstract = false,
};

FIXTURE_SETUP(socket_type_test)
{
	drop_caps(_metadata);

	if (!variant->abstract) {
		umask(0077);
		/* Clean up any leftover directory from previous tests. */
		rmdir(TMP_DIR);
		ASSERT_EQ(0, mkdir(TMP_DIR, 0700));
	}

	memset(&self->connected_addr, 0, sizeof(self->connected_addr));
	set_unix_address(&self->connected_addr, 0, variant->abstract);
	memset(&self->non_connected_addr, 0, sizeof(self->non_connected_addr));
	set_unix_address(&self->non_connected_addr, 1, variant->abstract);
}

FIXTURE_TEARDOWN(socket_type_test)
{
	if (!variant->abstract) {
		unlink(self->connected_addr.unix_addr.sun_path);
		unlink(self->non_connected_addr.unix_addr.sun_path);
		rmdir(TMP_DIR);
	}
}

TEST_F(socket_type_test, datagram_sockets)
{
	int server_conn_socket, server_unconn_socket;
	int pipe_parent[2], pipe_child[2];
	int status;
	char buf;
	pid_t child;
	const __u64 scope = variant->abstract ?
		LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
		LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;

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
				  &self->connected_addr.unix_addr,
				  self->connected_addr.unix_addr_len));

		/*
		 * Both connected and non-connected sockets can send data when
		 * the domain is not scoped.
		 */
		ASSERT_EQ(1, send(client_conn_socket, ".", 1, 0));
		ASSERT_EQ(1, sendto(client_unconn_socket, ".", 1, 0,
				    &self->non_connected_addr.unix_addr,
				    self->non_connected_addr.unix_addr_len));
		ASSERT_EQ(1, write(pipe_child[1], ".", 1));

		/* Scopes the domain. */
		create_scoped_domain(_metadata, scope);

		/*
		 * Connected socket sends data to the receiver, but the
		 * non-connected socket must fail to send data.
		 */
		ASSERT_EQ(1, send(client_conn_socket, ".", 1, 0));
		ASSERT_EQ(-1, sendto(client_unconn_socket, ".", 1, 0,
				     &self->non_connected_addr.unix_addr,
				     self->non_connected_addr.unix_addr_len));
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

	ASSERT_EQ(0, bind(server_conn_socket, &self->connected_addr.unix_addr,
			  self->connected_addr.unix_addr_len));
	ASSERT_EQ(0, bind(server_unconn_socket,
			  &self->non_connected_addr.unix_addr,
			  self->non_connected_addr.unix_addr_len));
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

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST_F(socket_type_test, self_connect)
{
	int connected_socket, non_connected_socket, status;
	pid_t child;
	const __u64 scope = variant->abstract ?
		LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET :
		LANDLOCK_SCOPE_PATHNAME_UNIX_SOCKET;

	connected_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	non_connected_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	ASSERT_LE(0, connected_socket);
	ASSERT_LE(0, non_connected_socket);

	ASSERT_EQ(0, bind(connected_socket, &self->connected_addr.unix_addr,
			  self->connected_addr.unix_addr_len));
	ASSERT_EQ(0, bind(non_connected_socket,
			  &self->non_connected_addr.unix_addr,
			  self->non_connected_addr.unix_addr_len));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		/* Child's domain is scoped. */
		create_scoped_domain(_metadata, scope);

		/*
		 * The child inherits the sockets, and cannot connect or
		 * send data to them.
		 */
		ASSERT_EQ(-1,
			  connect(connected_socket,
				  &self->connected_addr.unix_addr,
				  self->connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);

		ASSERT_EQ(-1, sendto(connected_socket, ".", 1, 0,
				     &self->connected_addr.unix_addr,
				     self->connected_addr.unix_addr_len));
		ASSERT_EQ(EPERM, errno);

		ASSERT_EQ(-1, sendto(non_connected_socket, ".", 1, 0,
				     &self->non_connected_addr.unix_addr,
				     self->non_connected_addr.unix_addr_len));
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

	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;
}

TEST_HARNESS_MAIN
