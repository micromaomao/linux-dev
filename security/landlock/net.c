// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Network management and hooks
 *
 * Copyright © 2022-2023 Huawei Tech. Co., Ltd.
 * Copyright © 2022-2025 Microsoft Corporation
 */

#include <linux/errno.h>
#include <linux/in.h>
#include <linux/lsm_audit.h>
#include <linux/net.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <net/ipv6.h>

#include "audit.h"
#include "common.h"
#include "cred.h"
#include "domain.h"
#include "limits.h"
#include "net.h"
#include "ruleset.h"
#include "supervisor.h"

int landlock_append_net_rule(struct landlock_ruleset *const ruleset,
			     const u16 port, access_mask_t access_rights,
			     const int flags)
{
	int err;
	const struct landlock_id id = {
		.key.data = (__force uintptr_t)htons(port),
		.type = LANDLOCK_KEY_NET_PORT,
	};

	BUILD_BUG_ON(sizeof(port) > sizeof(id.key.data));

	/* Transforms relative access rights to absolute ones. */
	access_rights |= LANDLOCK_MASK_ACCESS_NET &
			 ~landlock_get_net_access_mask(ruleset, 0);

	mutex_lock(&ruleset->lock);
	err = landlock_insert_rule(ruleset, id, access_rights, flags);
	mutex_unlock(&ruleset->lock);

	return err;
}

/**
 * landlock_check_notify_net - Check if denied net access should trigger notification
 *
 * @domain: The domain that denied access.
 * @layer_masks: Layer masks showing which layers still deny access.
 * @rule_flags: Collected rule flags for quiet determination.
 * @access_request: The denied access rights.
 * @port: The network port being accessed.
 *
 * Returns:
 * - 0 if a notification was queued (caller should return restart_syscall())
 * - -EACCES if notification cannot be sent (normal denial)
 */
static int landlock_check_notify_net(
	const struct landlock_ruleset *const domain,
	const struct layer_access_masks *const layer_masks,
	const struct collected_rule_flags *const rule_flags,
	const access_mask_t access_request, const __u16 port)
{
	ssize_t layer_level;
	const struct landlock_hierarchy *hierarchy;
	struct landlock_supervisor *notify_supervisor = NULL;
	int ret;

	if (!domain || !domain->hierarchy)
		return -EACCES;

	hierarchy = domain->hierarchy;
	for (layer_level = domain->num_layers - 1; layer_level >= 0;
	     layer_level--, hierarchy = hierarchy->parent) {
		if (!layer_masks->access[layer_level])
			continue;

		if (rule_flags &&
		    (rule_flags->quiet_masks & BIT(layer_level)))
			return -EACCES;

		if (!landlock_supervisor_has_notification(
			    hierarchy->supervisor))
			return -EACCES;

		if (!notify_supervisor)
			notify_supervisor = hierarchy->supervisor;
	}

	if (!notify_supervisor)
		return -EACCES;

	ret = landlock_queue_supervisor_notification(
		notify_supervisor,
		LANDLOCK_SUPERVISE_EVENT_TYPE_NET_ACCESS, access_request,
		NULL, NULL, false, false, port);
	if (ret)
		return -EACCES;

	return 0;
}

static int current_check_access_socket(struct socket *const sock,
				       struct sockaddr *const address,
				       const int addrlen,
				       access_mask_t access_request)
{
	__be16 port;
	struct layer_access_masks layer_masks = {};
	struct collected_rule_flags rule_flags = {};
	const struct landlock_rule *rule;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_NET_PORT,
	};
	const struct access_masks masks = {
		.net = access_request,
	};
	const struct landlock_cred_security *const subject =
		landlock_get_applicable_subject(current_cred(), masks, NULL);
	struct lsm_network_audit audit_net = {};

	if (!subject)
		return 0;

	/* Checks for minimal header length to safely read sa_family. */
	if (addrlen < offsetofend(typeof(*address), sa_family))
		return -EINVAL;

	switch (address->sa_family) {
	case AF_UNSPEC:
		if (access_request == LANDLOCK_ACCESS_NET_CONNECT_TCP) {
			/*
			 * Connecting to an address with AF_UNSPEC dissolves
			 * the TCP association, which have the same effect as
			 * closing the connection while retaining the socket
			 * object (i.e., the file descriptor).  As for dropping
			 * privileges, closing connections is always allowed.
			 *
			 * For a TCP access control system, this request is
			 * legitimate. Let the network stack handle potential
			 * inconsistencies and return -EINVAL if needed.
			 */
			return 0;
		} else if (access_request == LANDLOCK_ACCESS_NET_BIND_TCP) {
			/*
			 * Binding to an AF_UNSPEC address is treated
			 * differently by IPv4 and IPv6 sockets. The socket's
			 * family may change under our feet due to
			 * setsockopt(IPV6_ADDRFORM), but that's ok: we either
			 * reject entirely or require
			 * %LANDLOCK_ACCESS_NET_BIND_TCP for the given port, so
			 * it cannot be used to bypass the policy.
			 *
			 * IPv4 sockets map AF_UNSPEC to AF_INET for
			 * retrocompatibility for bind accesses, only if the
			 * address is INADDR_ANY (cf. __inet_bind). IPv6
			 * sockets always reject it.
			 *
			 * Checking the address is required to not wrongfully
			 * return -EACCES instead of -EAFNOSUPPORT or -EINVAL.
			 * We could return 0 and let the network stack handle
			 * these checks, but it is safer to return a proper
			 * error and test consistency thanks to kselftest.
			 */
			if (sock->sk->__sk_common.skc_family == AF_INET) {
				const struct sockaddr_in *const sockaddr =
					(struct sockaddr_in *)address;

				if (addrlen < sizeof(struct sockaddr_in))
					return -EINVAL;

				if (sockaddr->sin_addr.s_addr !=
				    htonl(INADDR_ANY))
					return -EAFNOSUPPORT;
			} else {
				if (addrlen < SIN6_LEN_RFC2133)
					return -EINVAL;
				else
					return -EAFNOSUPPORT;
			}
		} else {
			WARN_ON_ONCE(1);
		}
		/* Only for bind(AF_UNSPEC+INADDR_ANY) on IPv4 socket. */
		fallthrough;
	case AF_INET: {
		const struct sockaddr_in *addr4;

		if (addrlen < sizeof(struct sockaddr_in))
			return -EINVAL;

		addr4 = (struct sockaddr_in *)address;
		port = addr4->sin_port;

		if (access_request == LANDLOCK_ACCESS_NET_CONNECT_TCP) {
			audit_net.dport = port;
			audit_net.v4info.daddr = addr4->sin_addr.s_addr;
		} else if (access_request == LANDLOCK_ACCESS_NET_BIND_TCP) {
			audit_net.sport = port;
			audit_net.v4info.saddr = addr4->sin_addr.s_addr;
		} else {
			WARN_ON_ONCE(1);
		}
		break;
	}

#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6: {
		const struct sockaddr_in6 *addr6;

		if (addrlen < SIN6_LEN_RFC2133)
			return -EINVAL;

		addr6 = (struct sockaddr_in6 *)address;
		port = addr6->sin6_port;

		if (access_request == LANDLOCK_ACCESS_NET_CONNECT_TCP) {
			audit_net.dport = port;
			audit_net.v6info.daddr = addr6->sin6_addr;
		} else if (access_request == LANDLOCK_ACCESS_NET_BIND_TCP) {
			audit_net.sport = port;
			audit_net.v6info.saddr = addr6->sin6_addr;
		} else {
			WARN_ON_ONCE(1);
		}
		break;
	}
#endif /* IS_ENABLED(CONFIG_IPV6) */

	default:
		return 0;
	}

	/*
	 * Checks sa_family consistency to not wrongfully return
	 * -EACCES instead of -EINVAL.  Valid sa_family changes are
	 * only (from AF_INET or AF_INET6) to AF_UNSPEC.
	 *
	 * We could return 0 and let the network stack handle this
	 * check, but it is safer to return a proper error and test
	 * consistency thanks to kselftest.
	 */
	if (address->sa_family != sock->sk->__sk_common.skc_family &&
	    address->sa_family != AF_UNSPEC)
		return -EINVAL;

	id.key.data = (__force uintptr_t)port;
	BUILD_BUG_ON(sizeof(port) > sizeof(id.key.data));

	rule = landlock_find_rule(subject->domain, id);
	access_request = landlock_init_layer_masks(subject->domain,
						   access_request, &layer_masks,
						   LANDLOCK_KEY_NET_PORT);
	if (!access_request)
		return 0;

	if (landlock_unmask_layers(rule, &layer_masks, &rule_flags))
		return 0;

	/*
	 * Supervisee ruleset denied access.  Check if supervisor rulesets
	 * for the denying layers allow this access.
	 * For network checks, we pass NULL for the cache since it's a
	 * single-point check (no pathwalk), so atomicity is not a concern.
	 */
	scoped_guard(rcu)
	{
		if (landlock_check_supervisor_access(subject->domain, id,
						     &layer_masks, &rule_flags,
						     NULL))
			return 0;
	}

	audit_net.family = address->sa_family;

	/* Check if we should notify a supervisor instead of denying. */
	if (!landlock_check_notify_net(subject->domain, &layer_masks,
				       &rule_flags, access_request,
				       ntohs(port)))
		return restart_syscall();

	landlock_log_denial(
		subject,
		&(struct landlock_request){ .type = LANDLOCK_REQUEST_NET_ACCESS,
					    .audit.type = LSM_AUDIT_DATA_NET,
					    .audit.u.net = &audit_net,
					    .access = access_request,
					    .layer_masks = &layer_masks,
					    .rule_flags = rule_flags });
	return -EACCES;
}

static int hook_socket_bind(struct socket *const sock,
			    struct sockaddr *const address, const int addrlen)
{
	access_mask_t access_request;

	if (sk_is_tcp(sock->sk))
		access_request = LANDLOCK_ACCESS_NET_BIND_TCP;
	else
		return 0;

	return current_check_access_socket(sock, address, addrlen,
					   access_request);
}

static int hook_socket_connect(struct socket *const sock,
			       struct sockaddr *const address,
			       const int addrlen)
{
	access_mask_t access_request;

	if (sk_is_tcp(sock->sk))
		access_request = LANDLOCK_ACCESS_NET_CONNECT_TCP;
	else
		return 0;

	return current_check_access_socket(sock, address, addrlen,
					   access_request);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(socket_bind, hook_socket_bind),
	LSM_HOOK_INIT(socket_connect, hook_socket_connect),
};

__init void landlock_add_net_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}
