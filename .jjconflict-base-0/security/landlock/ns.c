// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Namespace hooks
 *
 * Copyright © 2026 Cloudflare, Inc.
 */

#include <linux/lsm_audit.h>
#include <linux/lsm_hooks.h>
#include <linux/ns/ns_common_types.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <uapi/linux/landlock.h>

#include "audit.h"
#include "cred.h"
#include "limits.h"
#include "ns.h"
#include "ruleset.h"
#include "setup.h"

/* Ensures the audit ns_id field can hold ns_common.ns_id without truncation. */
static_assert(sizeof(((struct common_audit_data *)NULL)->u.ns.ns_id) >=
	      sizeof(((struct ns_common *)NULL)->ns_id));

static const struct access_masks ns_perm = {
	.perm = LANDLOCK_PERM_NAMESPACE_USE,
};

/**
 * check_ns_type - Check namespace entry permission
 *
 * @ns: The namespace being allocated or installed.
 *
 * Shared check for namespace_init (creation via unshare(2) or clone(2)) and
 * namespace_install (entry via setns(2)): denies when the namespace type is not
 * in the domain's allowed set.  At allocation time @ns->ns_id is still zero and
 * is logged as such.
 *
 * Return: 0 if allowed, -EPERM if denied.
 */
static int check_ns_type(struct ns_common *const ns)
{
	const struct landlock_cred_security *subject;
	size_t denied_layer;

	subject =
		landlock_get_applicable_subject(current_cred(), ns_perm, NULL);
	if (!subject)
		return 0;

	denied_layer = landlock_perm_is_denied(
		subject->domain, LANDLOCK_PERM_NAMESPACE_USE,
		landlock_ns_type_to_bit(ns->ns_type));
	if (!denied_layer)
		return 0;

	landlock_log_denial(subject, &(struct landlock_request){
					     .type = LANDLOCK_REQUEST_NAMESPACE,
					     .audit.type = LSM_AUDIT_DATA_NS,
					     .audit.u.ns.ns_type = ns->ns_type,
					     .audit.u.ns.ns_id = ns->ns_id,
					     .layer_plus_one = denied_layer,
				     });
	return -EPERM;
}

static int hook_namespace_init(struct ns_common *const ns)
{
	return check_ns_type(ns);
}

static int hook_namespace_install(const struct nsset *const nsset,
				  struct ns_common *const ns)
{
	return check_ns_type(ns);
}

static struct security_hook_list landlock_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(namespace_init, hook_namespace_init),
	LSM_HOOK_INIT(namespace_install, hook_namespace_install),
};

__init void landlock_add_ns_hooks(void)
{
	security_add_hooks(landlock_hooks, ARRAY_SIZE(landlock_hooks),
			   &landlock_lsmid);
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

#include <kunit/test.h>

/* clang-format off */
#define _TEST_NS_BIT(struct_name, flag) \
	do { \
		const u64 bit = landlock_ns_type_to_bit(flag); \
		KUNIT_EXPECT_NE(test, 0ULL, bit); \
		KUNIT_EXPECT_EQ(test, 0ULL, seen & bit); \
		seen |= bit; \
	} while (0);
/* clang-format on */

static void test_ns_type_to_bit(struct kunit *const test)
{
	u64 seen = 0;

	FOR_EACH_NS_TYPE(_TEST_NS_BIT)

	KUNIT_EXPECT_EQ(test, GENMASK_ULL(LANDLOCK_NUM_PERM_NS - 1, 0), seen);
}

static void test_ns_type_to_bit_unknown(struct kunit *const test)
{
	KUNIT_EXPECT_EQ(test, 0ULL, landlock_ns_type_to_bit(CLONE_THREAD));
}

static void test_ns_types_to_bits_all(struct kunit *const test)
{
	KUNIT_EXPECT_EQ(test, GENMASK_ULL(LANDLOCK_NUM_PERM_NS - 1, 0),
			landlock_ns_types_to_bits(CLONE_NS_ALL));
}

/* clang-format off */
#define _TEST_NS_SINGLE(struct_name, flag) \
	KUNIT_EXPECT_EQ(test, landlock_ns_type_to_bit(flag), \
			landlock_ns_types_to_bits(flag));
/* clang-format on */

static void test_ns_types_to_bits_single(struct kunit *const test)
{
	FOR_EACH_NS_TYPE(_TEST_NS_SINGLE)
}

static void test_ns_types_to_bits_zero(struct kunit *const test)
{
	KUNIT_EXPECT_EQ(test, 0ULL, landlock_ns_types_to_bits(0));
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE(test_ns_type_to_bit),
	KUNIT_CASE(test_ns_type_to_bit_unknown),
	KUNIT_CASE(test_ns_types_to_bits_all),
	KUNIT_CASE(test_ns_types_to_bits_single),
	KUNIT_CASE(test_ns_types_to_bits_zero),
	{}
};

static struct kunit_suite test_suite = {
	.name = "landlock_ns",
	.test_cases = test_cases,
};

kunit_test_suite(test_suite);

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */
