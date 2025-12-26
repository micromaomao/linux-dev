/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock scoped_domains variants
 *
 * See the hierarchy variants from ptrace_test.c
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 * Copyright © 2024 Tahera Fahimi <fahimitahera@gmail.com>
 */

/*
 * To use this file, define SCOPED_DOMAINS_FIXTURE_NAME before including it.
 * If not defined, it defaults to "scoped_domains".
 *
 * Optionally define SCOPED_DOMAINS_EXTRA_FIELDS for additional variant fields.
 * Optionally define SCOPED_DOMAINS_VARIANT_PREFIX for variant name prefix.
 * Optionally define SCOPED_DOMAINS_EXTRA_INIT for additional field initialization.
 * Define SCOPED_DOMAINS_SKIP_FIXTURE_VARIANT to skip FIXTURE_VARIANT definition
 * (useful when including this file multiple times with different prefixes).
 */
#ifndef SCOPED_DOMAINS_FIXTURE_NAME
#define SCOPED_DOMAINS_FIXTURE_NAME scoped_domains
#endif

#ifndef SCOPED_DOMAINS_EXTRA_FIELDS
#define SCOPED_DOMAINS_EXTRA_FIELDS
#endif

#ifndef SCOPED_DOMAINS_VARIANT_PREFIX
#define SCOPED_DOMAINS_VARIANT_PREFIX
#endif

#ifndef SCOPED_DOMAINS_EXTRA_INIT
#define SCOPED_DOMAINS_EXTRA_INIT
#endif

/* Helper macros for concatenation */
#define _SCOPED_CONCAT2(a, b) a##b
#define _SCOPED_CONCAT(a, b) _SCOPED_CONCAT2(a, b)

#ifndef SCOPED_DOMAINS_SKIP_FIXTURE_VARIANT
/* clang-format on */
FIXTURE_VARIANT(SCOPED_DOMAINS_FIXTURE_NAME)
{
	bool domain_both;
	bool domain_parent;
	bool domain_child;
	SCOPED_DOMAINS_EXTRA_FIELDS
};
#endif

/*
 *        No domain
 *
 *   P1-.               P1 -> P2 : allow
 *       \              P2 -> P1 : allow
 *        'P2
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, without_domain)) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = false,
	.domain_child = false,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *        Child domain
 *
 *   P1--.              P1 -> P2 : allow
 *        \             P2 -> P1 : deny
 *        .'-----.
 *        |  P2  |
 *        '------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, child_domain)) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = false,
	.domain_child = true,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *        Parent domain
 * .------.
 * |  P1  --.           P1 -> P2 : deny
 * '------'  \          P2 -> P1 : allow
 *            '
 *            P2
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, parent_domain)) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = true,
	.domain_child = false,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *        Parent + child domain (siblings)
 * .------.
 * |  P1  ---.          P1 -> P2 : deny
 * '------'   \         P2 -> P1 : deny
 *         .---'--.
 *         |  P2  |
 *         '------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, sibling_domain)) {
	/* clang-format on */
	.domain_both = false,
	.domain_parent = true,
	.domain_child = true,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *         Same domain (inherited)
 * .-------------.
 * | P1----.     |      P1 -> P2 : allow
 * |        \    |      P2 -> P1 : allow
 * |         '   |
 * |         P2  |
 * '-------------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, inherited_domain)) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = false,
	.domain_child = false,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *         Inherited + child domain
 * .-----------------.
 * |  P1----.        |  P1 -> P2 : allow
 * |         \       |  P2 -> P1 : deny
 * |        .-'----. |
 * |        |  P2  | |
 * |        '------' |
 * '-----------------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, nested_domain)) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = false,
	.domain_child = true,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *         Inherited + parent domain
 * .-----------------.
 * |.------.         |  P1 -> P2 : deny
 * ||  P1  ----.     |  P2 -> P1 : allow
 * |'------'    \    |
 * |             '   |
 * |             P2  |
 * '-----------------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, nested_and_parent_domain)) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = true,
	.domain_child = false,
	SCOPED_DOMAINS_EXTRA_INIT
};

/*
 *         Inherited + parent and child domain (siblings)
 * .-----------------.
 * | .------.        |  P1 -> P2 : deny
 * | |  P1  .        |  P2 -> P1 : deny
 * | '------'\       |
 * |          \      |
 * |        .--'---. |
 * |        |  P2  | |
 * |        '------' |
 * '-----------------'
 */
/* clang-format off */
FIXTURE_VARIANT_ADD(SCOPED_DOMAINS_FIXTURE_NAME, _SCOPED_CONCAT(SCOPED_DOMAINS_VARIANT_PREFIX, forked_domains)) {
	/* clang-format on */
	.domain_both = true,
	.domain_parent = true,
	.domain_child = true,
	SCOPED_DOMAINS_EXTRA_INIT
};

#undef SCOPED_DOMAINS_FIXTURE_NAME
#undef SCOPED_DOMAINS_EXTRA_FIELDS
#undef SCOPED_DOMAINS_VARIANT_PREFIX
#undef SCOPED_DOMAINS_EXTRA_INIT
#undef SCOPED_DOMAINS_SKIP_FIXTURE_VARIANT
#undef _SCOPED_CONCAT
#undef _SCOPED_CONCAT2
