/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Landlock scoped_domains variants with socket type
 *
 * Extends scoped_base_variants.h with abstract/pathname socket type parameter.
 *
 * Copyright © 2024 Tahera Fahimi <fahimitahera@gmail.com>
 * Copyright © 2025 Microsoft Corporation
 */

/* clang-format on */
FIXTURE_VARIANT(scoped_domains)
{
bool domain_both;
bool domain_parent;
bool domain_child;
enum socket_type socket_type;
};

/*
 * Abstract socket variants
 */

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_without_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = false,
.domain_child = false,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_child_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = false,
.domain_child = true,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_parent_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = true,
.domain_child = false,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_sibling_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = true,
.domain_child = true,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_inherited_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = false,
.domain_child = false,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_nested_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = false,
.domain_child = true,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_nested_and_parent_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = true,
.domain_child = false,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, abstract_forked_domains) {
/* clang-format on */
.domain_both = true,
.domain_parent = true,
.domain_child = true,
.socket_type = SOCKET_TYPE_ABSTRACT,
};

/*
 * Pathname socket variants
 */

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_without_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = false,
.domain_child = false,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_child_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = false,
.domain_child = true,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_parent_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = true,
.domain_child = false,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_sibling_domain) {
/* clang-format on */
.domain_both = false,
.domain_parent = true,
.domain_child = true,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_inherited_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = false,
.domain_child = false,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_nested_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = false,
.domain_child = true,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_nested_and_parent_domain) {
/* clang-format on */
.domain_both = true,
.domain_parent = true,
.domain_child = false,
.socket_type = SOCKET_TYPE_PATHNAME,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(scoped_domains, pathname_forked_domains) {
/* clang-format on */
.domain_both = true,
.domain_parent = true,
.domain_child = true,
.socket_type = SOCKET_TYPE_PATHNAME,
};
