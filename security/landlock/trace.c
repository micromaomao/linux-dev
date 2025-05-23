// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Tracepoints
 *
 * Copyright © 2025 Microsoft Corporation
 */

#include <linux/path.h>

#include "access.h"
#include "domain.h"
#include "ruleset.h"

#define CREATE_TRACE_POINTS
#include <trace/events/landlock.h>
