// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#ifndef __VERSION_H
#define __VERSION_H

#include "state.h"

/**
 * Check if a new SnapRAID Daemon version is available upstream.
 * Queries the GitHub API, parses the release tag, and updates global state.
 */
int version_check(struct snapraid_state* state);

#endif

