// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#ifndef __VERSION_H
#define __VERSION_H

#include "state.h"

/**
 * Encode a version string in the format HIGH.LOW[betaNUMBER|rcNUMBER] into a 32-bit unsigned integer.
 * Release versions compare higher than rc versions, which compare higher than beta versions.
 * The second dot and everything after it are ignored.
 * Returns 0 if the version string is invalid.
 */
uint32_t version_encode(const char* v);

/**
 * Compare two version strings.
 * Returns -1 if a < b, 1 if a > b, and 0 if a == b.
 */
int version_cmp(const char* a, const char* b);

/**
 * Check if a new version of the daemon or engine is available upstream.
 * Requires state_lock to be held.
 */
int version_update_available_locked(const struct snapraid_state* state);

/**
 * Check if a new SnapRAID Daemon version is available upstream.
 * Queries the GitHub API, parses the release tag, and updates global state.
 */
int version_check_locked_yield(struct snapraid_state* state);

#endif

