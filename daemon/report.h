// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#ifndef __REPORT_H
#define __REPORT_H

#include "state.h"
#include "support.h"

/**
 * Generate a text report containing the result of the latest tasks.
 * @param state Current snapraid state
 * @param ss String stream to write the report to
 * @param latest_fix Pointer to the latest fix task
 * @param latest_sync Pointer to the latest sync task
 * @param latest_scrub Pointer to the latest scrub task
 * @param diff_stat Pointer to difference statistics
 */
void report_locked(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_report, struct snapraid_task* latest_fix, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub, struct snapraid_diff_stat* diff_stat);

/**
 * Generate a narrow text report (suitable for small screens).
 * @param state Current snapraid state
 * @param ss String stream to write the report to
 * @param latest_fix Pointer to the latest fix task
 * @param latest_sync Pointer to the latest sync task
 * @param latest_scrub Pointer to the latest scrub task
 * @param diff_stat Pointer to difference statistics
 */
void report_narrow_locked(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_report, struct snapraid_task* latest_fix, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub, struct snapraid_diff_stat* diff_stat);

#endif

