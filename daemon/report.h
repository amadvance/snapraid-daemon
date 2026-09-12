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
 * @param latest_report Pointer to the report task
 * @param latest_start Pointer to the start notification task, or 0 if none was scheduled
 * @param latest_fix Pointer to the latest fix task
 * @param latest_sync Pointer to the latest sync task
 * @param latest_scrub Pointer to the latest scrub task
 * @param diff_stat Pointer to difference statistics
 * @param fix_stat Pointer to fix statistics representing array repair status since latest sync
 */
void report_locked(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_report, struct snapraid_task* latest_start, struct snapraid_task* latest_fix, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub, struct snapraid_diff_stat* diff_stat, struct snapraid_fix_stat* fix_stat);

/**
 * Generate a narrow text report (suitable for small screens).
 * @param state Current snapraid state
 * @param ss String stream to write the report to
 * @param latest_report Pointer to the report task
 * @param latest_start Pointer to the start notification task, or 0 if none was scheduled
 * @param latest_fix Pointer to the latest fix task
 * @param latest_sync Pointer to the latest sync task
 * @param latest_scrub Pointer to the latest scrub task
 * @param diff_stat Pointer to difference statistics
 * @param fix_stat Pointer to fix statistics representing array repair status since latest sync
 */
void report_narrow_locked(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_report, struct snapraid_task* latest_start, struct snapraid_task* latest_fix, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub, struct snapraid_diff_stat* diff_stat, struct snapraid_fix_stat* fix_stat);

#endif

