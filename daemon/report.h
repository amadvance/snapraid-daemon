/*
 * Copyright (C) 2026 Andrea Mazzoleni
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __REPORT_H
#define __REPORT_H

#include "state.h"
#include "support.h"

/**
 * Generate a text report containing the result of the latest sync and scrub tasks.
 *
 * @param state Pointer to the global snapraid state
 * @param ss String stream to write the report to
 * @param latest_sync Pointer to the latest sync task, or NULL if not available
 * @param latest_scrub Pointer to the latest scrub task, or NULL if not available
 * @return 0 on success, -1 on error
 */
int report(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub);

#endif

