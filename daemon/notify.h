/*
 * Copyright (C) 2025 Andrea Mazzoleni
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

#ifndef __NOTIFY_H
#define __NOTIFY_H

#include "state.h"

/****************************************************************************/
/* notify */

/**
 * Handle array notifications (syslog, webhooks, heartbeats).
 * @param state Current snapraid state
 * @param high_cmd High-level command ID
 * @param report_level Importance level of the report
 * @param report_text Textual content of the report
 * @return 0 on success
 */
int notify_locked(struct snapraid_state* state, int high_cmd, int report_level, const char* report_text);

#endif

