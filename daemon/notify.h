// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __NOTIFY_H
#define __NOTIFY_H

#include "state.h"

/****************************************************************************/
/* notify */

/**
 * Handle task start notifications.
 * @param state Current snapraid state
 * @param high_cmd High-level command ID
 * @return 0 on success
 */
int notify_start_locked_yield(struct snapraid_state* state, int high_cmd);

/**
 * Handle array notifications (syslog, webhooks, heartbeats).
 * @param state Current snapraid state
 * @param high_cmd High-level command ID
 * @param report_level Importance level of the report
 * @param report_text Textual content of the report
 * @return 0 on success
 */
int notify_result_locked_yield(struct snapraid_state* state, int high_cmd, int report_level, int exit_code, const char* report_text);

#endif

