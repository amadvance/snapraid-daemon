// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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

