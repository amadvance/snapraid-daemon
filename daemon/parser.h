// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __PARSER_H
#define __PARSER_H

#include "state.h"

/****************************************************************************/
/* parser */

/**
 * Parse SnapRAID log file and update state accordingly.
 * @param state Current snapraid state
 * @param f File descriptor of log file
 * @param log_f FILE pointer of log file
 * @param log_path Path to log file
 */
void parse_log(struct snapraid_state* state, int f, FILE* log_f, const char* log_path);

/**
 * Parse a timestamp from a file name in the format YYMMDD-HHMMSS-*
 * @return 0 on success, -1 on error
 */
int parse_timestamp(const char* name, time_t* out);

/**
 * Parse past log files to populate the history
 * @return 0 on success, -1 on error
 */
int parse_past_log(struct snapraid_state* state);

/**
 * Start disks mapping.
 */
void parser_mapping_start(struct snapraid_state* state);

/**
 * Conclude disks mapping.
 */
void parser_mapping_done(struct snapraid_state* state, struct snapraid_task* task);

#endif

