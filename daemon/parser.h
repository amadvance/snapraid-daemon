// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __PARSER_H
#define __PARSER_H

#include "state.h"
#include "zio.h"

/****************************************************************************/
/* parser */

/**
 * Parse SnapRAID log file and update state accordingly.
 * @param state Current snapraid state
 * @param fd File descriptor of the input log file (if f is 0)
 * @param f ZFILE stream of the input log file (if not 0)
 * @param log_f ZFILE pointer of the output log file
 * @param log_path Path to the output log file
 */
int parse_log(struct snapraid_state* state, int fd, ZFILE* f, ZFILE* log_f, const char* log_path);

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
 * Start the parsing
 */
void parse_begin_locked(struct snapraid_state* state);

/**
 * End the parsing
 */
void parse_end_locked(struct snapraid_state* state, struct snapraid_task* task);

#endif

