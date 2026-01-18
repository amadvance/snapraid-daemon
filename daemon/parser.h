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

#endif

