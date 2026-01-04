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
 * @param cat_log_path Path to concatenated log file
 */
void parse_log(struct snapraid_state* state, int f, const char* cat_log_path);

#endif

