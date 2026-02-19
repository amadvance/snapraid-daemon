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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SMART_H
#define __SMART_H

#include "state.h"
#include "support.h"

/****************************************************************************/
/* smart */


#define SMART_KIND_PREFAIL 1
#define SMART_KIND_INFO 2
#define SMART_KIND_TEMP 4
#define SMART_KIND_PULSE 8

/**
 * Get SMART_KIND_* flags. 0 if none
 */
int smart_kind(int index, const char* name);

/**
 * Get the historic temperature range from SMART attributes
 */
void smart_temperature_range(struct snapraid_device* dev, uint64_t* temp, uint64_t* temp_min, uint64_t* temp_max);

/**
 * Output smart attributes in JSON format
 */
void json_smart_list(ss_t* s, int level, struct snapraid_device* dev);

#endif

