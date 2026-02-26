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

#define SMART_KIND_PULSE 0x01 /**< Needs a pulse when it changes */
#define SMART_KIND_PREFAIL 0x02 /**< It's a PREFAIL attribute, otherwise OLDAGE */
#define SMART_KIND_TEMP 0x08 /**< It's a temperature measure */
#define SMART_KIND_SIZE 0x10 /**< It's a size measure */
#define SMART_KIND_TIME 0x20 /**< It's a time measure */
#define SMART_KIND_PERC 0x40 /**< It's a percentage measure */
#define SMART_KIND_COUNT 0x80 /**< It's a counter measure (NOT USED BEING THE DEFAULT) */

/**
 * Convert a raw SMART value based on its kind.
 * @param raw Raw SMART attribute value
 * @param kind Attribute kind (one of SMART_KIND_*)
 * @return Normalized numeric value
 */
uint64_t smart_conv(uint64_t raw, int kind);

/**
 * Identify the kind of SMART attribute by its index and name.
 * @param index SMART attribute ID
 * @param name SMART attribute name
 * @return Attribute kind flags
 */
int smart_kind(int index, const char* name);

/**
 * Extract historic temperature extremes from SMART attributes.
 * @param dev Device structure to analyze
 * @param temp Pointer to store current temperature
 * @param temp_min Pointer to store minimum temperature
 * @param temp_max Pointer to store maximum temperature
 */
void smart_temperature_range(struct snapraid_device* dev, uint64_t* temp, uint64_t* temp_min, uint64_t* temp_max);

/**
 * Output a tracked metric as a JSON object.
 * @param s String stream for output
 * @param level JSON indentation level
 * @param name Metric name
 * @param tracked Tracked metric structure
 * @param kind Attribute kind
 */
void json_tracked(ss_t* s, int level, const char* name, struct snapraid_tracked* tracked, int kind);

/**
 * Output all SMART attributes of a device as a JSON list.
 * @param s String stream for output
 * @param level JSON indentation level
 * @param dev Device structure
 */
void json_smart_list(ss_t* s, int level, struct snapraid_device* dev);

#endif

