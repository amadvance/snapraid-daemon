// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __SMART_H
#define __SMART_H

#include "state.h"
#include "support.h"

/****************************************************************************/
/* smart */

#define SMART_KIND_PULSE 0x01 /**< Needs a pulse when it changes */
#define SMART_KIND_CRITICAL 0x02 /**< It's a CRITICAL attribute (most PREFAIL but not necessarely) */
#define SMART_KIND_COUNT 0x04 /**< It's a event counter */
#define SMART_KIND_TEMP 0x08 /**< It's a temperature measure in celsius */
#define SMART_KIND_SIZE 0x10 /**< It's a size measure */
#define SMART_KIND_TIME 0x20 /**< It's a time measure (to be converted to seconds considerign the unit) */
#define SMART_KIND_USE_RATIO 0x40 /**< It's a percentage measure from 0 to 100 */
#define SMART_KIND_LIFE_RATIO 0x80 /**< It's a percentage measure from 100 to 0 */
#define SMART_KIND_VENDOR 0x100 /**< It's a vendor specific value */
#define SMART_KIND_NORM 0x200 /**< It's a norm value */

/**
 * Convert a raw SMART value based on its kind.
 * @param raw Raw SMART attribute value
 * @param kind Attribute kind (one of SMART_KIND_* combined with one of FORMAT_*)
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
 * @param temp Pointer to store current temperature. Set to SMART_UNASSIGNED if unknown.
 * @param temp_min Pointer to store minimum temperature. Set to SMART_UNASSIGNED if unknown.
 * @param temp_max Pointer to store maximum temperature. Set to SMART_UNASSIGNED if unknown.
 */
void smart_temperature_range(struct snapraid_device* dev, uint64_t* temp, uint64_t* temp_min, uint64_t* temp_max);

/**
 * Output a tracked metric as a JSON object.
 * @param s String stream for output
 * @param level JSON indentation level
 * @param name Metric name
 * @param tracked Tracked metric structure
 * @param kind Attribute kind (one of SMART_KIND_* combined with one of FORMAT_*)
 */
void json_tracked(ss_t* s, int level, const char* name, struct snapraid_tracked* tracked, int kind);

/**
 * Output all SMART attributes of a device as a JSON list.
 * @param s String stream for output
 * @param level JSON indentation level
 * @param dev Device structure
 */
void json_smart_list(struct snapraid_state* state, const char* disk_name, ss_t* s, int level, struct snapraid_device* dev);

#endif

