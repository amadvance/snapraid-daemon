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

#ifndef __CONFIG_H
#define __CONFIG_H

#include "state.h"

/****************************************************************************/
/* config */

/**
 * Parse log level string to numeric value.
 * @param input Input string to parse ("critical", "error", "warning", "info")
 * @param out Pointer to store numeric log level
 * @return 0 on success, -1 on error
 */
int config_parse_level(const char* input, int* out);

/**
 * Parse scheduled_run string.
 * Format supported: "daily HH:MM" or "weekly <day> HH:MM"
 * @param input Input string to parse
 * @param config Configuration to update with parsed values
 * @return 0 on success, -1 on error
 */
int config_parse_scheduled_run(const char* input, struct snapraid_config* config);

/**
 * Get string representation of log level.
 * @param level Log level value
 * @return String representation
 */
const char* config_level_str(int level);

/**
 * Get string representation of schedule configuration.
 * @param config Configuration to read
 * @param buf Buffer to store result
 * @param size Size of buffer
 */
void config_schedule_str(const struct snapraid_config* config, char* buf, size_t size);

/**
 * Initialize configuration with defaults.
 * @param config Configuration to initialize
 * @param argv0 Program name for defaults
 */
void config_init(struct snapraid_config* config, const char* argv0);

/**
 * Load configuration from file.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int config_load(struct snapraid_state* state);

/**
 * Reload configuration from file.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int config_reload(struct snapraid_state* state);

/**
 * Save configuration to file.
 * @param config Configuration to save
 * @return 0 on success, -1 on error
 */
int config_save(struct snapraid_config* config);

/**
 * Set string configuration value.
 * @param config Configuration to modify
 * @param key Configuration key name
 * @param new_value New value to set
 */
void config_set_string(struct snapraid_config* config, const char* key, char* new_value);

/**
 * Set integer configuration value.
 * @param config Configuration to modify
 * @param key Configuration key name
 * @param new_value New value to set
 */
void config_set_int(struct snapraid_config* config, const char* key, int new_value);

#endif

