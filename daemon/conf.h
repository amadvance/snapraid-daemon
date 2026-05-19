// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __CONFIG_H
#define __CONFIG_H

#include "state.h"

/****************************************************************************/
/* config */

/**
 * Allocate a new configuration line entry.
 * @return Pointer to newly allocated line entry
 */
struct snapraid_config_line* config_line_alloc(void);

/**
 * Free a configuration line entry.
 * @param void_line Pointer to line entry to free
 */
void config_line_free(void* void_line);

/**
 * Parse log level string to numeric value.
 * @param input Input string to parse ("critical", "error", "warning", "info")
 * @param out Pointer to store numeric log level
 * @return 0 on success, -1 on error
 */
int config_parse_level(const char* input, int* out);

/**
 * Parse maintenance_schedule string.
 * Format supported: "HH:MM" or "<day> HH:MM"
 * @param input Input string to parse
 * @param config Configuration to update with parsed values
 * @return 0 on success, -1 on error
 */
int config_parse_maintenance_schedule(const char* input, struct snapraid_config* config);

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
void config_schedule_str(struct snapraid_config* config, char* buf, size_t size);

/**
 * Initialize configuration with defaults.
 * @param state Current snapraid state
 */
void config_init(struct snapraid_state* state);

/**
 * Free configuration.
 * @param state Current snapraid state
 */
void config_done(struct snapraid_state* state);

/**
 * Set a configuration to default values
 */
void config_default_locked(struct snapraid_state* state);

/**
 * Export the current configuration
 */
void config_dup_locked(struct snapraid_state* state, struct snapraid_config* config);

/**
 * Import a configuration to the state
 */
int config_apply_locked(struct snapraid_state* state, struct snapraid_config* config);

/**
 * Destroy a not imported configuration
 */
void config_free(struct snapraid_config* config);

/**
 * Load configuration from file.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int config_load_locked(struct snapraid_state* state);

/**
 * Reload configuration from file.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int config_reload_locked(struct snapraid_state* state);

/**
 * Save configuration to file.
 * @param config Configuration to save
 * @return 0 on success, -1 on error
 */
int config_save_locked(struct snapraid_state* state);

#endif

