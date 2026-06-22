// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __APP_H
#define __APP_H

#include "state.h"

/****************************************************************************/
/* app */

#define DAEMON_NAME "snapraidd"

/**
 * Find the SnapRAID binary in the system.
 * @return Path to SnapRAID binary, or NULL if not found
 */
const char* app_find_engine(const char* sys_engine);

/**
 * Find the curl binary in the system.
 * @return Path to curl binary, or NULL if not found
 */
const char* app_find_curl(void);

/**
 * Find the docker binary in the system.
 * @return Path to docker binary, or NULL if not found
 */
const char* app_find_docker(void);

/**
 * Find the poweroff binary in the system.
 * @return Path to poweroff binary, or 0 if not found
 */
const char* app_find_poweroff(void);

/**
 * Default paths.
 */
void app_default_log(char* dst, size_t dst_size);
void app_default_conf(char* dst, size_t dst_size);
void app_default_data(char* dst, size_t dst_size, const char* root);

/**
 * Gather static system information.
 * @param system Pointer to system structure to populate
 */
void app_system_info(struct snapraid_system* system);

/**
 * Refresh dynamic system information (uptime, memory).
 * @param system Pointer to system structure to update
 */
void app_system_refresh(struct snapraid_system* system);

/**
 * Set the instance
 */
void app_instance(const char* instance);

/****************************************************************************/
/* daemon */

/**
 * Process the arguments
 */
void daemon_options(struct snapraid_state* state, int argc, char* argv[]);

/**
 * Initialize the daemon
 */
int daemon_init(struct snapraid_state* state);

/**
 * Run the daemon
 */
void daemon_run(struct snapraid_state* state);

/**
 * Deinitialize the daemon
 */
void daemon_done(struct snapraid_state* state);

#endif

