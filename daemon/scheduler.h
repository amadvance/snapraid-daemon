// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __SCHEDULER_H
#define __SCHEDULER_H

#include "state.h"

/****************************************************************************/
/* scheduler */

/**
 * Initialize the scheduler system.
 * @param state Current snapraid state
 */
void scheduler_init(struct snapraid_state* state);

/**
 * Cleanup the scheduler system.
 * @param state Current snapraid state
 */
void scheduler_done(struct snapraid_state* state);

/**
 * Trigger a scheduler check.
 * @param state Current snapraid state
 */
void scheduler_pulse(struct snapraid_state* state);

/**
 * Schedule a maintenance operation (sync followed by optional scrub).
 * @param state Current snapraid state
 * @param spindown 1 to spindown disks after completion, 0 otherwise
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_maintenance(struct snapraid_state* state, int spindown, char* msg, size_t msg_size, int* status);

/**
 * Schedule a heal operation (fix errors).
 * @param state Current snapraid state
 * @param spindown 1 to spindown disks after completion, 0 otherwise
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_heal(struct snapraid_state* state, int spindown, char* msg, size_t msg_size, int* status);

/**
 * Schedule an undelete operation.
 * @param state Current snapraid state
 * @param spindown 1 to spindown disks after completion, 0 otherwise
 * @param filter_list List of filters for undelete
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_undelete(struct snapraid_state* state, int spindown, sl_t* filter_list, char* msg, size_t msg_size, int* status);

/**
 * Schedule a spindown of idle disks.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_suspend_idle(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

/**
 * Schedule a refresh.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_refresh(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

/**
 * Schedule a custom sequence of commands.
 * @param state Current snapraid state
 * @param scheds List of schedule entries
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 */
void schedule_commands(struct snapraid_state* state, tommy_list* scheds, char* msg, size_t msg_size, int* status);

#endif

