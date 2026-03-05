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

