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

#ifndef __RUNNER_H
#define __RUNNER_H

#include "state.h"

/****************************************************************************/
/* runner */

/**
 * Initialize the runner system.
 * @param state Current snapraid state
 */
void runner_init(struct snapraid_state* state);

/**
 * Cleanup the runner system.
 * @param state Current snapraid state
 */
void runner_done(struct snapraid_state* state);

/**
 * Get command name string for command ID.
 * @param cmd Command ID
 * @return Command name string
 */
const char* runner_cmd(int cmd);

/**
 * Execute a SnapRAID command with arguments.
 * @param state Current snapraid state
 * @param cmd Command ID to execute
 * @param arg_list List of command arguments
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of command
 */
int runner(struct snapraid_state* state, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status);
int runner_locked(struct snapraid_state* state, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status);

/**
 * Delete old log files.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of operation
 */
int runner_delete_old_log(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

/**
 * Delete old history entries.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of operation
 */
int runner_delete_old_history(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

/**
 * Stop the current running task.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @param pid Pointer to store the stopped PID
 * @param number Pointer to store the stopped task number
 * @return Exit status of operation
 */
int runner_stop(struct snapraid_state* state, char* msg, size_t msg_size, int* status, pid_t* pid, int* number);

#endif

