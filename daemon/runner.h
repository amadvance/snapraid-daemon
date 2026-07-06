// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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
 * Execute a SnapRAID command with arguments in a new task.
 * @param state Current snapraid state
 * @param high_cmd High-level command ID
 * @param cmd SnapRAID command ID to execute
 * @param now Current timestamp
 * @param arg_list List of command arguments
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of command
 */
int runner(struct snapraid_state* state, int high_cmd, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status);

/**
 * Execute a SnapRAID command with state lock already held.
 * @param state Current snapraid state
 * @param high_cmd High-level command ID
 * @param cmd SnapRAID command ID to execute
 * @param now Current timestamp
 * @param arg_list List of command arguments
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of command
 */
int runner_locked(struct snapraid_state* state, int high_cmd, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status);

/**
 * Check if the specified command is currently running or scheduled in the queue.
 * @param state Current snapraid state
 * @param cmd Command ID
 * @return 1 if running/scheduled, 0 otherwise
 */
int runner_has_cmd_locked(struct snapraid_state* state, int cmd);

/**
 * Delete old log files.
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of operation
 */
int runner_delete_old_log_locked_yield(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

/**
 * Delete old history entries.
 *
 * This function will never delete the latest executed task (state->runner.latest).
 *
 * @param state Current snapraid state
 * @param msg Buffer for error message
 * @param msg_size Size of message buffer
 * @param status Pointer to store HTTP status code
 * @return Exit status of operation
 */
int runner_delete_old_history_locked(struct snapraid_state* state, char* msg, size_t msg_size, int* status);

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

