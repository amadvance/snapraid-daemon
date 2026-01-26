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

#ifndef __DAEMON_H
#define __DAEMON_H

/****************************************************************************/
/* daemon */

/**
 * OS specific
 */

/**
 * Spawn a new process with the specified argument vector.
 * @param argv Array of command line arguments
 * @param stderr_fd Pointer to store file descriptor for stderr
 * @return Process ID of spawned process
 */
pid_t daemon_spawn(char** argv, int* stderr_fd);

/**
 * Execute a system command with optional user context and input.
 * @param command Command to execute
 * @param target_user User to run command as (NULL for current user)
 * @param stdin_text Text to provide as stdin (NULL for no input)
 * @return Exit status of command
 */
int daemon_command(const char* command, const char* target_user, const char* stdin_text);

/**
 * Execute a script file with specified user context.
 * @param script_path Path to script file
 * @param run_as_user User to run script as (NULL for current user)
 * @return Exit status of script
 */
int daemon_script(const char* script_path, const char* run_as_user);

/**
 * Initialize signal handling for the daemon.
 */
void daemon_signal_init(void);

/**
 * Enable or disable signal handling.
 * @param enable 1 to enable signals, 0 to disable
 */
void daemon_signal_set(int enable);

/**
 * Daemonize the current process.
 * @return The PID file descriptor on success, -1 on error
 */
int daemon_daemonize(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg);

/**
 * Restore signal handlers after fork in child process.
 * This resets signals to default handling for the daemon.
 */
void daemon_signal_restore_after_fork(void);

#endif

