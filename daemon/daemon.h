// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __DAEMON_H
#define __DAEMON_H

/****************************************************************************/
/* os */

/**
 * Find the SnapRAID binary in the system.
 * @return Path to SnapRAID binary, or NULL if not found
 */
const char* os_find_engine(const char* sys_engine);

/**
 * Default paths.
 */
void os_default_log(char* dst, size_t dst_size);
void os_default_conf(char* dst, size_t dst_size);
void os_default_data(char* dst, size_t dst_size, const char* root);

/**
 * Get the os_tick counter value in seconds.
 */
uint64_t os_tick_sec(void);

/**
 * Abort the process with a stacktrace.
 */
void os_abort(void) __noreturn;

/*
 * Wait for the child process to terminate.
 */
int os_wait(pid_t pid, int* status);

/**
 * Terminate gracefully a process.
 */
int os_term(pid_t pid);

/**
 * Spawn a new process with the specified argument vector.
 * @param argv Array of command line arguments
 * @param stderr_fd Pointer to store file descriptor for stderr
 * @return Process ID of spawned process
 */
pid_t os_spawn(char** argv, int* stderr_fd);

/**
 * Execute a system command with optional user context and input.
 * @param command Command to execute
 * @param run_as_user User to run command as (NULL for current user)
 * @param stdin_text Text to provide as stdin (NULL for no input)
 * @return Exit status of command
 */
int os_command(const char* command, const char* run_as_user, const char* stdin_text);

/**
 * Execute a script file with specified user context.
 * @param argv Array of command line arguments
 * @param run_as_user User to run script as (NULL for current user)
 * @return Exit status of script
 */
int os_script(char** argv, const char* run_as_user);

/**
 * Gather static system information.
 * @param system Pointer to system structure to populate
 */
void os_system(struct snapraid_system* system);

/**
 * Refresh dynamic system information (uptime, memory).
 * @param system Pointer to system structure to update
 */
void os_system_refresh(struct snapraid_system* system);

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

