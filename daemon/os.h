// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#ifndef __OS_H
#define __OS_H

/****************************************************************************/
/* signal */

/**
 * Enable or disable signal handling.
 * @param enable 1 to enable signals, 0 to disable
 */
void os_signal_set(int enable);

/**
 * Initialize signal handling.
 */
void os_signal_init(void (*handler_term)(int sig), void (*handler_hup)(int sig));

/**
 * Restore signal handlers after fork in child process.
 * This resets signals to default handling.
 */
void os_signal_restore_after_fork(void);

/****************************************************************************/
/* os */

/**
 * Initializes the system.
 */
void os_init(void);

/**
 * Deinitializes the system.
 */
void os_done(void);

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
 * Spawn a new process with the specified argument vector, optionally capturing stdout and/or stderr.
 * @param argv Array of command line arguments
 * @param stdout_read_fd Pointer to store file descriptor for stdout, or NULL to redirect to /dev/null
 * @param stderr_read_fd Pointer to store file descriptor for stderr, or NULL to redirect to /dev/null
 * @return Process ID of spawned process, or -1 on failure
 */
pid_t os_spawn(char** argv, int* stdout_read_fd, int* stderr_read_fd, const char* run_as_user);

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
 * @param envp Environment variables (NULL-terminated list of strings)
 * @param run_as_user User to run script as (NULL for current user)
 * @return Exit status of script
 */
int os_script(char** argv, char** envp, const char* run_as_user);

/**
 * Shutdown the system.
 * @return 0 on success, -1 on failure
 */
int os_shutdown(void);

/**
 * Fill memory with pseudo-random values
 */
int os_randomize(void* ptr, size_t size);

#endif

