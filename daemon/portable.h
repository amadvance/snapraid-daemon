/*
 * Copyright (C) 2011 Andrea Mazzoleni
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

#ifndef __PORTABLE_H
#define __PORTABLE_H

#if HAVE_CONFIG_H
#include "config.h" /* Use " to include first in the same directory of this file */
#endif

/***************************************************************************/
/* Config */

#ifdef __MINGW32__
/**
 * Enable the GNU printf functions instead of using the MSVCRT ones.
 *
 * Note that this is the default if _POSIX is also defined.
 * To disable it you have to set it to 0.
 */
#define __USE_MINGW_ANSI_STDIO 1

/**
 * Define the MSVCRT version targeting Windows Vista.
 */
#define __MSVCRT_VERSION__ 0x0600

/**
 * Include Windows Vista headers.
 *
 * Like for InitializeCriticalSection().
 */
#define _WIN32_WINNT 0x600

/**
 * Enable the rand_s() function.l
 */
#define _CRT_RAND_S

#include <windows.h>
#endif

/**
 * Specify the format attribute for printf.
 */
#ifdef __MINGW32__
#if defined(__USE_MINGW_ANSI_STDIO) && __USE_MINGW_ANSI_STDIO == 1
#define attribute_printf gnu_printf /* GNU format */
#else
#define attribute_printf ms_printf /* MSVCRT format */
#endif
#else
#define attribute_printf printf /* GNU format is the default one */
#endif

/**
 * Compiler extension
 */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif

/**
 * Includes some standard headers.
 */
#include <stdio.h>
#include <stdlib.h> /* On many systems (e.g., Darwin), `stdio.h' is a prerequisite. */
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#if HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)
#else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#if HAVE_NDIR_H
#include <ndir.h>
#endif
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_MKDEV
#include <sys/mkdev.h>
#endif

#if HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_MATH_H
#include <math.h>
#endif

#if HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#ifdef HAVE_STRINGS
#include <strings.h>
#endif

#if HAVE_SYSLOG_H
#include <syslog.h>
#endif

#if HAVE_GRP_H
#include <grp.h>
#endif

#if HAVE_PWD_H
#include <pwd.h>
#endif

/**
 * Enable thread use.
 */
#ifdef _WIN32
#define HAVE_THREAD 1
typedef void* windows_thread_t;
typedef CRITICAL_SECTION windows_mutex_t;
typedef CONDITION_VARIABLE windows_cond_t;
typedef void* windows_key_t;
/* remap to pthread */
#define thread_id_t windows_thread_t
#define thread_mutex_t windows_mutex_t
#define thread_cond_t windows_cond_t
#define pthread_mutex_init windows_mutex_init
#define pthread_mutex_destroy windows_mutex_destroy
#define pthread_mutex_lock windows_mutex_lock
#define pthread_mutex_unlock windows_mutex_unlock
#define pthread_cond_init windows_cond_init
#define pthread_cond_destroy windows_cond_destroy
#define pthread_cond_signal windows_cond_signal
#define pthread_cond_broadcast windows_cond_broadcast
#define pthread_cond_wait windows_cond_wait
#define pthread_create windows_create
#define pthread_join windows_join
#else
#if HAVE_PTHREAD_H
#include <pthread.h>
#endif
#if HAVE_PTHREAD_CREATE
#define HAVE_THREAD 1
typedef pthread_t thread_id_t;
typedef pthread_mutex_t thread_mutex_t;
typedef pthread_cond_t thread_cond_t;
#endif
#endif

#if HAVE_GETOPT_LONG
#define SWITCH_GETOPT_LONG(a, b) a
#else
#define SWITCH_GETOPT_LONG(a, b) b
#endif

#ifdef _WIN32
#include <string.h>
/* map Windows name to POSIX name */
#define strncasecmp _strnicmp
#endif

#ifdef HAVE_LINUX_CLOSE_RANGE_H
#include <linux/close_range.h>
#endif

/* implement close_range for glibc 2.33 or earlier */
#if defined(__linux__) && !defined(HAVE_CLOSE_RANGE)
#include <sys/syscall.h>
#ifndef __NR_close_range
#define __NR_close_range 436
#endif
#define close_range close_range_impl
static inline int close_range_impl(unsigned int first, unsigned int last, unsigned int flags)
{
	return syscall(__NR_close_range, first, last, flags);
}
#define HAVE_CLOSE_RANGE 1
#endif

/**
 * OS specific
 */

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
 * @param target_user User to run command as (NULL for current user)
 * @param stdin_text Text to provide as stdin (NULL for no input)
 * @return Exit status of command
 */
int os_command(const char* command, const char* target_user, const char* stdin_text);

/**
 * Execute a script file with specified user context.
 * @param script_path Path to script file
 * @param run_as_user User to run script as (NULL for current user)
 * @return Exit status of script
 */
int os_script(const char* script_path, const char* run_as_user);

/**
 * Initialize signal handling for the daemon.
 */
void os_signal_init(void);

/**
 * Enable or disable signal handling.
 * @param enable 1 to enable signals, 0 to disable
 */
void os_signal_set(int enable);

/**
 * Daemonize the current process.
 * @return 0 on success, -1 on error
 */
int os_daemonize(void);

/**
 * Restore signal handlers after fork in child process.
 * This resets signals to default handling for the daemon.
 */
void os_signal_restore_after_fork(void);

#endif
