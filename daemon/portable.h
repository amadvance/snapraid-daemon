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
 * Enable the rand_s() function.
 */
#define _CRT_RAND_S

/**
 * Undef as it clashes with windows.h declarations
 */
#undef DATADIR

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

#if HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif

#if HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#if HAVE_ZLIB
#include <zlib.h>
#endif

#if HAVE_ZSTD
#include <zstd.h>
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
 * Includes specific support for Windows or Linux.
 */
#ifdef __MINGW32__
#include "mingw.h"
#else
#include "unix.h"
#endif

/****************************************************************************/
/* app */

#define DAEMON "snapraidd"

#endif

