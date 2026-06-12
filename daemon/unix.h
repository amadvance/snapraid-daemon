// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2011 Andrea Mazzoleni

#ifndef __UNIX_H
#define __UNIX_H

#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#define FOPEN_CLOEXEC "e"
#define FOPEN_TEXT ""

#define O_BINARY 0 /**< Not used in Unix. */
#define O_SEQUENTIAL 0 /**< In Unix posix_fadvise() shall be used. */

#define SYSLOG "syslog"

#if !HAVE_EACCESS
/**
 * Check effective user's permissions for a file.
 * Conceptually identical to access(), but uses the effective UID/GID.
 */
int eaccess(const char* pathname, int mode);
#endif

/****************************************************************************/
/* thread */

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#if HAVE_PTHREAD
#define HAVE_THREAD 1
typedef pthread_t thread_id_t;
typedef pthread_mutex_t thread_mutex_t;
typedef pthread_cond_t thread_cond_t;
typedef pthread_rwlock_t thread_rwlock_t;
#endif

#endif

