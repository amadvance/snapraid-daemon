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

/****************************************************************************/
/* thread */

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#if HAVE_PTHREAD_CREATE
#define HAVE_THREAD 1
typedef pthread_t thread_id_t;
typedef pthread_mutex_t thread_mutex_t;
typedef pthread_cond_t thread_cond_t;
typedef pthread_rwlock_t thread_rwlock_t;
#endif

#endif

