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

#ifndef __SUPPORT_H
#define __SUPPORT_H

#include "tommyds/tommylist.h"

/****************************************************************************/
/* string stream */

typedef struct ss {
	char* ptr;
	ssize_t size;
	ssize_t len;
} ss_t;

void ss_init(struct ss* s, size_t size);
void ss_done(struct ss* s);
void ss_write(struct ss* s, const char* arg, size_t len);
void ss_prints(struct ss* s, const char* arg);
int ss_vprintf(struct ss* s, const char* fmt, va_list ap);
int ss_printf(struct ss* s, const char* fmt, ...)  __attribute__((format(attribute_printf, 2, 3)));
void ss_jsons(struct ss* s, int tab, const char* arg);
int ss_jsonf(struct ss* s, int tab, const char* fmt, ...)  __attribute__((format(attribute_printf, 3, 4)));

static inline ssize_t ss_len(struct ss* s)
{
	return s->len;
}

static inline char* ss_ptr(struct ss* s)
{
	return s->ptr;
}

void ss_reserve(struct ss* s, ssize_t needed);

static inline char* ss_top(struct ss* s)
{
	return s->ptr + s->len;
}

static inline void ss_forward(struct ss* s, size_t written)
{
	s->len += written;
}

static inline ssize_t ss_avail(struct ss* s)
{
	return s->size - s->len;
}

/****************************************************************************/
/* string list */

typedef struct sn {
	tommy_node node;
	char str[];
} sn_t;

static inline void sl_init(tommy_list* list)
{
	tommy_list_init(list);
}

static inline void sl_free(tommy_list* list)
{
	tommy_list_foreach(list, free);
}

void sl_insert_str(tommy_list* list, const char* add);
void sl_insert_list(tommy_list* list, tommy_list* add);
void sl_insert_int(tommy_list* list, int add);

/****************************************************************************/
/* string */

#ifndef HAVE_STRLCPY
size_t sncpy(char* dst, size_t dst_size, const char* src);
#else
static inline size_t sncpy(char* dst, size_t dst_size, const char* src)
{
	return strlcpy(dst, src, dst_size);
}
#endif

int strint(int* out, const char* src);
int struint(unsigned* out, const char* src);
int stri64(int64_t* out, const char* src);
int stru64(uint64_t* out, const char* src);
char* strtrim(char* str);

/****************************************************************************/
/* memory */

/**
 * Safe malloc.
 * If no memory is available, it aborts.
 */
void* malloc_nofail(size_t size);

/**
 * Safe calloc.
 * If no memory is available, it aborts.
 */
void* calloc_nofail(size_t count, size_t size);

/**
 * Safe recalloc.
 * If no memory is available, it aborts.
 */
void* realloc_nofail(void* ptr, size_t size);

/**
 * Safe strdup.
 * If no memory is available, it aborts.
 */
char* strdup_nofail(const char* str);

/****************************************************************************/
/* thread */

/**
 * Thread wrappers to handle error conditions.
 */
void thread_mutex_init(thread_mutex_t* mutex);
void thread_mutex_destroy(thread_mutex_t* mutex);
void thread_mutex_lock(thread_mutex_t* mutex);
void thread_mutex_unlock(thread_mutex_t* mutex);
void thread_cond_init(thread_cond_t* cond);
void thread_cond_destroy(thread_cond_t* cond);
void thread_cond_signal(thread_cond_t* cond);
void thread_cond_broadcast(thread_cond_t* cond);
void thread_cond_wait(thread_cond_t* cond, thread_mutex_t* mutex);
void thread_create(thread_id_t* thread, void* (*func)(void *), void *arg);
void thread_join(thread_id_t thread, void** retval);
void thread_yield(void);

#endif

