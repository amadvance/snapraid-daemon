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

/**
 * Initialize string stream.
 * @param s String stream to initialize
 * @param size Initial buffer size
 */
void ss_init(ss_t* s, size_t size);

/**
 * Cleanup string stream.
 * @param s String stream to cleanup
 */
void ss_done(ss_t* s);

/**
 * Reserve space in string stream buffer.
 * @param s String stream
 * @param needed Number of bytes needed
 */
void ss_reserve(ss_t* s, ssize_t needed);

/**
 * Return a pointer to the string.
 *
 * The string returned will remain valid until the next write.
 * The called may decide to own the returned string, and not use anymore
 * the ss_t object. In such case the called is responsible to free the string.
 *
 * @param s String stream
 * @return The string 0 terminated.
 */
char* ss_extract(ss_t* s);

/**
 * Return a pointer to a duplicate of the string.
 * @param s String stream
 * @return The string 0 terminated. It must be deallocated by the called.
 */
char* ss_dup(ss_t* s);

/**
 * Write data to string stream.
 * @param s String stream
 * @param arg Data to write
 * @param len Length of data
 */
static inline void ss_write(ss_t* s, const char* arg, ssize_t len)
{
	if (tommy_unlikely(s->len + len > s->size))
		ss_reserve(s, len);
	memcpy(s->ptr + s->len, arg, len);
	s->len += len;
}

/**
 * Print string to string stream.
 * @param s String stream
 * @param arg String to print
 */
#if defined(__GNUC__) || defined(__clang__)
#define ss_prints(s, arg) \
	do { \
		const char* p_arg = (arg); \
		ssize_t p_len = __builtin_constant_p(arg) ? sizeof(arg) - 1 : strlen(p_arg); \
		ss_write(s, p_arg, p_len); \
	} while (0)
#else /* no __builtin_constant_p available */
static inline void ss_prints(ss_t* s, const char* arg)
{
	ss_write(s, arg, strlen(arg));
}
#endif

/**
 * Print formatted string to string stream (va_list version).
 * @param s String stream
 * @param fmt Format string
 * @param ap Variable arguments
 * @return Number of characters written
 */
ssize_t ss_vprintf(ss_t* s, const char* fmt, va_list ap);

/**
 * Print formatted string to string stream.
 * @param s String stream
 * @param fmt Format string
 * @return Number of characters written
 */
ssize_t ss_printf(ss_t* s, const char* fmt, ...)  __attribute__((format(attribute_printf, 2, 3)));

/**
 * Write a repeated char.
 */
ssize_t ss_printc(ss_t* s, char c, size_t pad);

/**
 * Write a string with right space padding.
 */
ssize_t ss_printr(ss_t* s, const char* str, size_t pad);

/**
 * Write a string with left space padding.
 */
ssize_t ss_printl(ss_t* s, const char* str, size_t pad);

/**
 * Write JSON-escaped string to string stream.
 * @param s String stream
 * @param level Indentation level
 * @param arg String to write
 */
void ss_jsons(ss_t* s, int level, const char* arg);

/**
 * Write formatted JSON to string stream.
 * @param s String stream
 * @param level Indentation level
 * @param fmt Format string
 * @return Number of characters written
 */
int ss_jsonf(ss_t* s, int level, const char* fmt, ...)  __attribute__((format(attribute_printf, 3, 4)));

static inline void ss_json_open(ss_t* s, int* level)
{
	ss_jsons(s, *level, "{\n");
	++*level;
}

static inline void ss_json_object_open(ss_t* s, int* level, const char* field)
{
	ss_jsonf(s, *level, "\"%s\": {\n", field);
	++*level;
}

static inline void ss_json_close(ss_t* s, int* level)
{
	--*level;
	if (s->ptr[s->len - 1] == ',') {
		s->len -= 2;
		ss_prints(s, "\n");
	}
	if (*level != 0)
		ss_jsons(s, *level, "},\n");
	else
		ss_jsons(s, *level, "}\n");
}

static inline void ss_json_list_open(ss_t* s, int* level)
{
	ss_jsonf(s, *level, "[\n");
	++*level;
}

static inline void ss_json_array_open(ss_t* s, int* level, const char* field)
{
	ss_jsonf(s, *level, "\"%s\": [\n", field);
	++*level;
}

static inline void ss_json_array_close(ss_t* s, int* level)
{
	--*level;
	if (s->ptr[s->len - 1] == ',') {
		s->len -= 2;
		ss_prints(s, "\n");
	}
	if (*level != 0)
		ss_jsons(s, *level, "],\n");
	else
		ss_jsons(s, *level, "]\n");
}

/**
 * Write a formatted JSON array element as string.
 */
void ss_json_elem(ss_t* s, int level, const char* arg);

/**
 * Write a formatted JSON pair.
 */
void ss_json_str(ss_t* s, int level, const char* field, const char* arg);

static inline void ss_json_bool(ss_t* s, int level, const char* field, int arg)
{
	ss_jsonf(s, level, "\"%s\": %s,\n", field, arg ? "true" : "false");
}

static inline void ss_json_int(ss_t* s, int level, const char* field, int arg)
{
	ss_jsonf(s, level, "\"%s\": %d,\n", field, arg);
}

static inline void ss_json_uint(ss_t* s, int level, const char* field, unsigned arg)
{
	ss_jsonf(s, level, "\"%s\": %u,\n", field, arg);
}

static inline void ss_json_i64(ss_t* s, int level, const char* field, int64_t arg)
{
	ss_jsonf(s, level, "\"%s\": %" PRIi64 ",\n", field, arg);
}

static inline void ss_json_u64(ss_t* s, int level, const char* field, uint64_t arg)
{
	ss_jsonf(s, level, "\"%s\": %" PRIu64 ",\n", field, arg);
}

static inline void ss_json_double(ss_t* s, int level, const char* field, double arg)
{
	ss_jsonf(s, level, "\"%s\": %g,\n", field, arg);
}

/**
 * Write a formatted JSON pair with a ISO8601 timestamp.
 */
void ss_json_pair_iso8601(ss_t* s, int level, const char* field, time_t arg);

static inline ssize_t ss_len(ss_t* s)
{
	return s->len;
}

static inline char* ss_ptr(ss_t* s)
{
	return s->ptr;
}

static inline char* ss_top(ss_t* s)
{
	return s->ptr + s->len;
}

static inline void ss_forward(ss_t* s, size_t written)
{
	s->len += written;
}

static inline ssize_t ss_avail(ss_t* s)
{
	return s->size - s->len;
}

/****************************************************************************/
/* string list */

typedef tommy_list sl_t;

typedef struct sn {
	tommy_node node;
	char str[];
} sn_t;

static inline void sl_init(sl_t* list)
{
	tommy_list_init(list);
}

static inline void sl_free(sl_t* list)
{
	tommy_list_foreach(list, free);
}

/**
 * Insert string into string list.
 * @param list String list to insert into
 * @param add String to insert
 */
void sl_insert_str(sl_t* list, const char* add);

/**
 * Insert contents of one string list into another.
 * @param list Destination string list
 * @param add Source string list to insert
 */
void sl_insert_list(sl_t* list, sl_t* add);

/**
 * Insert integer as string into string list.
 * @param list String list to insert into
 * @param add Integer value to insert
 */
void sl_insert_int(sl_t* list, int add);

/**
 * Compare alphabetically two string nodes
 **/
int sl_compare(const void* void_a, const void* void_b);

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
int strdouble(double* out, const char* src);

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

