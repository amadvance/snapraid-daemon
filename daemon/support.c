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

#include "portable.h"

#include "support.h"

/****************************************************************************/
/* string stream */

void ss_init(struct ss* s, size_t size)
{
	s->len = 0;

	if (size > 0) {
		s->ptr = malloc_nofail(size);
		s->size = size;
	} else {
		s->ptr = 0;
		s->size = 0;
	}
}

void ss_reserve(struct ss* s, ssize_t needed)
{
	ssize_t new_size;

	needed += s->len;

	if (s->size >= needed)
		return;

	new_size = s->size;
	if (new_size < 16)
		new_size = 16;

	while (new_size < needed)
		new_size *= 2;

	s->ptr = realloc_nofail(s->ptr, new_size);
	s->size = new_size;
}

void ss_done(struct ss* s)
{
	free(s->ptr);
}

void ss_write(struct ss* s, const char* arg, size_t len)
{
	ss_reserve(s, len);
	memcpy(s->ptr + s->len, arg, len);
	s->len += len;
}

ssize_t ss_vprintf(struct ss* s, const char* fmt, va_list ap)
{
	size_t available;
	ssize_t needed;
	va_list ap_retry;

	available = s->size - s->len;

	va_copy(ap_retry, ap);

	needed = vsnprintf(s->ptr + s->len, available, fmt, ap);
	if (needed < 0) {
		va_end(ap_retry);
		return -1;
	}

	if ((size_t)needed >= available) { /* truncation occurred */
		ss_reserve(s, (size_t)needed + 1);

		vsnprintf(s->ptr + s->len, (size_t)needed + 1, fmt, ap_retry);
	}

	s->len += (size_t)needed;
	va_end(ap_retry);

	return 0;
}

ssize_t ss_printf(struct ss* s, const char* fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ss_vprintf(s, fmt, ap);
	va_end(ap);

	return ret;
}

ssize_t ss_printc(struct ss* s, char c, size_t pad)
{
	ss_reserve(s, pad);
	memset(ss_top(s), c, pad);
	ss_forward(s, pad);
	return pad;
}

ssize_t ss_printr(struct ss* s, const char* str, size_t pad)
{
	size_t len = strlen(str);

	if (len < pad)
		ss_printc(s, ' ', pad - len);

	ss_write(s, str, len);

	return len < pad ? pad : len;
}

ssize_t ss_printl(struct ss* s, const char* str, size_t pad)
{
	size_t len = strlen(str);

	ss_write(s, str, len);

	if (len < pad)
		ss_printc(s, ' ', pad - len);

	return len < pad ? pad : len;
}

void ss_jsons(struct ss* s, int tab, const char* arg)
{
	while (tab > 0) {
		ss_write(s, "  ", 2);
		--tab;
	}

	ss_prints(s, arg);
}

int ss_jsonf(struct ss* s, int tab, const char* fmt, ...)
{
	va_list ap;
	int ret;

	while (tab > 0) {
		ss_write(s, "  ", 2);
		--tab;
	}

	va_start(ap, fmt);
	ret = ss_vprintf(s, fmt, ap);
	va_end(ap);

	return ret;
}

int ss_json_iso8601(struct ss* s, int tab, const char* format, time_t ts)
{
	int ret;
	struct tm tm_info;
	char buf[32];

	while (tab > 0) {
		ss_write(s, "  ", 2);
		--tab;
	}

	localtime_r(&ts, &tm_info);

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_info);

	ret = ss_printf(s, format, buf);

	return ret;
}

/****************************************************************************/
/* string list */

void sl_insert_str(sl_t* list, const char* add)
{
	ssize_t len = strlen(add);
	sn_t* sn = malloc_nofail(sizeof(tommy_node) + len + 1);
	memcpy(sn->str, add, len + 1);
	tommy_list_insert_tail(list, &sn->node, sn);
}

void sl_insert_list(sl_t* list, sl_t* add)
{
	for (tommy_node* i = tommy_list_head(add); i != 0; i = i->next) {
		sn_t* sn = i->data;
		sl_insert_str(list, sn->str);
	}
}

void sl_insert_int(sl_t* list, int add)
{
	char add_str[16];

	snprintf(add_str, sizeof(add_str), "%d", add);

	sl_insert_str(list, add_str);
}

int sl_compare(const void* void_a, const void* void_b)
{
	const sn_t* a = void_a;
	const sn_t* b = void_b;

	return strcmp(a->str, b->str);
}

/****************************************************************************/
/* string */

#ifndef HAVE_STRLCPY
size_t sncpy(char* dst, size_t dst_size, const char* src)
{
	const char *s = src;
	size_t n = dst_size;

	if (n != 0) {
		while (--n != 0) {
			if ((*dst++ = *s++) == '\0') {
				return (size_t)(s - src - 1);
			}
		}
		*dst = '\0';
	}

	while (*s++) {
		;
	}

	return (size_t)(s - src - 1);
}
#endif

int strint(int* out, const char* s)
{
	char* e;
	long v;

	errno = 0;
	v = strtol(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != '\0')
		return -1; /* not a valid number */

	if (v < INT_MIN || v > INT_MAX)
		return -1; /* outside int range */

	*out = v;
	return 0;
}

int struint(unsigned* out, const char* s)
{
	char* e;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != '\0')
		return -1; /* not a valid number */

	if (v > UINT_MAX)
		return -1; /* outside int range */

	*out = v;
	return 0;
}

int stri64(int64_t* out, const char* s)
{
	char* e;
	long long v;

	errno = 0;
	v = strtoll(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != '\0')
		return -1; /* not a valid number */

	*out = v;
	return 0;
}

int stru64(uint64_t* out, const char* s)
{
	char* e;
	unsigned long long v;

	errno = 0;
	v = strtoull(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != '\0')
		return -1; /* not a valid number */

	*out = v;
	return 0;
}

int strdouble(double* out, const char* s)
{
	char* e;
	double v;

	errno = 0;
	v = strtod(s, &e);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != '\0')
		return -1; /* not a valid number */

	if (!isfinite(v))
		return -1; /* exclude nan and inf */

	*out = v;
	return 0;
}

char* strtrim(char* str)
{
	char* begin;
	char* end;

	begin = str;
	while (begin[0] && isspace((unsigned char)begin[0]))
		++begin;

	end = begin + strlen(begin);
	while (end > begin && isspace((unsigned char)end[-1]))
		--end;

	end[0] = 0;

	if (begin != end)
		memmove(str, begin, end - begin + 1);

	return str;
}


/****************************************************************************/
/* memory */

void* malloc_nofail(size_t size)
{
	void* ptr = malloc(size);

	if (!ptr) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

void* calloc_nofail(size_t count, size_t size)
{
	void* ptr = calloc(count, size);

	if (!ptr) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

void* realloc_nofail(void* ptr, size_t size)
{
	ptr = realloc(ptr, size);

	if (!ptr) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

char* strdup_nofail(const char* str)
{
	char* ptr = strdup(str);

	if (!ptr) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

/****************************************************************************/
/* thread */

void thread_mutex_init(thread_mutex_t* mutex)
{
	if (pthread_mutex_init(mutex, 0) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_mutex_destroy(thread_mutex_t* mutex)
{
	if (pthread_mutex_destroy(mutex) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_mutex_lock(thread_mutex_t* mutex)
{
	if (pthread_mutex_lock(mutex) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_mutex_unlock(thread_mutex_t* mutex)
{
	if (pthread_mutex_unlock(mutex) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_cond_init(thread_cond_t* cond)
{
	if (pthread_cond_init(cond, 0) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_cond_destroy(thread_cond_t* cond)
{
	if (pthread_cond_destroy(cond) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_cond_signal(thread_cond_t* cond)
{
	if (pthread_cond_signal(cond) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_cond_broadcast(thread_cond_t* cond)
{
	if (pthread_cond_broadcast(cond) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_cond_wait(thread_cond_t* cond, thread_mutex_t* mutex)
{
	if (pthread_cond_wait(cond, mutex) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_create(thread_id_t* thread, void* (*func)(void*), void *arg)
{
	if (pthread_create(thread, 0, func, arg) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_join(thread_id_t thread, void** retval)
{
	if (pthread_join(thread, retval) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_yield(void)
{
#ifdef __MINGW32__
	Sleep(0);
#else
	sched_yield();
#endif
}

