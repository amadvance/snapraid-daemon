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

void ss_init(ss_t* s, size_t size)
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

void ss_reserve(ss_t* s, ssize_t needed)
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

void ss_done(ss_t* s)
{
	free(s->ptr);
}

char* ss_extract(ss_t* s)
{
	ss_reserve(s, 1);
	s->ptr[s->len] = 0; /* write a final 0, but don't increase the length */
	return s->ptr;
}

char* ss_dup(ss_t* s)
{
	char* str = malloc_nofail(ss_len(s) + 1);
	memcpy(str, ss_ptr(s), ss_len(s));
	str[ss_len(s)] = 0;
	return str;
}

ssize_t ss_vprintf(ss_t* s, const char* fmt, va_list ap)
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

ssize_t ss_printf(ss_t* s, const char* fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ss_vprintf(s, fmt, ap);
	va_end(ap);

	return ret;
}

ssize_t ss_printc(ss_t* s, char c, size_t pad)
{
	ss_reserve(s, pad);
	memset(ss_top(s), c, pad);
	ss_forward(s, pad);
	return pad;
}

ssize_t ss_printr(ss_t* s, const char* str, size_t pad)
{
	size_t len = strlen(str);

	if (len < pad)
		ss_printc(s, ' ', pad - len);

	ss_write(s, str, len);

	return len < pad ? pad : len;
}

ssize_t ss_printl(ss_t* s, const char* str, size_t pad)
{
	size_t len = strlen(str);

	ss_write(s, str, len);

	if (len < pad)
		ss_printc(s, ' ', pad - len);

	return len < pad ? pad : len;
}

static void ss_json_tab(ss_t* s, int level)
{
	while (level > 0) {
		ss_write(s, "  ", 2);
		--level;
	}
}

void ss_jsons(ss_t* s, int level, const char* arg)
{
	ss_json_tab(s, level);

	ss_prints(s, arg);
}

static void ss_json_esc(ss_t* s, const char* arg)
{
	while (*arg) {
		ssize_t len = strcspn(arg, "\"\\\n\r\t");
		if (len == 0) {
			switch (*arg) {
			case '"' :
				ss_write(s, "\\\"", 2);
				break;
			case '\\' :
				ss_write(s, "\\\\", 2);
				break;
			case '\n' :
				ss_write(s, "\\n", 2);
				break;
			case '\r' :
				ss_write(s, "\\r", 2);
				break;
			case '\t' :
				ss_write(s, "\\t", 2);
				break;
			}
			++arg;
		} else {
			ss_write(s, arg, len);
			arg += len;
		}
	}
}

int ss_jsonf(ss_t* s, int level, const char* fmt, ...)
{
	va_list ap;
	int ret;

	ss_json_tab(s, level);

	va_start(ap, fmt);
	ret = ss_vprintf(s, fmt, ap);
	va_end(ap);

	return ret;
}

static void ss_json_munge_separator(ss_t* s)
{
	if (s->len >= 2
		&& s->ptr[s->len - 1] == '\n'
		&& s->ptr[s->len - 2] == ',') {
		s->len -= 2;
		ss_prints(s, "\n");
	}
}

void ss_json_open(ss_t* s, int* level)
{
	ss_jsons(s, *level, "{\n");
	++*level;
}

void ss_json_object_open(ss_t* s, int* level, const char* field)
{
	ss_jsonf(s, *level, "\"%s\": {\n", field);
	++*level;
}

void ss_json_close(ss_t* s, int* level)
{
	--*level;
	ss_json_munge_separator(s);
	if (*level != 0)
		ss_jsons(s, *level, "},\n");
	else
		ss_jsons(s, *level, "}\n");
}

void ss_json_list_open(ss_t* s, int* level)
{
	ss_jsonf(s, *level, "[\n");
	++*level;
}

void ss_json_array_open(ss_t* s, int* level, const char* field)
{
	ss_jsonf(s, *level, "\"%s\": [\n", field);
	++*level;
}

void ss_json_array_close(ss_t* s, int* level)
{
	--*level;
	ss_json_munge_separator(s);
	if (*level != 0)
		ss_jsons(s, *level, "],\n");
	else
		ss_jsons(s, *level, "]\n");
}

void ss_json_elem(ss_t* s, int level, const char* arg)
{
	ss_json_tab(s, level);

	ss_prints(s, "\"");
	ss_prints(s, arg);
	ss_prints(s, "\",\n");
}

void ss_json_str(ss_t* s, int level, const char* field, const char* arg)
{
	ss_json_tab(s, level);

	ss_prints(s, "\"");
	ss_prints(s, field);
	ss_prints(s, "\": \"");
	ss_json_esc(s, arg);
	ss_prints(s, "\",\n");
}

void ss_json_pair_iso8601(ss_t* s, int level, const char* field, time_t arg)
{
	struct tm tm_info;
	char buf[32];

	localtime_r(&arg, &tm_info);

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_info);

	ss_json_str(s, level, field, buf);
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

void thread_rwlock_init(thread_rwlock_t* rwlock)
{
	if (pthread_rwlock_init(rwlock, 0) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_rwlock_destroy(thread_rwlock_t* rwlock)
{
	if (pthread_rwlock_destroy(rwlock) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_rwlock_rdlock(thread_rwlock_t* rwlock)
{
	if (pthread_rwlock_rdlock(rwlock) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_rwlock_wrlock(thread_rwlock_t* rwlock)
{
	if (pthread_rwlock_wrlock(rwlock) != 0) {
		/* LCOV_EXCL_START */
		abort();
		/* LCOV_EXCL_STOP */
	}
}

void thread_rwlock_unlock(thread_rwlock_t* rwlock)
{
	if (pthread_rwlock_unlock(rwlock) != 0) {
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

/****************************************************************************/
/* compression */

#define Z_NONE 0
#define Z_ZLIB 1
#define Z_ZSTD 2

#if HAVE_ZLIB || HAVE_ZSTD
int mg_accept_z(struct mg_connection* conn)
{
	const struct mg_request_info* ri = mg_get_request_info(conn);

	/*
	 * ONLY use compressed chunking if we are on HTTP/1.1
	 * HTTP/1.0 can't do it. HTTP/2+ does it differently at the library level.
	 */
	if (!ri->http_version || strcmp(ri->http_version, "1.1") != 0)
		return Z_NONE;

	const char* i = mg_get_header(conn, "Accept-Encoding");
	if (!i)
		return Z_NONE;  /* no header */

	int best = Z_NONE;
	while (*i) {
		/* skip separators */
		while (*i == ' ' || *i == ',')
			++i;

#if HAVE_ZLIB
		/* check if we have GZIP */
		if ((i[0] == 'g' || i[0] == 'G')
			&& (i[1] == 'z' || i[1] == 'Z')
			&& (i[2] == 'i' || i[2] == 'I')
			&& (i[3] == 'p' || i[3] == 'P')
			&& (i[4] == ';' || i[4] == ' ' || i[4] == ',' || i[4] == 0)) {
			best = Z_ZLIB;
		}
#endif

#if HAVE_ZSTD
		/* check if we have ZSTD */
		if ((i[0] == 'z' || i[0] == 'Z')
			&& (i[1] == 's' || i[1] == 'S')
			&& (i[2] == 't' || i[2] == 'T')
			&& (i[3] == 'd' || i[3] == 'D')
			&& (i[4] == ';' || i[4] == ' ' || i[4] == ',' || i[4] == 0)) {
			return Z_ZSTD; /* no better than this */
		}
#endif

		/* skip until the next token */
		while (*i && *i != ',')
			++i;
	}

	return best;
}
#else
int mg_accept_z(struct mg_connection* conn)
{
	(void)conn;
	return Z_NONE;
}
#endif

#define Z_CHUNK_DATA_SIZE 8192
#define Z_HEADER_RESERVE 16 /* extra to keep following CHUNK aligned */
#define Z_FOOTER_RESERVE 7

#if HAVE_ZLIB
int mg_write_gzip(struct mg_connection* conn, const char* src, size_t src_size)
{
	z_stream strm;
	char buf[Z_HEADER_RESERVE + Z_CHUNK_DATA_SIZE + Z_FOOTER_RESERVE];
	int res;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + 15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		return -1;
	}

	/*
	 * Determine if we can do this in one single burst
	 * deflateBound provides the absolute maximum size zlib might need
	 */
	int can_finish_immediately = (deflateBound(&strm, src_size) <= Z_CHUNK_DATA_SIZE);

	strm.next_in = (Bytef*)src;
	strm.avail_in = (uInt)src_size;

	do {
		/* use Z_FINISH immediately if we know it fits, otherwise use Z_NO_FLUSH */
		int flush = (can_finish_immediately || strm.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;

		strm.next_out = (Bytef*)(buf + Z_HEADER_RESERVE);
		strm.avail_out = Z_CHUNK_DATA_SIZE;

		res = deflate(&strm, flush);

		size_t compressed_len = Z_CHUNK_DATA_SIZE - strm.avail_out;

		if (compressed_len > 0 || res == Z_STREAM_END) {
			char hex[Z_HEADER_RESERVE + 1];
			int hex_len = snprintf(hex, sizeof(hex), "%zX\r\n", compressed_len);

			char* send_start = (buf + Z_HEADER_RESERVE) - hex_len;
			memcpy(send_start, hex, hex_len);

			char* footer_ptr = buf + Z_HEADER_RESERVE + compressed_len;
			memcpy(footer_ptr, "\r\n", 2);

			size_t total_to_send = hex_len + compressed_len + 2;

			if (res == Z_STREAM_END) {
				memcpy(footer_ptr + 2, "0\r\n\r\n", 5);
				total_to_send += 5;
			}

			if (mg_write(conn, send_start, total_to_send) <= 0) {
				deflateEnd(&strm);
				return -1;
			}
		}
	} while (res != Z_STREAM_END);

	deflateEnd(&strm);
	return 0;
}
#endif

#if HAVE_ZSTD
int mg_write_zstd(struct mg_connection* conn, const char *src, size_t src_size)
{
	ZSTD_CCtx* cctx = ZSTD_createCCtx();
	if (!cctx)
		return -1;

	char buf[Z_HEADER_RESERVE + Z_CHUNK_DATA_SIZE + Z_FOOTER_RESERVE];

	ZSTD_inBuffer input = { src, src_size, 0 };
	int finished = 0;

	do {
		/* prepare output buffer starting after the reserved header space */
		ZSTD_outBuffer output = { buf + Z_HEADER_RESERVE, Z_CHUNK_DATA_SIZE, 0 };

		/* determine if we are on the last bit of input */
		ZSTD_EndDirective mode = (input.pos < input.size) ? ZSTD_e_continue : ZSTD_e_end;

		size_t remaining = ZSTD_compressStream2(cctx, &output, &input, mode);

		if (ZSTD_isError(remaining)) {
			ZSTD_freeCCtx(cctx);
			return -1;
		}

		size_t compressed_len = output.pos;

		/* only send a chunk if we have data OR if we just finished the stream */
		if (compressed_len > 0 || (mode == ZSTD_e_end && remaining == 0)) {
			finished = (mode == ZSTD_e_end && remaining == 0);

			char hex[Z_HEADER_RESERVE + 1];
			int hex_len = snprintf(hex, sizeof(hex), "%zX\r\n", compressed_len);
			char* send_start = (buf + Z_HEADER_RESERVE) - hex_len;
			memcpy(send_start, hex, hex_len);

			char* footer_ptr = (char*)output.dst + compressed_len;
			memcpy(footer_ptr, "\r\n", 2);
			size_t total_to_send = hex_len + compressed_len + 2;

			if (finished) {
				memcpy(footer_ptr + 2, "0\r\n\r\n", 5);
				total_to_send += 5;
			}

			if (mg_write(conn, send_start, total_to_send) <= 0) {
				ZSTD_freeCCtx(cctx);
				return -1;
			}
		}
	} while (!finished);

	ZSTD_freeCCtx(cctx);
	return 0;
}
#endif

