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
/* mime */

typedef struct {
	const char* extension;
	const char* mime_type;
} mime_entry;

static const mime_entry MIME[] =
{
	/* core */
	{ ".html", "text/html" },
	{ ".htm", "text/html" },
	{ ".js", "text/javascript" },
	{ ".mjs", "text/javascript" },
	{ ".css", "text/css" },
	{ ".tsx", "application/x-typescript" },

	/* images */
	{ ".svg", "image/svg+xml" },
	{ ".png", "image/png" },
	{ ".jpg", "image/jpeg" },
	{ ".jpeg", "image/jpeg" },
	{ ".ico", "image/x-icon" },
	{ ".webp", "image/webp" },
	{ ".avif", "image/avif" },
	{ ".gif", "image/gif" },

	/* fonts */
	{ ".woff2", "font/woff2" },
	{ ".woff", "font/woff" },
	{ ".ttf", "font/ttf" },
	{ ".otf", "font/otf" },
	{ ".eot", "application/vnd.ms-fontobject" },

	/* data */
	{ ".json", "application/json" },
	{ ".map", "application/json" },
	{ ".xml", "application/xml" },
	{ ".pdf", "application/pdf" },
	{ ".txt", "text/plain" },
	{ ".log", "text/plain" },
	{ ".csv", "text/csv" },

	/* archives */
	{ ".zip", "application/zip" },
	{ ".gz", "application/gzip" },
	{ ".wasm", "application/wasm" },

	{ 0 }
};

const char* get_mime_type(const char* path)
{
	if (!path)
		return 0;

	for (int i = 0; MIME[i].extension != 0; ++i) {
		if (strstr(path, MIME[i].extension)) {
			return MIME[i].mime_type;
		}
	}

	return 0;
}

/****************************************************************************/
/* crc32 */

/* CRC32 lookup table for polynomial 0xEDB88320 */
static const uint32_t crc32_table[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

/**
 * Calculates CRC32 for a buffer.
 * Initial CRC should be 0 (or 0xFFFFFFFF if you want to skip XORing in the loop).
 */
uint32_t calculate_crc32(const void* void_data, size_t length)
{
	const uint8_t* data = void_data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < length; i++) {
		uint8_t table_index = (uint8_t)(crc ^ data[i]);
		crc = (crc >> 8) ^ crc32_table[table_index];
	}
	return crc ^ 0xFFFFFFFF;
}

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

void ss_json_tab(ss_t* s, int level)
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

void sl_insert_double(sl_t* list, double add)
{
	char add_str[16];

	snprintf(add_str, sizeof(add_str), "%.2f", add);

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
/* pulse */

void pulse(struct snapraid_state* state, unsigned mask)
{
	if ((mask & PULSE_ARRAY) != 0)
		++state->pulse.array;
	if ((mask & PULSE_CONFIG) != 0)
		++state->pulse.config;
	if ((mask & PULSE_DISKS) != 0)
		++state->pulse.disks;
	if ((mask & PULSE_TASKS) != 0)
		++state->pulse.tasks;
	if ((mask & PULSE_ACTIVITY) != 0)
		++state->pulse.activity;
}

int pulse_strint(struct snapraid_state* state, unsigned mask, int* out, const char* src)
{
	int val;
	if (strint(&val, src) != 0)
		return -1;
	if (*out == val)
		return 0;
	pulse(state, mask);
	*out = val;
	return 0;
}

int pulse_struint(struct snapraid_state* state, unsigned mask, unsigned* out, const char* src)
{
	unsigned val;
	if (struint(&val, src) != 0)
		return -1;
	if (*out == val)
		return 0;
	pulse(state, mask);
	*out = val;
	return 0;
}

int pulse_stri64(struct snapraid_state* state, unsigned mask, int64_t* out, const char* src)
{
	int64_t val;
	if (stri64(&val, src) != 0)
		return -1;
	if (*out == val)
		return 0;
	pulse(state, mask);
	*out = val;
	return 0;
}

int pulse_stru64(struct snapraid_state* state, unsigned mask, uint64_t* out, const char* src)
{
	uint64_t val;
	if (stru64(&val, src) != 0)
		return -1;
	if (*out == val)
		return 0;
	pulse(state, mask);
	*out = val;
	return 0;
}

int pulse_double(struct snapraid_state* state, unsigned mask, double* out, const char* src)
{
	double val;
	if (strdouble(&val, src) != 0)
		return -1;
	if (*out == val)
		return 0;
	pulse(state, mask);
	*out = val;
	return 0;
}

void pulse_str(struct snapraid_state* state, unsigned mask, char* out, size_t out_size, const char* src)
{
	if (strcmp(out, src) == 0)
		return;
	pulse(state, mask);
	sncpy(out, out_size, src);
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

