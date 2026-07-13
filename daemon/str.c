// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#include "str.h"
#include "memory.h"

/****************************************************************************/
/* string */

#ifndef HAVE_STRLCPY
size_t sncpy(char* dst, size_t dst_size, const char* src)
{
	const char* s = src;
	size_t n = dst_size;

	if (n != 0) {
		while (--n != 0) {
			if ((*dst++ = *s++) == 0) {
				return (size_t)(s - src - 1);
			}
		}
		*dst = 0;
	}

	while (*s++) {
		;
	}

	return (size_t)(s - src - 1);
}
#endif

#ifndef HAVE_STRLCAT
size_t sncat(char* dst, size_t dst_size, const char* src)
{
	char* d = dst;
	const char* s = src;
	size_t n = dst_size;
	size_t dlen;

	while (n != 0 && *d != 0) {
		--n;
		++d;
	}
	dlen = (size_t)(d - dst);
	n = dst_size - dlen;

	if (n == 0) {
		while (*s != 0) {
			++s;
		}
		return dlen + (size_t)(s - src);
	}

	while (*s != 0) {
		if (n > 1) {
			*d = *s;
			++d;
			--n;
		}
		++s;
	}
	*d = 0;

	return dlen + (size_t)(s - src);
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

	if (e == s || *e != 0)
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

	while (*s && isspace((unsigned char)*s))
		++s;

	if (*s == '-') {
		errno = ERANGE;
		return -1; /* negative (accepted by strtoul) */
	}

	errno = 0;
	v = strtoul(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != 0)
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

	if (e == s || *e != 0)
		return -1; /* not a valid number */

	*out = v;
	return 0;
}

int stru64(uint64_t* out, const char* s)
{
	char* e;
	unsigned long long v;

	while (*s && isspace((unsigned char)*s))
		++s;

	if (*s == '-') {
		errno = ERANGE;
		return -1; /* negative (accepted by strtoul) */
	}

	errno = 0;
	v = strtoull(s, &e, 10);
	if (errno != 0)
		return -1; /* overflow or underflow */

	if (e == s || *e != 0)
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

	if (e == s || *e != 0)
		return -1; /* not a valid number */

	if (!isfinite(v))
		return -1; /* exclude nan and inf */

	*out = v;
	return 0;
}

#ifndef _WIN32
void strupr(char* str)
{
	while (*str) {
		*str = toupper((unsigned char)*str);
		++str;
	}
}
#endif

unsigned strsplit(char** split_map, unsigned split_max, char* str, const char* delimiters, const char* trim)
{
	unsigned mac = 0;

	/* skip initial delimiters */
	str += strspn(str, delimiters);

	while (*str != 0 && mac < split_max) {
		/* start of the token */
		char* tok_start = str;

		/* find the first delimiter or the end of the string */
		str += strcspn(str, delimiters);

		/* put the final terminator if missing */
		if (*str != 0)
			*str++ = 0;

		/* skip trailing delimiters */
		str += strspn(str, delimiters);

		/* trim the token if trim is specified */
		if (trim != 0) {
			tok_start += strspn(tok_start, trim);
			size_t len = strlen(tok_start);
			while (len > 0 && strchr(trim, tok_start[len - 1]) != 0) {
				tok_start[len - 1] = 0;
				--len;
			}
		}

		/* store the token only if it's not empty */
		if (*tok_start != 0) {
			split_map[mac] = tok_start;
			++mac;
		}
	}

	return mac;
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

	return needed;
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
	const unsigned char* p = (const unsigned char*)arg;

	while (*p) {
		/* named JSON escapes */
		switch (*p) {
		case '"' :  ss_write(s, "\\\"", 2); ++p; continue;
		case '\\' : ss_write(s, "\\\\", 2); ++p; continue;
		case '\b' : ss_write(s, "\\b", 2); ++p; continue;
		case '\f' : ss_write(s, "\\f", 2); ++p; continue;
		case '\n' : ss_write(s, "\\n", 2); ++p; continue;
		case '\r' : ss_write(s, "\\r", 2); ++p; continue;
		case '\t' : ss_write(s, "\\t", 2); ++p; continue;
		}

		/* control characters: U+0000–U+001F and U+007F (DEL) */
		if (*p < 0x20 || *p == 0x7F) {
			char buf[7];
			snprintf(buf, sizeof(buf), "\\u%04x", *p);
			ss_write(s, buf, 6);
			++p;
			continue;
		}

		/* printable ASCII: 0x20–0x7E */
		if (*p < 0x80) {
			ss_write(s, (const char*)p, 1);
			++p;
			continue;
		}

		/* UTF-8 multi-byte sequences (0x80 and above) */
		int len;
		uint32_t min_cp; /* minimum valid codepoint for this sequence length */

		if ((*p & 0xE0) == 0xC0) { /* 110xxxxx */
			len = 2;
			min_cp = 0x80;
		} else if ((*p & 0xF0) == 0xE0) { /* 1110xxxx */
			len = 3;
			min_cp = 0x800;
		} else if ((*p & 0xF8) == 0xF0) { /* 11110xxx */
			len = 4;
			min_cp = 0x10000;
		} else {
			/* bare continuation byte (0x80–0xBF) or invalid byte (0xF8–0xFF) */
			ss_write(s, "\\ufffd", 6);
			++p;
			continue;
		}

		/* validate continuation bytes (10xxxxxx) and check for truncation */
		int valid = 1;
		for (int i = 1; i < len; ++i) {
			if (p[i] == '\0' || (p[i] & 0xC0) != 0x80) {
				valid = 0;
				break;
			}
		}
		if (!valid) {
			/* emit one replacement char and advance a single byte to resync */
			ss_write(s, "\\ufffd", 6);
			++p;
			continue;
		}

		/* decode the codepoint */
		uint32_t cp;
		switch (len) {
		case 2 :
			cp = (uint32_t)(p[0] & 0x1F) << 6
				| (uint32_t)(p[1] & 0x3F);
			break;
		case 3 :
			cp = (uint32_t)(p[0] & 0x0F) << 12
				| (uint32_t)(p[1] & 0x3F) << 6
				| (uint32_t)(p[2] & 0x3F);
			break;
		default : /* 4 */
			cp = (uint32_t)(p[0] & 0x07) << 18
				| (uint32_t)(p[1] & 0x3F) << 12
				| (uint32_t)(p[2] & 0x3F) << 6
				| (uint32_t)(p[3] & 0x3F);
			break;
		}

		/* overlong encoding: codepoint is representable in a shorter sequence */
		if (cp < min_cp) {
			ss_write(s, "\\ufffd", 6);
			++p; /* advance only 1 byte; continuation bytes may be valid elsewhere */
			continue;
		}

		/* surrogate halves U+D800–U+DFFF are forbidden in UTF-8 (RFC 3629) */
		if (cp >= 0xD800 && cp <= 0xDFFF) {
			ss_write(s, "\\ufffd", 6);
			p += len;
			continue;
		}

		/* codepoints above U+10FFFF are outside the Unicode range */
		if (cp > 0x10FFFF) {
			ss_write(s, "\\ufffd", 6);
			p += len;
			continue;
		}

		/* structurally and semantically valid UTF-8: pass through as raw bytes */
		ss_write(s, (const char*)p, len);
		p += len;
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
	ss_json_esc(s, arg);
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
	char buf[32];

	struct tm res;
	struct tm* tm_info = localtime_r(&arg, &res);

	if (tm_info) {
		strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm_info);
	} else {
		sncpy(buf, sizeof(buf), "1970-01-01T00:00:00");
	}

	ss_json_str(s, level, field, buf);
}

