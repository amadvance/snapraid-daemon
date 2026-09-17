// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "os/portable.h"

#include "os/os.h"
#include "support.h"
#include "scheduler.h"
#include "selftest.h"

struct filter_escape_test_case {
	const char* input;
	const char* expected;
	int expected_ret;
};

static const struct filter_escape_test_case FILTER_ESCAPE_TEST[] = {
	/* regular text */
	{ "foo", "foo", 0 },
	{ "foo/bar/baz.txt", "foo/bar/baz.txt", 0 },

	/* wildcards outside character classes */
	{ "*.txt", "*.txt", 0 },
	{ "photo?.jpg", "photo?.jpg", 0 },
	{ "dir/**/file", "dir/**/file", 0 },

	/* escaped wildcard metacharacters outside classes */
	{ "foo\\[bar\\]", "foo^[bar^]", 0 },
	{ "foo\\*bar", "foo^*bar", 0 },
	{ "foo\\?bar", "foo^?bar", 0 },

	/* escaped backslash outside classes */
	{ "foo\\\\bar", "foo\\bar", 0 },

	/* literal caret outside classes */
	{ "foo^bar", "foo^^bar", 0 },
	{ "foo^^bar", "foo^^^^bar", 0 },

	/* escaped caret outside classes */
	{ "foo\\^bar", "foo^^bar", 0 },

	/* unescaped character class containing caret (preserve caret semantics inside [...]) */
	{ "file[^-z]", "file[^-z]", 0 },
	{ "file[^a-z]", "file[^a-z]", 0 },
	{ "file[a^b]", "file[a^b]", 0 },

	/* character class with regular ranges */
	{ "file[a-z]", "file[a-z]", 0 },
	{ "file[0-9]", "file[0-9]", 0 },

	/* carets both inside and outside character classes */
	{ "foo^dir/file[^-z]^ext", "foo^^dir/file[^-z]^^ext", 0 },

	/* escaped brackets: not character classes, carets inside must be doubled */
	{ "foo\\[^bar\\]", "foo^[^^bar^]", 0 },
	{ "foo\\[^-z\\]", "foo^[^^-z^]", 0 },

	/* lone backslash or non-escapable character */
	{ "foo\\", "foo\\", 0 },
	{ "foo\\abar", "foo\\abar", 0 },

	/* empty string */
	{ "", "", 0 },

	{ 0, 0, 0 }
};

static int test_filter_escape_overflow(void)
{
	char small_buf[4];

	/* "foo^" converts to "foo^^" (5 chars + null = 6 bytes), should fail on 4-byte buffer */
	if (filter_escape_to_windows(small_buf, sizeof(small_buf), "foo^") != -1) {
		printf("selftest: filter_escape_to_windows should fail when buffer too small\n");
		return -1;
	}

	/* "foo\*" converts to "foo^*" (5 chars + null = 6 bytes), should fail on 4-byte buffer */
	if (filter_escape_to_windows(small_buf, sizeof(small_buf), "foo\\*") != -1) {
		printf("selftest: filter_escape_to_windows should fail when buffer too small\n");
		return -1;
	}

	return 0;
}

static int test_filter_escape(void)
{
	for (int i = 0; FILTER_ESCAPE_TEST[i].input != 0; ++i) {
		char out[PATH_MAX];
		int ret = filter_escape_to_windows(out, sizeof(out), FILTER_ESCAPE_TEST[i].input);

		if (ret != FILTER_ESCAPE_TEST[i].expected_ret) {
			printf("selftest: filter_escape_to_windows(\"%s\") returned %d, expected %d\n",
				FILTER_ESCAPE_TEST[i].input, ret, FILTER_ESCAPE_TEST[i].expected_ret);
			return -1;
		}

		if (ret == 0 && strcmp(out, FILTER_ESCAPE_TEST[i].expected) != 0) {
			printf("selftest: filter_escape_to_windows(\"%s\") produced \"%s\", expected \"%s\"\n",
				FILTER_ESCAPE_TEST[i].input, out, FILTER_ESCAPE_TEST[i].expected);
			return -1;
		}
	}

	if (test_filter_escape_overflow() != 0)
		return -1;

	return 0;
}

struct json_unescape_test_case {
	const char* input;
	size_t len;
	const char* expected;
	int expected_ret;
};

static const struct json_unescape_test_case JSON_UNESCAPE_TEST[] = {
	/* empty and plain string */
	{ "", 0, "", 0 },
	{ "hello world", 11, "hello world", 0 },

	/* standard json escape sequences */
	{ "\\\"quotes\\\"", 10, "\"quotes\"", 0 },
	{ "back\\\\slash", 11, "back\\slash", 0 },
	{ "slash\\/forward", 14, "slash/forward", 0 },
	{ "line\\nbreak", 11, "line\nbreak", 0 },
	{ "car\\rriage", 10, "car\rriage", 0 },
	{ "tab\\tspace", 10, "tab\tspace", 0 },
	{ "form\\ffeed", 10, "form\ffeed", 0 },
	{ "back\\bspace", 11, "back\bspace", 0 },

	/* unicode escape sequences (1-byte, 2-byte, 3-byte utf-8) */
	{ "\\u0041\\u0042\\u0043", 18, "ABC", 0 },
	{ "caf\\u00e9", 9, "caf\xc3\xa9", 0 },
	{ "euro \\u20ac", 11, "euro \xe2\x82\xac", 0 },

	/* unknown escape sequence: preserves literal backslash */
	{ "foo\\xbar", 8, "foo\\xbar", 0 },

	/* trailing backslash at end of string */
	{ "foo\\", 4, "foo\\", 0 },

	/* PEP 383 surrogateescape escapes (\uDC80–\uDCFF restore raw bytes 0x80–0xFF) */
	{ "\\udce9", 6, "\xe9", 0 },
	{ "\\udcc0\\udc80", 12, "\xc0\x80", 0 },
	{ "\\udced\\udca0\\udc80", 18, "\xed\xa0\x80", 0 },
	{ "\\udcf4\\udc90\\udc80\\udc80", 24, "\xf4\x90\x80\x80", 0 },

	/* invalid unicode escapes and non-PEP383 lone surrogates */
	{ "\\u12", 4, "", -1 },
	{ "\\u123", 5, "", -1 },
	{ "\\u123z", 6, "", -1 },
	{ "\\uG000", 6, "", -1 },
	{ "\\udc00", 6, "", -1 },
	{ "\\udc7f", 6, "", -1 },
	{ "\\ud800", 6, "", -1 },
	{ "\\udbff", 6, "", -1 },

	{ 0, 0, 0, 0 }
};

static int test_json_unescape_overflow(void)
{
	char small_buf[4];

	/* "hello" needs 6 bytes (5 + null), should fail on 4-byte buffer */
	if (json_unescape("hello", 5, small_buf, sizeof(small_buf)) != -1) {
		printf("selftest: json_unescape should fail when buffer too small for plain text\n");
		return -1;
	}

	/* unicode euro "\u20ac" generates 3 utf-8 bytes + null = 4 bytes; with 3-byte buffer must fail */
	if (json_unescape("\\u20ac", 6, small_buf, 3) != -1) {
		printf("selftest: json_unescape should fail when buffer too small for utf-8\n");
		return -1;
	}

	/* surrogate escapes "\udce9\udce9\udce9" (18 chars) generate 3 bytes + null = 4 bytes; must succeed in 4-byte buffer */
	if (json_unescape("\\udce9\\udce9\\udce9", 18, small_buf, sizeof(small_buf)) != 0) {
		printf("selftest: json_unescape should succeed when escaped len > buffer size but unescaped fits\n");
		return -1;
	}

	if (strcmp(small_buf, "\xe9\xe9\xe9") != 0) {
		printf("selftest: json_unescape produced wrong result for surrogate escapes\n");
		return -1;
	}

	return 0;
}

static int test_json_unescape(void)
{
	for (int i = 0; JSON_UNESCAPE_TEST[i].input != 0; ++i) {
		char out[256];
		int ret = json_unescape(JSON_UNESCAPE_TEST[i].input, JSON_UNESCAPE_TEST[i].len, out, sizeof(out));

		if (ret != JSON_UNESCAPE_TEST[i].expected_ret) {
			printf("selftest: json_unescape(\"%.*s\") returned %d, expected %d\n",
				(int)JSON_UNESCAPE_TEST[i].len, JSON_UNESCAPE_TEST[i].input, ret, JSON_UNESCAPE_TEST[i].expected_ret);
			return -1;
		}

		if (ret == 0 && strcmp(out, JSON_UNESCAPE_TEST[i].expected) != 0) {
			printf("selftest: json_unescape(\"%.*s\") produced \"%s\", expected \"%s\"\n",
				(int)JSON_UNESCAPE_TEST[i].len, JSON_UNESCAPE_TEST[i].input, out, JSON_UNESCAPE_TEST[i].expected);
			return -1;
		}
	}

	if (test_json_unescape_overflow() != 0)
		return -1;

	return 0;
}

struct json_esc_test_case {
	const char* input;
	const char* expected;
};

static const struct json_esc_test_case JSON_ESC_TEST[] = {
	/* plain ASCII */
	{ "hello world", "\"hello world\",\n" },

	/* valid multi-byte UTF-8 */
	{ "caf\xc3\xa9", "\"caf\xc3\xa9\",\n" },

	/* literal valid U+FFFD (0xEF 0xBF 0xBD) is valid UTF-8, preserved raw */
	{ "\xef\xbf\xbd", "\"\xef\xbf\xbd\",\n" },

	/* single invalid byte (e.g. Latin-1 0xE9) encodes as PEP 383 surrogateescape */
	{ "\xe9", "\"\\udce9\",\n" },

	/* overlong 2-byte sequence (0xC0 0x80) encodes as 2 surrogateescapes */
	{ "\xc0\x80", "\"\\udcc0\\udc80\",\n" },

	/* surrogate 3-byte sequence (0xED 0xA0 0x80) encodes as 3 surrogateescapes */
	{ "\xed\xa0\x80", "\"\\udced\\udca0\\udc80\",\n" },

	/* codepoint > 0x10FFFF 4-byte sequence encodes as 4 surrogateescapes */
	{ "\xf4\x90\x80\x80", "\"\\udcf4\\udc90\\udc80\\udc80\",\n" },

	/* mixed string with surrogate and ASCII */
	{ "foo_\xed\xa0\x80_bar", "\"foo_\\udced\\udca0\\udc80_bar\",\n" },

	{ 0, 0 }
};

static int test_json_esc(void)
{
	for (int i = 0; JSON_ESC_TEST[i].input != 0; ++i) {
		ss_t s;
		ss_init(&s, 256);
		ss_json_elem(&s, 0, JSON_ESC_TEST[i].input);

		const char* actual = ss_extract(&s);
		if (strcmp(actual, JSON_ESC_TEST[i].expected) != 0) {
			printf("selftest: json_esc failed for test case %d: got \"%s\", expected \"%s\"\n",
				i, actual, JSON_ESC_TEST[i].expected);
			ss_done(&s);
			return -1;
		}

		/* verify lossless round-trip through json_unescape (strip enclosing quotes and comma-newline) */
		size_t esc_len = strlen(actual);
		if (esc_len >= 4) {
			char roundtrip[256];
			int ret = json_unescape(actual + 1, esc_len - 4, roundtrip, sizeof(roundtrip));
			if (ret != 0 || strcmp(roundtrip, JSON_ESC_TEST[i].input) != 0) {
				printf("selftest: json roundtrip failed for test case %d (\"%s\"): got \"%s\"\n",
					i, JSON_ESC_TEST[i].input, roundtrip);
				ss_done(&s);
				return -1;
			}
		}

		ss_done(&s);
	}

	return 0;
}

int selftest(void)
{
	if (test_filter_escape() != 0)
		return -1;

	if (test_json_unescape() != 0)
		return -1;

	if (test_json_esc() != 0)
		return -1;

	return 0;
}

void test(int argc, char* argv[])
{
	if (argc < 2 || strcmp(argv[1], "test") != 0)
		return;

	uint64_t t_start = os_tick_ms();

	printf("Test...\n");

	if (selftest() != 0)
		exit(EXIT_FAILURE);

	uint64_t t_end = os_tick_ms();

	printf("Test: %" PRIu64 " ms\n", (t_end - t_start));
	printf("Everything OK\n");

	exit(EXIT_SUCCESS);
}

