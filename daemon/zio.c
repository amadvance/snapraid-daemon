// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "portable.h"
#include <stdarg.h>

#include "support.h"
#include "zio.h"

int is_gz_extension(const char* filename)
{
	size_t len;

	if (filename == 0)
		return 0;
	len = strlen(filename);
	if (len < 3)
		return 0;

	return strcmp(filename + len - 3, ".gz") == 0;
}

ZFILE* zdopen(int fd, const char* mode, int is_gz)
{
	ZFILE* stream;

	if (mode == 0)
		return 0;

	stream = malloc_nofail(sizeof(struct ZFILE));
	stream->is_gz = is_gz;

	if (is_gz) {
#if HAVE_ZLIB
		stream->handle.gz_file = gzdopen(fd, mode);
#else
		stream->handle.gz_file = 0;
		(void)fd;
		errno = ENOSYS;
#endif
		if (stream->handle.gz_file == 0) {
			free(stream);
			return 0;
		}
	} else {
		stream->handle.normal_file = fdopen(fd, mode);
		if (stream->handle.normal_file == 0) {
			free(stream);
			return 0;
		}
	}

	return stream;
}

int zclose(ZFILE* stream)
{
	int result;

	if (stream == 0)
		return -1;

	if (stream->is_gz) {
#if HAVE_ZLIB
		result = (gzclose(stream->handle.gz_file) == 0) ? 0 : -1;
#else
		result = -1;
#endif
	} else {
		result = fclose(stream->handle.normal_file);
	}

	free(stream);
	return result;
}

size_t zread(void* ptr, size_t size, size_t nmemb, ZFILE* stream)
{
	if (stream == 0 || size == 0 || nmemb == 0)
		return 0;

	if (stream->is_gz) {
#if HAVE_ZLIB
		unsigned int total_bytes = (unsigned int)(size * nmemb);
		int bytes_read = gzread(stream->handle.gz_file, ptr, total_bytes);
		if (bytes_read <= 0)
			return 0;

		return (size_t)bytes_read / size;
#else
		return 0;
#endif
	} else {
		return fread(ptr, size, nmemb, stream->handle.normal_file);
	}
}

size_t zwrite(const void* ptr, size_t size, size_t nmemb, ZFILE* stream)
{
	if (stream == 0 || size == 0 || nmemb == 0)
		return 0;

	if (stream->is_gz) {
#if HAVE_ZLIB
		unsigned int total_bytes = (unsigned int)(size * nmemb);
		int bytes_written = gzwrite(stream->handle.gz_file, ptr, total_bytes);
		if (bytes_written <= 0)
			return 0;

		return (size_t)bytes_written / size;
#else
		return 0;
#endif
	} else {
		return fwrite(ptr, size, nmemb, stream->handle.normal_file);
	}
}

#define ZPRINTF_MAX (128 + PATH_MAX)

int zprintf(ZFILE* stream, const char* format, ...)
{
	char buf[ZPRINTF_MAX];
	va_list args;
	int len;

	if (stream == 0)
		return -1;

	va_start(args, format);
	len = vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return -1;

	if (zwrite(buf, 1, len, stream) != (size_t)len)
		return -1;

	return len;
}

int zflush(ZFILE* stream)
{
	if (stream == 0)
		return -1;

	if (stream->is_gz) {
#if HAVE_ZLIB
		return gzflush(stream->handle.gz_file, Z_SYNC_FLUSH);
#else
		return -1;
#endif
	} else {
		return fflush(stream->handle.normal_file);
	}
}

