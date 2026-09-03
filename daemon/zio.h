// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#ifndef __ZIO_H
#define __ZIO_H

#ifdef MOCK_NO_ZLIB
#undef HAVE_ZLIB
#define HAVE_ZLIB 0
#endif

/****************************************************************************/
/* zio */

typedef struct ZFILE ZFILE;

struct ZFILE {
	int is_gz;
	union {
		FILE* normal_file;
#if HAVE_ZLIB
		gzFile gz_file;
#else
		void* gz_file;
#endif
	} handle;
};

/**
 * Wrap a file descriptor into a ZFILE.
 */
ZFILE* zdopen(int fd, const char* mode, int is_gz);

/**
 * Check if the filename ends with ".gz".
 */
int is_gz_extension(const char* filename);

/**
 * Close a file.
 */
int zclose(ZFILE* stream);

/**
 * Read from a file.
 */
ssize_t zread(void* ptr, size_t size, size_t nmemb, ZFILE* stream);

/**
 * Write to a file.
 */
size_t zwrite(const void* ptr, size_t size, size_t nmemb, ZFILE* stream);

/**
 * Print to a file.
 */
int zprintf(ZFILE* stream, const char* format, ...) __attribute__((format(attribute_printf, 2, 3)));

/**
 * Flush pending data.
 */
int zflush(ZFILE* stream);

#endif

