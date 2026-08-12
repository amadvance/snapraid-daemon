// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "os/portable.h"

#include "os/os.h"
#include "memory.h"

/****************************************************************************/
/* memory */

void* malloc_nofail(size_t size)
{
	void* ptr = malloc(size ? size : 1);

	if (!ptr) {
		/* LCOV_EXCL_START */
		os_abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

void* calloc_nofail(size_t count, size_t size)
{
	void* ptr = calloc(count ? count : 1, size ? size : 1);

	if (!ptr) {
		/* LCOV_EXCL_START */
		os_abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

void* realloc_nofail(void* ptr, size_t size)
{
	ptr = realloc(ptr, size ? size : 1);

	if (!ptr) {
		/* LCOV_EXCL_START */
		os_abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

char* strdup_nofail(const char* str)
{
	char* ptr = strdup(str);

	if (!ptr) {
		/* LCOV_EXCL_START */
		os_abort();
		/* LCOV_EXCL_STOP */
	}

	return ptr;
}

