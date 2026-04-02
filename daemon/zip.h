// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __ZIP_H
#define __ZIP_H

#include "state.h"

/****************************************************************************/
/* zip */

/**
 * Scan a ZIP file and load its content into the web page list.
 * @param page_list List of web pages to populate
 * @param path Path to ZIP file
 * @return 0 on success, -1 on error
 */
int crawl_zip(tommy_list* page_list, const char* path);

#endif

