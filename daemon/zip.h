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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

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

