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

#ifndef __WEB_H
#define __WEB_H

#include "state.h"

/****************************************************************************/
/* rest */

/**
 * Initialize WEB server.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int web_init(struct snapraid_state* state);

/**
 * Cleanup WEB server.
 * @param state Current snapraid state
 */
void web_done(struct snapraid_state* state);

int web_reload(struct snapraid_state* state, const char* net_web_root);

#define HTTP_HEADERS_MAX 512

/**
 * Generates and prints security and CORS headers into the provided string builder.
 * These headers protect the SnapRAID daemon from cross-site attacks and ensure
 * that only authorized web origins can communicate with the API.
 */
void http_headers(struct mg_connection* conn, ss_t* s, time_t now, time_t last_modified, int net_security_headers, const char* net_allowed_origin);

#endif

