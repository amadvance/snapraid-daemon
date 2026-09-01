// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __WEB_H
#define __WEB_H

#include "state.h"

/****************************************************************************/
/* web */

#define WEB_PAGE_SIZE_MAX (16 * 1024 * 1024)

/**
 * Initialize WEB server and load assets from web root.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int web_init(struct snapraid_state* state);

/**
 * Register WEB request handler.
 * @param state Current snapraid state
 */
void web_start(struct snapraid_state* state);

/**
 * Cleanup WEB server and free asset cache.
 * @param state Current snapraid state
 */
void web_done(struct snapraid_state* state);

/**
 * Reload web assets from the specified root directory.
 * @param state Current snapraid state
 * @param net_web_root Path to new web root directory
 * @return 0 on success, -1 on error
 */
int web_reload(struct snapraid_state* state, const char* net_web_root);

#define HTTP_HEADERS_MAX 512

/**
 * Generates and prints security and CORS headers into the provided string builder.
 * These headers protect the SnapRAID daemon from cross-site attacks and ensure
 * that only authorized web origins can communicate with the API.
 * @param conn Current HTTP connection
 * @param s String stream for output
 * @param now Current timestamp
 * @param net_security_headers 1 to enable security headers, 0 otherwise
 * @param net_allowed_origin Allowed origin for CORS, or NULL
 */
void http_headers_secure(struct mg_connection* conn, ss_t* s, time_t now, int net_security_headers, const char* net_allowed_origin);

#endif

