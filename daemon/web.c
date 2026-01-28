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

#include "state.h"
#include "log.h"
#include "elem.h"
#include "support.h"
#include "web.h"

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

#define MIME_BINARY "application/octet-stream"

static const char* get_mime_type(const char* path)
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

static void crawl_directory(tommy_list* page_list, size_t skip, const char* current_path)
{
	DIR* d = opendir(current_path);
	if (!d)
		return;

	while (1) {
		struct dirent* dd;

		errno = 0;
		dd = readdir(d);
		if (dd == 0 && errno != 0) {
			log_msg(LVL_ERROR, "crawler error readdir %s, errno=%s(%d)", current_path, strerror(errno), errno);
			break;
		}
		if (dd == 0) {
			break; /* finished */
		}

		if (dd->d_name[0] == '.')
			continue;

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", current_path, dd->d_name);

		struct stat st;
		if (lstat(path, &st) != 0) {
			log_msg(LVL_ERROR, "crawler error stating %s, errno=%s(%d)", path, strerror(errno), errno);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			crawl_directory(page_list, skip, path);
		} else if (S_ISLNK(st.st_mode)) {
			log_msg(LVL_WARNING, "crawler ignore link %s", path);
		} else if (S_ISREG(st.st_mode)) {
			int f = open(path, O_RDONLY);
			if (f == -1) {
				log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", path, strerror(errno), errno);
				continue;
			}

			const char* relative = path + skip;
			struct snapraid_page* page = page_alloc(relative, st.st_size);

			if (read(f, page->content, page->size) != page->size) {
				log_msg(LVL_ERROR, "crawler error reading %s, errno=%s(%d)", path, strerror(errno), errno);
				close(f);
				page_free(page);
				continue;
			}

			close(f);

			page->mime_type = get_mime_type(relative);
			if (!page->mime_type)
				page->mime_type = MIME_BINARY;

			tommy_list_insert_tail(page_list, &page->node, page);
		}
	}

	closedir(d);
}

#define HTTP_HEADERS_MAX 512

static void send_headers(struct mg_connection* conn, ss_t* s, time_t last_modified)
{
	int net_security_headers;
	char net_allowed_origin[CONFIG_MAX];
	time_t now = time(0);

	/* obtain the security configuration */
	state_lock();
	net_security_headers = state_ptr()->config.net_security_headers;
	sncpy(net_allowed_origin, sizeof(net_allowed_origin), state_ptr()->config.net_allowed_origin);
	state_unlock();

	ss_printf(s, "Server: %s/%s\r\n", PACKAGE_NAME, PACKAGE_VERSION);

	char date_buf[64];
	struct tm tm_gmt;
	gmtime_r(&now, &tm_gmt);
	strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_gmt);
	ss_printf(s, "Date: %s\r\n", date_buf);

	/* allowing the browser to cache for 1 day (86400 seconds) */
	ss_prints(s, "Cache-Control: public, max-age=86400\r\n");

	if (last_modified != 0) {
		gmtime_r(&last_modified, &tm_gmt);
		strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_gmt);
		ss_printf(s, "Last-Modified: %s\r\n", date_buf);
	}

	ss_prints(s, "Vary: Accept-Encoding, Origin\r\n");

	if (net_security_headers) {
		ss_prints(s, "X-Frame-Options: SAMEORIGIN\r\n");
		ss_prints(s, "X-Content-Type-Options: nosniff\r\n");
		ss_prints(s, "Content-Security-Policy: default-src 'self';\r\n");
		ss_prints(s, "Referrer-Policy: no-referrer\r\n");
		ss_prints(s, "Cross-Origin-Opener-Policy: same-origin\r\n");
	}

	if (strcmp(net_allowed_origin, "none") != 0) {
		if (strcmp(net_allowed_origin, "self") == 0) {
			const char* host = mg_get_header(conn, "Host");
			ss_printf(s, "Access-Control-Allow-Origin: http://%s\r\n", host ? host : "null");
		} else {
			ss_printf(s, "Access-Control-Allow-Origin: %s\r\n", net_allowed_origin);
		}

		ss_prints(s, "Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS\r\n");
		ss_prints(s, "Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
	}
}

static int send_no_content(struct mg_connection* conn)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	ss_prints(&s, "HTTP/1.1 204 No Content\r\n");
	send_headers(conn, &s, 0);
	ss_prints(&s, "Connection: close\r\n\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));

	ss_done(&s);
	return 204;
}

static int send_error(struct mg_connection* conn, int status)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s, 0);
	ss_prints(&s, "Connection: close\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));

	ss_done(&s);

	return status;
}

static int send_file(struct mg_connection* conn, time_t page_time, const char* body, size_t body_len, const char* mime)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	int z = mg_accept_z(conn);

	// TODO
	z = Z_NONE;

	ss_printf(&s, "HTTP/1.1 200 OK\r\n");
	send_headers(conn, &s, page_time);
	ss_printf(&s, "Content-Type: %s\r\n", mime);
	switch (z) {
#if HAVE_ZLIB
	case Z_ZLIB :
		ss_printf(&s, "Content-Encoding: gzip\r\n");
		ss_prints(&s, "Transfer-Encoding: chunked\r\n");
		break;
#endif
#if HAVE_ZSTD
	case Z_ZSTD :
		ss_printf(&s, "Content-Encoding: zstd\r\n");
		ss_prints(&s, "Transfer-Encoding: chunked\r\n");
		break;
#endif
	default :
		ss_printf(&s, "Content-Length: %zd\r\n", body_len);
	}
	ss_prints(&s, "Connection: close\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));

	ss_done(&s);

	switch (z) {
#if HAVE_ZLIB
	case Z_ZLIB :
		mg_write_gzip(conn, body, body_len);
		break;
#endif
#if HAVE_ZSTD
	case Z_ZSTD :
		mg_write_zstd(conn, body, body_len);
		break;
#endif
	default :
		mg_write(conn, body, body_len);
	}

	/*
	 * If mg_write_* fails we just proceed to close the socket
	 * We already sent 200 OK headers, so we can't send a 500 now.
	 * We simply stop here. Do NOT send the "0\r\n\r\n".
	 * By exiting the handler, the connection will close.
	 */

	return 200;
}

static int is_not_modified(struct mg_connection *conn, time_t file_mtime)
{
	const char *if_mod_since = mg_get_header(conn, "If-Modified-Since");
	if (!if_mod_since)
		return 0;

	char date_buf[64];
	struct tm *tm = gmtime(&file_mtime);
	strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", tm);

	/* if the strings match exactly, the browser's cache is still valid */
	return strcmp(if_mod_since, date_buf) == 0;
}

static int handler_virtual_file(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);

	const char* target_uri = ri->local_uri;
	if (strcmp(target_uri, "/") == 0) {
		target_uri = "/index.html";
	}

	page_rdlock();

	time_t page_time = state->page_time;

	tommy_node* i = tommy_list_head(&state->page_list);
	while (i) {
		struct snapraid_page* page = i->data;

		if (strcmp(target_uri, page->path) == 0) {
			if (strcmp(ri->request_method, "OPTIONS") == 0) {
				page_unlock();
				return send_no_content(conn);
			}

			if (strcmp(ri->request_method, "GET") != 0) {
				page_unlock();
				return send_error(conn, 405);
			}

			/* check if browser already has the latest version */
			if (is_not_modified(conn, page_time)) {
				page_unlock();
				return send_error(conn, 304);
			}

			int status = send_file(conn, page_time, page->content, page->size, page->mime_type);
			page_unlock();
			return status;
		}

		i = i->next;
	}

	page_unlock();

	return 0;
}

static ssize_t read_file(const char* path, struct stat* st, char** body)
{
	int f = open(path, O_RDONLY);
	if (f == -1) {
		log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", path, strerror(errno), errno);
		return -1;
	}

	*body = malloc_nofail(st->st_size);

	if (read(f, *body, st->st_size) != st->st_size) {
		log_msg(LVL_ERROR, "crawler error reading %s, errno=%s(%d)", path, strerror(errno), errno);
		free(*body);
		close(f);
		return -1;
	}

	close(f);
	return st->st_size;
}

static int handler_real_file(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);

	const char* target_uri = ri->local_uri;

	if (strstr(target_uri, "..") != 0)
		return send_error(conn, 403);

	if (strcmp(target_uri, "/") == 0)
		target_uri = "/index.html";

	const char* mime = get_mime_type(target_uri);
	if (mime == 0)
		return send_error(conn, 403);

	state_lock();
	char root[PATH_MAX];
	sncpy(root, sizeof(root), state->config.net_web_root);
	state_unlock();

	char physical_path[PATH_MAX + 13];
	snprintf(physical_path, sizeof(physical_path), "%s/%s", root, target_uri);

	char resolved_path[PATH_MAX];
	if (realpath(physical_path, resolved_path) == 0)
		return 0; /* not a page, follow other handlers */

	char resolved_root[PATH_MAX];
	if (realpath(root, resolved_root) == 0)
		return 0; /* not a page, follow other handlers */

	size_t root_len = strlen(resolved_root);
	if (strncmp(resolved_path, resolved_root, root_len) != 0 || (resolved_path[root_len] != '\0' && resolved_path[root_len] != '/'))
		return send_error(conn, 403);

	struct stat st;
	if (lstat(resolved_path, &st) == -1)
		return 0; /* not a page, follow other handlers */

	if (!S_ISREG(st.st_mode))
		return send_error(conn, 403);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_error(conn, 405);

	/* check if browser already has the latest version */
	if (is_not_modified(conn, st.st_mtime))
		return send_error(conn, 304);

	char* body = 0;
	ssize_t body_len = read_file(resolved_path, &st, &body);
	if (body_len == -1) {
		return send_error(conn, 500);
	}

	int status = send_file(conn, st.st_mtime, body, body_len, mime);

	free(body);

	return status;
}

int web_init(struct snapraid_state* state, int nocache)
{
	state->page_cache = !nocache;

	if (state->page_cache) {
		if (web_reload(state, state->config.net_web_root) != 0)
			return -1;
		mg_set_request_handler(state->rest_context, "**", handler_virtual_file, state);
	} else {
		mg_set_request_handler(state->rest_context, "**", handler_real_file, state);
	}

	return 0;
}

void web_done(struct snapraid_state* state)
{
	(void)state;
}

int web_reload(struct snapraid_state* state, const char* root)
{
	page_wrlock();

	/* cleaup all pages */
	tommy_list_foreach(&state->page_list, page_free);
	tommy_list_init(&state->page_list);

	if (root[0] == 0) {
		page_unlock();
		return 0;
	}

	if (root[0] != '/') {
		log_msg(LVL_ERROR, "web server cannot serve relative %s", root);
		goto bail;
	}

	if (strstr(root, "..") != 0) {
		log_msg(LVL_ERROR, "web server cannot serve %s", root);
		goto bail;
	}

	/* trim ending slash of net_web_root */
	size_t len = strlen(root);
	while (len > 0 && root[len - 1] == '/')
		--len;

	if (root[0] == 0) {
		log_msg(LVL_ERROR, "web server cannot serve root directory /");
		goto bail;
	}

	state->page_time = time(0);
	crawl_directory(&state->page_list, len, root);

	page_unlock();

	return 0;

bail:
	page_unlock();
	return -1;
}

