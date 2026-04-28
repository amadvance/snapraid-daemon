// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "log.h"
#include "elem.h"
#include "support.h"
#include "daemon.h"
#include "zip.h"
#include "web.h"

void http_headers(struct mg_connection* conn, ss_t* s, time_t now, time_t last_modified, int net_security_headers, const char* net_allowed_origin)
{
	ss_printf(s, "Server: %s/%s\r\n", DAEMON, PACKAGE_VERSION);

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


	/*
	 * Forces the browser to always fetch fresh data from the daemon.
	 * 'no-store' prevents the sensitive JSON status from being saved to disk.
	 */
	ss_prints(s, "Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0\r\n");

	/* Legacy (HTTP/1.0): Support for HTTP/1.0 proxies */
	ss_prints(s, "Pragma: no-cache\r\n");

	/* Legacy (HTTP/1.0): Mark as expired immediately */
	ss_prints(s, "Expires: 0\r\n");

	/*
	 * Vary: Origin
	 * Crucial for 'self' reflection. It tells intermediate caches and proxies
	 * that the response depends on the 'Origin' header of the request,
	 * preventing a response meant for one user from being served to another.
	 *
	 * Vary: Accept-Encoding
	 * Compression depends on the Accept-Encoding
	 */
	ss_prints(s, "Vary: Origin, Accept-Encoding\r\n");

	/*
	 * These headers provide "Defense in Depth" against common web vulnerabilities.
	 */
	if (net_security_headers) {
		/*
		 * X-Frame-Options: SAMEORIGIN
		 * Prevents "Clickjacking" attacks. By setting this to SAMEORIGIN, the browser
		 * will only render this page inside an <iframe> if the parent page is
		 * hosted on the same origin (this daemon). It blocks malicious external
		 * sites from overlaying invisible buttons on top of your API controls.
		 */
		ss_prints(s, "X-Frame-Options: SAMEORIGIN\r\n");

		/* * X-Content-Type-Options: nosniff
		 * Prevents "MIME-sniffing" attacks. It forces the browser to trust the
		 * 'Content-Type' header sent by the daemon. Without this, a browser might
		 * guess that a .log file is actually a .js script and execute it,
		 * leading to potential XSS vulnerabilities.
		 */
		ss_prints(s, "X-Content-Type-Options: nosniff\r\n");

		/*
		 * Content-Security-Policy (CSP)
		 * The most powerful security header.
		 * - 'default-src self': Only allow scripts, styles, and images from this daemon.
		 * - 'frame-ancestors self': Modern version of X-Frame-Options; ensures only
		 * this daemon can embed its own pages.
		 */
		ss_prints(s, "Content-Security-Policy: default-src 'self'\r\n");

		/*
		 * Referrer-Policy: no-referrer
		 * Privacy protection. Ensures that if the user clicks a link to an external
		 * site (like the SnapRAID manual), the browser does not send the
		 * daemon's local IP or internal URL in the 'Referer' header.
		 */
		ss_prints(s, "Referrer-Policy: no-referrer\r\n");

		/*
		 * Cross-Origin-Opener-Policy: same-origin
		 * Context Isolation. Prevents other browser tabs from maintaining a
		 * reference to this window. This mitigates certain side-channel attacks
		 * (like Spectre) and prevents a malicious tab from "reaching into"
		 * the SnapRAID dashboard window via JavaScript.
		 */
		ss_prints(s, "Cross-Origin-Opener-Policy: same-origin\r\n");
	}

	/*
	 * These headers allow or deny specific web applications from making
	 * asynchronous (AJAX/Fetch) calls to the SnapRAID API.
	 */
	if (strcmp(net_allowed_origin, "none") != 0) {
		/*
		 * Access-Control-Allow-Origin
		 * Tells the browser which website is allowed to read the API response.
		 * - If 'self', we reflect the 'Host' header to allow local UI access.
		 * - If a URL is provided, we whitelist only that specific dashboard.
		 */
		if (strcmp(net_allowed_origin, "self") == 0) {
			const char* host = mg_get_header(conn, "Host");
			ss_printf(s, "Access-Control-Allow-Origin: http://%s\r\n", host ? host : "null");
		} else {
			ss_printf(s, "Access-Control-Allow-Origin: %s\r\n", net_allowed_origin);
		}

		/*
		 * Access-Control-Allow-Methods & Headers
		 * These are required for the "Pre-flight" check (OPTIONS request).
		 * Browsers will check these before allowing a POST or DELETE request
		 * to ensure the daemon supports those actions and the 'Content-Type' header.
		 */
		ss_prints(s, "Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS\r\n");
		ss_prints(s, "Access-Control-Allow-Headers: Content-Type, Authorization\r\n");
	}
}

static ssize_t read_fd(int fd, void* buffer, ssize_t size)
{
	char* p = buffer;
	ssize_t total = 0;

	while (total < size) {
		ssize_t r = read(fd, p + total, size - total);

		if (r == 0) { /* EOF */
			return -1;
		}

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		total += r;
	}

	return total;
}

static ssize_t read_file(const char* path, struct stat* st, char** body)
{
	int f = open(path, O_RDONLY | O_BINARY);
	if (f == -1) {
		log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", path, strerror(errno), errno);
		return -1;
	}

	*body = malloc_nofail(st->st_size);

	if (read_fd(f, *body, st->st_size) != st->st_size) {
		log_msg(LVL_ERROR, "crawler error reading %s, errno=%s(%d)", path, strerror(errno), errno);
		close(f);
		free(*body);
		*body = 0;
		return -1;
	}

	close(f);
	return st->st_size;
}

#ifndef _WIN32
#define FD_ARG(v) v
#else
#define FD_ARG(v) - 1
#endif

static void crawl_directory_fd(tommy_list* page_list, size_t skip, int current_fd, const char* current_path)
{
#ifdef _WIN32
	(void)current_fd;
	DIR* d = opendir(current_path);
#else
	DIR* d = fdopendir(current_fd);
#endif
	if (!d) {
		log_msg(LVL_ERROR, "crawler error fdopendir %s, errno=%s(%d)", current_path, strerror(errno), errno);
#ifndef _WIN32
		close(current_fd);
#endif
		return;
	}

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

		char path[PATH_MAX + PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", current_path, dd->d_name);

		struct stat st;
#ifndef _WIN32
		int fd = openat(current_fd, dd->d_name, O_RDONLY | O_NOFOLLOW);
		if (fd == -1) {
			if (errno == ELOOP) {
				log_msg(LVL_WARNING, "crawler ignore link %s/%s", current_path, dd->d_name);
			} else {
				log_msg(LVL_ERROR, "crawler error openat %s, errno=%s(%d)", path, strerror(errno), errno);
			}
			continue;
		}

		if (fstat(fd, &st) != 0) {
			log_msg(LVL_ERROR, "crawler error fstat %s, errno=%s(%d)", path, strerror(errno), errno);
			close(fd);
			continue;
		}
#else
		if (lstat(path, &st) != 0) {
			log_msg(LVL_ERROR, "crawler error fstat %s, errno=%s(%d)", path, strerror(errno), errno);
			continue;
		}
#endif

		if (S_ISDIR(st.st_mode)) {
			crawl_directory_fd(page_list, skip, FD_ARG(fd), path);
			continue; /* fd consumed by recursion */
		} else if (S_ISREG(st.st_mode)) {
			const char* relative = path + skip;
			const char* mime_type = get_mime_type(relative);
			if (mime_type == 0) {
				log_msg(LVL_WARNING, "crawler ignore unknown file %s", path);
				continue;
			}

			struct snapraid_page* page = page_alloc(relative, st.st_size);

#ifdef _WIN32
			int fd = open(path, O_RDONLY | O_BINARY);
			if (fd == -1) {
				log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", path, strerror(errno), errno);
				return;
			}
#endif
			if (read_fd(fd, page->content, page->size) != page->size) {
				log_msg(LVL_ERROR, "crawler error reading %s, errno=%s(%d)", path, strerror(errno), errno);
				close(fd);
				page_free(page);
				continue;
			}

			close(fd);

			page->mime_type = mime_type;

			tommy_list_insert_tail(page_list, &page->node, page);
		} else {
			log_msg(LVL_WARNING, "crawler ignore special file %s", path);
#ifndef _WIN32
			close(fd);
#endif
		}
	}

	closedir(d); /* closes current_fd */
}

static void crawl_directory(tommy_list* page_list, size_t skip, const char* current_path)
{
#ifndef _WIN32
	int fd = open(current_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1) {
		log_msg(LVL_ERROR, "crawler error opening %s, errno=%s(%d)", current_path, strerror(errno), errno);
		return;
	}
#endif

	crawl_directory_fd(page_list, skip, FD_ARG(fd), current_path);
}

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

	http_headers(conn, s, now, last_modified, net_security_headers, net_allowed_origin);
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

static int is_not_modified(struct mg_connection* conn, time_t file_mtime)
{
	const char* if_mod_since = mg_get_header(conn, "If-Modified-Since");
	if (!if_mod_since)
		return 0;

	char date_buf[64];
	struct tm tm_gmt;
	gmtime_r(&file_mtime, &tm_gmt);
	strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_gmt);

	/* if the strings match exactly, the browser's cache is still valid */
	return strcmp(if_mod_since, date_buf) == 0;
}

static int handler_virtual_file(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);

	const char* target_uri = ri->local_uri;
	if (!target_uri)
		return send_error(conn, 403);

	if (strcmp(target_uri, "/") == 0)
		target_uri = "/index.html";

	web_rdlock();

	time_t page_time = state->web.page_time;

	tommy_node* i = tommy_list_head(&state->web.page_list);
	while (i) {
		struct snapraid_page* page = i->data;

		if (strcmp(target_uri, page->path) == 0) {
			if (strcmp(ri->request_method, "OPTIONS") == 0) {
				web_unlock();
				return send_no_content(conn);
			}

			if (strcmp(ri->request_method, "GET") != 0) {
				web_unlock();
				return send_error(conn, 405);
			}

			/* check if browser already has the latest version */
			if (is_not_modified(conn, page_time)) {
				web_unlock();
				return send_error(conn, 304);
			}

			int status = send_file(conn, page_time, page->content, page->size, page->mime_type);
			web_unlock();
			return status;
		}

		i = i->next;
	}

	web_unlock();

	return 0;
}

static int handler_real_file(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);

	const char* target_uri = ri->local_uri;
	if (!target_uri)
		return send_error(conn, 403);

	if (strstr(target_uri, "..") != 0)
		return send_error(conn, 403);

	if (strcmp(target_uri, "/") == 0)
		target_uri = "/index.html";

	const char* mime_type = get_mime_type(target_uri);
	if (mime_type == 0)
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
	if (strncmp(resolved_path, resolved_root, root_len) != 0 || (resolved_path[root_len] != 0 && resolved_path[root_len] != '/'))
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

	int status = send_file(conn, st.st_mtime, body, body_len, mime_type);

	free(body);

	return status;
}

int web_init(struct snapraid_state* state)
{
	if (!state->web.page_nocache) {
		if (web_reload(state, state->config.net_web_root) != 0)
			return -1;
		mg_set_request_handler(state->rest_context, "**", handler_virtual_file, state);
	} else {
		log_msg(LVL_INFO, "serving web root %s", state->config.net_web_root);
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
	web_wrlock();

	/* cleaup all pages */
	tommy_list_foreach(&state->web.page_list, page_free);
	tommy_list_init(&state->web.page_list);

	if (root[0] == 0) {
		web_unlock();
		return 0;
	}

	if (strstr(root, "..") != 0) {
		log_msg(LVL_ERROR, "web server cannot serve %s", root);
		goto bail;
	}

	const char* dot = strrchr(root, '.');
	if (dot != 0 && strcmp(dot, ".zip") == 0) {
		char zip[PATH_MAX];
		if (strchr(root, '/') == 0) {
			/* if it's just the file name, use the default data dir */
			os_default_data(zip, sizeof(zip), root);
		} else {
			sncpy(zip, sizeof(zip), root);
		}

		state->web.page_time = time(0);
		log_msg(LVL_INFO, "crawling zip %s", zip);
		crawl_zip(&state->web.page_list, zip);
	} else {
		if (root[0] != '/') {
			log_msg(LVL_ERROR, "web server cannot serve relative %s", root);
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

		state->web.page_time = time(0);
		log_msg(LVL_INFO, "crawling directory %s", root);
		crawl_directory(&state->web.page_list, len, root);
	}

	web_unlock();

	return 0;

bail:
	web_unlock();
	return -1;
}

