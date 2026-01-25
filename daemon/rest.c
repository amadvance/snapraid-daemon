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
#include "support.h"
#include "runner.h"
#include "conf.h"
#include "log.h"
#include "elem.h"
#include "scheduler.h"
#include "rest.h"

/****************************************************************************/
/* jsmn */

#define JSMN_STRICT
#include "../jsmn/jsmn.h"

/**
 * Max number of JSON tokens
 */
#define JSMN_TOKEN_MAX 128

/**
 * Initial size for building JSON text
 */
#define JSON_INITIAL_SIZE 512

/**
 * Max size of the JSON text
 */
#define JSON_MAX_SIZE 16384

/****************************************************************************/
/* json */

#define json_const(v) v, sizeof(v) - 1

static char* json_token(char* js, jsmntok_t* jv)
{
	js[jv[0].end] = 0;
	return &js[jv[0].start];
}

static int json_entry(const char* js, jsmntok_t* jv, const char* field, ssize_t field_len)
{
	/* check if the field is matching */
	if (jv[0].type != JSMN_STRING
		|| field_len != jv[0].end - jv[0].start
		|| strncmp(js + jv[0].start, field, field_len) != 0)
		return -1;

	/* ensure that there is only one child  */
	if (jv[0].size != 1)
		return -1;

	/* STRING and PRIMITIVE should have no children */
	if ((jv[1].type == JSMN_STRING || jv[1].type == JSMN_PRIMITIVE) && jv[1].size != 0)
		return -1;

	return 0;
}

static int json_type(const char* js, jsmntok_t* jv, const char* field, ssize_t field_len, unsigned type)
{
	if (json_entry(js, jv, field, field_len) != 0)
		return -1;

	/* ensure that it has the correct type */
	if (jv[1].type != type)
		return -1;

	return 0;
}

static int json_value(const char* js, jsmntok_t* jv, int low, int high, int* out)
{
	const int limit_div = INT_MAX / 10;
	const int limit_rem = INT_MAX % 10;
	int v;
	int i;

	if (jv[0].type != JSMN_PRIMITIVE)
		return -1;

	v = 0;
	for (i = jv[0].start; i < jv[0].end; ++i) {
		unsigned d;

		if (js[i] < '0' || js[i] > '9')
			return -1;

		d = js[i] - '0';

		if (v > limit_div || (v == limit_div && d > limit_rem))
			return -1; /* overflow */

		v = v * 10 + d;
	}

	if (v < low || v > high)
		return -1;

	*out = v;
	return 0;
}

static int json_boolean(const char* js, jsmntok_t* jv, int* out)
{
	if (jv[0].type != JSMN_PRIMITIVE)
		return -1;

	if (5 == jv[0].end - jv[0].start
		&& strncmp(js + jv[0].start, "false", 5) == 0) {
		*out = 0;
		return 0;
	}

	if (4 == jv[0].end - jv[0].start
		&& strncmp(js + jv[0].start, "true", 4) == 0) {
		*out = 1;
		return 0;
	}

	return -1;
}

static int json_string(const char* js, jsmntok_t* jv, char* out, size_t out_size)
{
	size_t len = jv[0].end - jv[0].start;

	if (jv[0].type != JSMN_STRING
		|| len + 1 > out_size)
		return -1;

	memcpy(out, &js[jv[0].start], len);
	out[len] = 0;

	return 0;
}

static int json_string_inplace(char* js, jsmntok_t* jv, char** out)
{
	if (jv[0].type != JSMN_STRING)
		return -1;

	*out = json_token(js, jv);

	return 0;
}

static void json_error_parse(char* str, size_t str_size, int jc)
{
	switch (jc) {
	case 0 : snprintf(str, str_size, "Empty JSON"); break;
	case JSMN_ERROR_NOMEM : snprintf(str, str_size, "JSON too long"); break;
	case JSMN_ERROR_INVAL : snprintf(str, str_size, "Invalid character inside JSON string"); break;
	case JSMN_ERROR_PART : snprintf(str, str_size, "Partial JSON"); break;
	default : snprintf(str, str_size, "Unknown JSON error"); break;
	}
	;
}

static void json_error_arg(char* str, size_t str_size, char* js, jsmntok_t* je, jsmntok_t* ja)
{
	snprintf(str, str_size, "Invalid JSON argument %s for %s", json_token(js, ja), json_token(js, je));
}

static void json_error_entry(char* str, size_t str_size, char* js, jsmntok_t* jv)
{
	snprintf(str, str_size, "Unrecognized JSON token %s", json_token(js, jv));
}

static void json_error_forbidden(char* str, size_t str_size, char* js, jsmntok_t* jv)
{
	snprintf(str, str_size, "Modification of restricted parameter '%s' is disabled by host configuration.", json_token(js, jv));
}

static int json_read(struct mg_connection* conn, char** js, ssize_t* jl, char* msg, size_t msg_size)
{
	ss_t s;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	ssize_t content_length = ri->content_length;

	/* If Content-Length is missing, assume no Payload */
	if (content_length < 0) {
		*js = 0;
		*jl = 0;
		return 200;
	}

	if (content_length >= JSON_MAX_SIZE) {
		sncpy(msg, msg_size, "Payload Too Large");
		return 413;
	}

	ss_init(&s, content_length);

	while (ss_len(&s) < content_length) {
		int r = mg_read(conn, ss_top(&s), ss_avail(&s));
		if (r <= 0) {
			sncpy(msg, msg_size, "Payload Too Short");
			return 400;
		}

		ss_forward(&s, r);
	}

	*js = ss_ptr(&s);
	*jl = ss_len(&s);

	return 200;
}

/****************************************************************************/
/* helper */

#define HTTP_HEADERS_MAX 512

/**
 * Generates and prints security and CORS headers into the provided string builder.
 * These headers protect the SnapRAID daemon from cross-site attacks and ensure
 * that only authorized web origins can communicate with the API.
 */
static void send_headers(struct mg_connection* conn, ss_t* s)
{
	int net_security_headers;
	char net_allowed_origin[CONFIG_MAX];

	/* obtain the security configuration */
	state_lock();
	net_security_headers = state_ptr()->config.net_security_headers;
	sncpy(net_allowed_origin, sizeof(net_allowed_origin), state_ptr()->config.net_allowed_origin);
	state_unlock();

	ss_printf(s, "Server: %s/%s\r\n", PACKAGE_NAME, PACKAGE_VERSION);

	/*
	 * Forces the browser to always fetch fresh data from the daemon.
	 * 'no-store' prevents the sensitive JSON status from being saved to disk.
	 */
	ss_prints(s, "Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0\r\n");

	/* Legacy support for HTTP/1.0 proxies */
	ss_prints(s, "Pragma: no-cache\r\n");

	/* Mark as expired immediately */
	ss_prints(s, "Expires: 0\r\n");

	char date_buf[64];
	struct tm tm_gmt;
	time_t now = time(0);
	gmtime_r(&now, &tm_gmt);

	/* RFC 7231 / RFC 1123 format: Weekday, Day Month Year Time GMT */
	strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_gmt);
	ss_printf(s, "Date: %s\r\n", date_buf);

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
		ss_prints(s, "Content-Security-Policy: default-src 'self'; frame-ancestors 'self';\r\n");

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

		/* * Vary: Origin
		 * Crucial for 'self' reflection. It tells intermediate caches and proxies
		 * that the response depends on the 'Origin' header of the request,
		 * preventing a response meant for one user from being served to another.
		 */
		ss_prints(s, "Vary: Origin\r\n");

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

static void send_json_answer(struct mg_connection* conn, int status, ss_t* body)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	int body_len = ss_len(body);

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s);
	ss_prints(&s, "Content-Type: application/json\r\n");
	ss_printf(&s, "Content-Length: %d\r\n", body_len);
	ss_prints(&s, "Connection: close\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));
	mg_write(conn, ss_ptr(body), ss_len(body));

	ss_done(&s);
}

static int send_json_success(struct mg_connection* conn, int status)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	char body[256];
	int body_len = snprintf(body, sizeof(body), "{\n  \"success\": true\n}\n");

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s);
	ss_prints(&s, "Content-Type: application/json\r\n");
	ss_printf(&s, "Content-Length: %d\r\n", body_len);
	ss_prints(&s, "Connection: close\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));
	mg_write(conn, body, body_len);

	ss_done(&s);

	return status;
}

static int send_json_error(struct mg_connection* conn, int status, const char* message)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	char body[256];
	int body_len = snprintf(body, sizeof(body), "{\n  \"success\": false,\n  \"message\": \"%s\"\n}\n", message);

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s);
	ss_prints(&s, "Content-Type: application/json\r\n");
	ss_printf(&s, "Content-Length: %d\r\n", body_len);
	ss_prints(&s, "Connection: close\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));
	mg_write(conn, body, body_len);

	ss_done(&s);

	return status;
}

static int send_options(struct mg_connection* conn)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	ss_prints(&s, "HTTP/1.1 204 No Content\r\n");
	send_headers(conn, &s);
	ss_prints(&s, "Content-Length: 0\r\n");
	ss_prints(&s, "Connection: close\r\n\r\n");
	ss_prints(&s, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));

	ss_done(&s);
	return 204;
}

/****************************************************************************/
/* handler */

static int handler_not_found(struct mg_connection* conn, void* cbdata)
{
	(void)cbdata;
	return send_json_error(conn, 404, "Resource not found");
}

/**
 * PATCH /api/v1/config
 */
static int handler_config_patch(struct mg_connection* conn, void* cbdata)
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	int status;
	jsmntok_t jv[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	ssize_t jl;
	char* js;
	int jc;

	status = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (status != 200)
		return send_json_error(conn, status, msg);

	state_lock();

	jsmn_init(&jp);
	jc = jsmn_parse(&jp, js, jl, jv, JSMN_TOKEN_MAX);
	if (jc <= 0) {
		json_error_parse(msg, sizeof(msg), jc);
		goto bad;
	} else {
		int c0;
		int j = 0;
		if (jv[j].type != JSMN_OBJECT) {
			snprintf(msg, sizeof(msg), "Missing root JSON object");
			goto bad;
		}
		c0 = jv[j++].size;
		while (c0-- > 0) {
			char buf[128];
			if (json_entry(js, &jv[j], json_const("maintenance_schedule")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& config_parse_maintenance_schedule(buf, &state->config) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("probe_interval_minutes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 1440, &state->config.probe_interval_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.probe_interval_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("spindown_idle_minutes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 1440, &state->config.spindown_idle_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.spindown_idle_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_deletes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.sync_threshold_deletes) == 0) {
				} else {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_threshold_deletes);
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_updates")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.sync_threshold_updates) == 0) {
				} else {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_threshold_updates);
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_prehash")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.sync_prehash) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_prehash);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_force_zero")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.sync_force_zero) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_force_zero);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_percentage")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 100, &state->config.scrub_percentage) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.scrub_percentage);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_older_than")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 1000, &state->config.scrub_older_than) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.scrub_older_than);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("script_run_as_user")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.script_run_as_user, sizeof(state->config.script_run_as_user)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("script_pre_run")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.script_pre_run, sizeof(state->config.script_pre_run)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("script_post_run")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.script_post_run, sizeof(state->config.script_post_run)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("log_directory")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.log_directory, sizeof(state->config.log_directory)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("log_retention_days")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.log_retention_days) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.log_retention_days);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_enabled")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.notify_syslog_enabled) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.notify_syslog_enabled);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& config_parse_level(buf, &state->config.notify_syslog_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_run_as_user")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.notify_run_as_user, sizeof(state->config.notify_run_as_user)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_heartbeat")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.notify_heartbeat, sizeof(state->config.notify_heartbeat)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_result")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.notify_result, sizeof(state->config.notify_result)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_result_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& config_parse_level(buf, &state->config.notify_result_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_email_recipient")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.notify_email_recipient, sizeof(state->config.notify_email_recipient)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_email_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& config_parse_level(buf, &state->config.notify_email_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_differences")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.notify_differences) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.notify_differences);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else {
				json_error_entry(msg, sizeof(msg), js, &jv[j]);
				goto bad;
			}
		}
	}

	(void)config_save(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_success(conn, 200);

bad:
	(void)config_save(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_error(conn, 400, msg);

forbidden:
	(void)config_save(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_error(conn, 403, msg);
}

/**
 * GET /api/v1/config
 */
static int handler_config_get(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	struct snapraid_config* config = &state->config;
	int level = 0;
	ss_t s;
	char schedule_buf[64];

	state_lock();

	ss_init(&s, JSON_INITIAL_SIZE);

	config_schedule_str(config, schedule_buf, sizeof(schedule_buf));

	ss_json_open(&s, &level);
	ss_json_str(&s, level, "maintenance_schedule", schedule_buf);
	ss_json_int(&s, level, "sync_threshold_deletes", config->sync_threshold_deletes);
	ss_json_int(&s, level, "sync_threshold_updates", config->sync_threshold_updates);
	ss_json_bool(&s, level, "sync_prehash", config->sync_prehash);
	ss_json_bool(&s, level, "sync_force_zero", config->sync_force_zero);
	ss_json_int(&s, level, "scrub_percentage", config->scrub_percentage);
	ss_json_int(&s, level, "scrub_older_than", config->scrub_older_than);

	ss_json_int(&s, level, "probe_interval_minutes", config->probe_interval_minutes);
	ss_json_int(&s, level, "spindown_idle_minutes", config->spindown_idle_minutes);

	ss_json_str(&s, level, "script_run_as_user", config->script_run_as_user);
	ss_json_str(&s, level, "script_pre_run", config->script_pre_run);
	ss_json_str(&s, level, "script_post_run", config->script_post_run);

	ss_json_str(&s, level, "log_directory", config->log_directory);
	ss_json_int(&s, level, "log_retention_days", config->log_retention_days);

	ss_json_bool(&s, level, "notify_syslog_enabled", config->notify_syslog_enabled);
	ss_json_str(&s, level, "notify_syslog_level", config_level_str(config->notify_syslog_level));

	ss_json_str(&s, level, "notify_run_as_user", config->notify_run_as_user);
	ss_json_str(&s, level, "notify_heartbeat", config->notify_heartbeat);
	ss_json_str(&s, level, "notify_result", config->notify_result);
	ss_json_str(&s, level, "notify_result_level", config_level_str(config->notify_result_level));

	ss_json_str(&s, level, "notify_email_recipient", config->notify_email_recipient);
	ss_json_str(&s, level, "notify_email_level", config_level_str(config->notify_email_level));

	ss_json_bool(&s, level, "notify_differences", config->notify_differences);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

static int handler_config(struct mg_connection* conn, void* cbdata)
{
	const struct mg_request_info* ri = mg_get_request_info(conn);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") == 0)
		return handler_config_get(conn, cbdata);

	if (strcmp(ri->request_method, "PATCH") == 0)
		return handler_config_patch(conn, cbdata);

	return send_json_error(conn, 405, "Only GET/PATCH is allowed for this endpoint");
}

/**
 * POST /api/v1/COMMAND
 */
static int handler_action(struct mg_connection* conn, void* cbdata)
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	const char* path = ri->local_uri;
	int status;
	jsmntok_t jv[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	ssize_t jl;
	char* js;
	int jc;
	sl_t arg_list;

	sl_init(&arg_list);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	int cmd = 0;
	const char* arg = 0;
	if (strncmp(path, "/api/v1/", 8) == 0)
		cmd = command_parse(path + 8);
	switch (cmd) {
	case 0 :
		return send_json_error(conn, 404, "Resource not found");
	case CMD_MAINTENANCE :
	case CMD_HEAL :
	case CMD_DOWN_IDLE :
		break;
	case CMD_UNDELETE :
		arg = "filters";
		break;
	default :
		arg = "args";
		break;
	}

	status = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (status != 200)
		return send_json_error(conn, status, msg);

	jsmn_init(&jp);
	jc = jsmn_parse(&jp, js, jl, jv, JSMN_TOKEN_MAX);
	if (jc < 0) {
		json_error_parse(msg, sizeof(msg), jc);
		goto bad;
	} else if (jc == 0) {
		/* accept an empty request */
	} else {
		int c0;
		int j = 0;
		if (jv[j].type != JSMN_OBJECT) {
			snprintf(msg, sizeof(msg), "Missing root JSON object");
			goto bad;
		}
		c0 = jv[j++].size;
		while (c0-- > 0) {
			if (arg != 0 && json_type(js, &jv[j], json_const(arg), JSMN_ARRAY) == 0) {
				int j1 = j;
				int c1 = jv[++j].size;
				++j;
				while (c1-- > 0) {
					char* val;
					if (json_string_inplace(js, &jv[j], &val) == 0) {
						sl_insert_str(&arg_list, val);
					} else {
						json_error_arg(msg, sizeof(msg), js, &jv[j1], &jv[j]);
						goto bad;
					}
					++j;
				}
			} else {
				json_error_entry(msg, sizeof(msg), js, &jv[j]);
				goto bad;
			}
		}
	}

	switch (cmd) {
	case CMD_MAINTENANCE :
		schedule_maintenance(state, msg, sizeof(msg), &status);
		break;
	case CMD_HEAL :
		schedule_heal(state, msg, sizeof(msg), &status);
		break;
	case CMD_UNDELETE :
		schedule_undelete(state, &arg_list, msg, sizeof(msg), &status);
		break;
	case CMD_DOWN_IDLE :
		schedule_down_idle(state, msg, sizeof(msg), &status);
		break;
	default :
		runner(state, cmd, 0, &arg_list, msg, sizeof(msg), &status);
	}

	free(js);
	sl_free(&arg_list);

	if (status >= 200 && status <= 299)
		return send_json_success(conn, status);
	else
		return send_json_error(conn, status, msg);

bad:
	free(js);
	return send_json_error(conn, 400, "Unrecognized json");
}

/**
 * POST /api/v1/stop
 */
static int handler_stop(struct mg_connection* conn, void* cbdata)
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int status;
	pid_t pid = 0;
	int number = 0;
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	if (runner_stop(state, msg, sizeof(msg), &status, &pid, &number) != 0)
		return send_json_error(conn, status, msg);

	ss_init(&s, JSON_INITIAL_SIZE);

	ss_json_open(&s, &level);
	ss_json_bool(&s, level, "success", 1);
	ss_json_str(&s, level, "message", "Signal sent");
	ss_json_int(&s, level, "number", number);
	ss_json_u64(&s, level, "pid", pid);
	ss_json_close(&s, &level);

	send_json_answer(conn, status, &s);

	ss_done(&s);

	return status;
}

/**
 * POST /api/v1/report
 */
static int handler_report(struct mg_connection* conn, void* cbdata)
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int status;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	runner(state, CMD_REPORT, 0, 0, msg, sizeof(msg), &status);

	if (status >= 200 && status <= 299)
		return send_json_success(conn, status);
	else
		return send_json_error(conn, status, msg);
}

static void json_device_list(ss_t* s, int level, tommy_list* list)
{
	++level;
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* dev = i->data;
		ss_json_open(s, &level);
		ss_json_str(s, level, "device_node", dev->file);
		ss_json_int(s, level, "split_index", dev->split_index);
		ss_json_str(s, level, "health", health_name(dev->health));
		if (*dev->family)
			ss_json_str(s, level, "family", dev->family);
		if (*dev->model)
			ss_json_str(s, level, "model", dev->model);
		if (*dev->serial)
			ss_json_str(s, level, "serial", dev->serial);
		ss_json_str(s, level, "power", power_name(dev->power));
		if (dev->size != SMART_UNASSIGNED)
			ss_json_u64(s, level, "size_bytes", dev->size);
		if (dev->rotational != SMART_UNASSIGNED)
			ss_json_u64(s, level, "rotational", dev->rotational);
		if (dev->error_protocol != SMART_UNASSIGNED)
			ss_json_u64(s, level, "error_protocol", dev->error_protocol);
		if (dev->error_medium != SMART_UNASSIGNED)
			ss_json_u64(s, level, "error_medium", dev->error_medium);
		if (dev->wear_level != SMART_UNASSIGNED)
			ss_json_u64(s, level, "wear_level", dev->wear_level);
		if (dev->afr != 0)
			ss_json_double(s, level, "annual_failure_rate", dev->afr);
		if (dev->prob != 0)
			ss_json_double(s, level, "failure_probability", dev->prob);
		ss_json_object_open(s, &level, "smart");
		if (dev->smart[SMART_REALLOCATED_SECTOR_COUNT] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "reallocated_sector_count", dev->smart[SMART_REALLOCATED_SECTOR_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "uncorrectable_error_cnt", dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] & 0xFFFF);
		if (dev->smart[SMART_COMMAND_TIMEOUT] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "command_timeout", dev->smart[SMART_COMMAND_TIMEOUT] & 0xFFFF);
		if (dev->smart[SMART_CURRENT_PENDING_SECTOR] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "current_pending_sector", dev->smart[SMART_CURRENT_PENDING_SECTOR] & 0xFFFFFFFF);
		if (dev->smart[SMART_OFFLINE_UNCORRECTABLE] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "offline_uncorrectable", dev->smart[SMART_OFFLINE_UNCORRECTABLE] & 0xFFFFFFFF);
		if (dev->smart[SMART_START_STOP_COUNT] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "start_stop_count", dev->smart[SMART_START_STOP_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_LOAD_CYCLE_COUNT] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "power_on_hours", dev->smart[SMART_LOAD_CYCLE_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_POWER_ON_HOURS] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "load_cycle_count", dev->smart[SMART_POWER_ON_HOURS] & 0xFFFFFFFF);
		if (dev->smart[SMART_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "temperature_celsius", dev->smart[SMART_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		else if (dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_json_u64(s, level, "temperature_celsius", dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		if (dev->flags != SMART_UNASSIGNED) {
			ss_json_bool(s, level, "failing", dev->flags & SMARTCTL_FLAG_FAIL);
			ss_json_bool(s, level, "prefail", dev->flags & SMARTCTL_FLAG_PREFAIL);
			ss_json_bool(s, level, "prefail_logged", dev->flags & SMARTCTL_FLAG_PREFAIL_LOGGED);
			ss_json_bool(s, level, "error_logged", dev->flags & SMARTCTL_FLAG_ERROR_LOGGED);
			ss_json_bool(s, level, "selferror_logged", dev->flags & SMARTCTL_FLAG_SELFERROR_LOGGED);
		}
		ss_json_close(s, &level);
		ss_json_close(s, &level);
	}
}

static void json_disk_list(ss_t* s, int level, tommy_list* list)
{
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		ss_json_open(s, &level);
		ss_json_str(s, level, "name", disk->name);
		ss_json_str(s, level, "health", health_name(health_disk(disk)));
		// TODO power
		if (disk->content_size != SMART_UNASSIGNED)
			ss_json_u64(s, level, "allocated_space_bytes", disk->content_size);
		if (disk->content_free != SMART_UNASSIGNED)
			ss_json_u64(s, level, "free_space_bytes", disk->content_free);
		if (disk->access_count != 0) {
			ss_json_i64(s, level, "access_count", disk->access_count);
			ss_json_pair_iso8601(s, level, "access_count_initial_time", disk->access_count_initial_time);
			ss_json_i64(s, level, "access_count_idle_duration", disk->access_count_latest_time - disk->access_count_initial_time);
		}
		ss_json_i64(s, level, "error_io", disk->error_io);
		ss_json_i64(s, level, "error_data", disk->error_data);

		ss_json_array_open(s, &level, "splits");
		for (tommy_node* j = tommy_list_head(&disk->split_list); j; j = j->next) {
			struct snapraid_split* split = j->data;

			ss_json_open(s, &level);
			if (*split->uuid)
				ss_json_str(s, level, "uuid", split->uuid);
			if (*split->content_uuid)
				ss_json_str(s, level, "stored_uuid", split->content_uuid);
			ss_json_str(s, level, "path", split->path);
			ss_json_close(s, &level);
		}
		ss_json_array_close(s, &level);

		ss_json_array_open(s, &level, "devices");
		json_device_list(s, level, &disk->device_list);
		ss_json_array_close(s, &level);
		ss_json_close(s, &level);
	}
}

/**
 * GET /api/v1/disks
 * Returns detailed disk status lists
 */
static int handler_disks(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	ss_json_array_open(&s, &level, "data_disks");
	json_disk_list(&s, level, &state->data_list);
	ss_json_array_close(&s, &level);
	ss_json_array_open(&s, &level, "parity_disks");
	json_disk_list(&s, level, &state->parity_list);
	ss_json_array_close(&s, &level);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

static void json_task(ss_t* s, int level, struct snapraid_task* task)
{
	ss_json_open(s, &level);
	ss_json_int(s, level, "number", task->number);
	ss_json_str(s, level, "command", command_name(task->cmd));
	ss_json_str(s, level, "health", health_name(health_task(task)));
	if (task->running) {
		switch (task->state) {
		case PROCESS_STATE_START : ss_json_str(s, level, "status", "starting"); break;
		case PROCESS_STATE_RUN : ss_json_str(s, level, "status", "processing"); break;
		case PROCESS_STATE_TERM : ss_json_str(s, level, "status", "finalizing"); break;
		case PROCESS_STATE_SIGNAL : ss_json_str(s, level, "status", "stopping"); break;
		}
	} else {
		switch (task->state) {
		case PROCESS_STATE_QUEUE :
			ss_json_str(s, level, "status", "queued");
			break;
		case PROCESS_STATE_SIGNAL :
			ss_json_str(s, level, "status", "signaled");
			ss_json_int(s, level, "exit_sig", task->exit_sig);
			break;
		case PROCESS_STATE_CANCEL :
			ss_json_str(s, level, "status", "canceled");
			ss_json_str(s, level, "exit_msg", task->exit_msg);
			break;
		case PROCESS_STATE_TERM :
			ss_json_str(s, level, "status", "terminated");
			ss_json_int(s, level, "exit_code", task->exit_code);
			break;
		}
	}
	if (task->unix_queue_time)
		ss_json_pair_iso8601(s, level, "scheduled_at", task->unix_queue_time);
	if (task->unix_start_time != 0)
		ss_json_pair_iso8601(s, level, "started_at", task->unix_start_time);
	if (task->unix_end_time != 0)
		ss_json_pair_iso8601(s, level, "finished_at", task->unix_end_time);
	if (task->cmd == CMD_SYNC || task->cmd == CMD_SCRUB
		|| task->cmd == CMD_FIX || task->cmd == CMD_CHECK) {
		switch (task->state) {
		case PROCESS_STATE_RUN :
		case PROCESS_STATE_TERM :
		case PROCESS_STATE_SIGNAL :
			ss_json_int(s, level, "progress", task->progress);
			ss_json_uint(s, level, "eta_seconds", task->eta_seconds);
			ss_json_uint(s, level, "speed_mbs", task->speed_mbs);
			ss_json_uint(s, level, "cpu_usage", task->cpu_usage);
			ss_json_uint(s, level, "elapsed_seconds", task->elapsed_seconds);
			ss_json_uint(s, level, "block_begin", task->block_begin);
			ss_json_uint(s, level, "block_end", task->block_end);
			ss_json_uint(s, level, "block_count", task->block_count);
			ss_json_uint(s, level, "block_idx", task->block_idx);
			ss_json_uint(s, level, "block_done", task->block_done);
			ss_json_u64(s, level, "size_done_bytes", task->size_done);
			break;
		}
	}
	if (task->log_file[0])
		ss_json_str(s, level, "log_file", task->log_file);

	if (task->text_report)
		ss_json_str(s, level, "report_output", task->text_report);

	ss_json_array_open(s, &level, "messages");
	for (tommy_node* i = tommy_list_head(&task->message_list); i; i = i->next) {
		sn_t* message = i->data;
		ss_json_elem(s, level, message->str);
	}
	ss_json_array_close(s, &level);

	switch (task->cmd) {
	case CMD_SYNC :
	case CMD_SCRUB :
		ss_json_i64(s, level, "error_soft", task->error_soft + task->hash_error_soft);
		ss_json_i64(s, level, "error_io", task->error_io);
		ss_json_i64(s, level, "error_data", task->error_data);
		ss_json_i64(s, level, "block_bad", task->block_bad);
		break;
	case CMD_FIX :
	case CMD_CHECK :
		ss_json_i64(s, level, "error_unrecoverable", task->error_unrecoverable);
		ss_json_i64(s, level, "error_soft", task->error_soft + task->hash_error_soft);
		ss_json_i64(s, level, "error_io", task->error_io);
		ss_json_i64(s, level, "error_data", task->error_data);
		ss_json_i64(s, level, "block_bad", task->block_bad);
		break;
	case CMD_STATUS :
		ss_json_i64(s, level, "block_bad", task->block_bad);
		break;
	}
	ss_json_array_open(s, &level, "errors");
	for (tommy_node* i = tommy_list_head(&task->error_list); i; i = i->next) {
		sn_t* error = i->data;
		ss_json_elem(s, level, error->str);
	}
	ss_json_array_close(s, &level);
	ss_json_close(s, &level);
}

/**
 * GET /api/v1/activity
 */
static int handler_activity(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	struct snapraid_task* task = state->runner.latest;
	if (!task)
		return send_json_error(conn, 204, "No task");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	json_task(&s, level, task);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /api/v1/queue
 */
static int handler_queue(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_list_open(&s, &level);
	for (tommy_node* i = tommy_list_head(&state->runner.waiting_list); i; i = i->next) {
		struct snapraid_task* task = i->data;

		json_task(&s, level, task);
	}
	ss_json_array_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /api/v1/history
 */
static int handler_history(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_list_open(&s, &level);
	for (tommy_node* i = tommy_list_head(&state->runner.history_list); i; i = i->next) {
		struct snapraid_task* task = i->data;

		json_task(&s, level, task);
	}
	ss_json_array_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /api/v1/array
 */
static int handler_array(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	struct snapraid_global* global = &state->global;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_options(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	ss_json_str(&s, level, "daemon_version", PACKAGE_VERSION);
	if (*global->version) {
		ss_json_str(&s, level, "health", health_name(health_array(state)));
		ss_json_str(&s, level, "engine_version", global->version);
		ss_json_str(&s, level, "engine_conf", global->conf_engine);
		if (*global->content)
			ss_json_str(&s, level, "engine_content", global->content);
		ss_json_int(&s, level, "block_size_bytes", global->blocksize);
		if (global->last_time)
			ss_json_pair_iso8601(&s, level, "last_command_at", global->last_time);
		if (*global->last_cmd)
			ss_json_str(&s, level, "last_command", global->last_cmd);
		if (global->afr != 0)
			ss_json_double(&s, level, "annual_failure_rate", global->afr);
		if (global->prob != 0)
			ss_json_double(&s, level, "failure_probability", global->prob);
		ss_json_u64(&s, level, "file_count", global->file_total);
		ss_json_u64(&s, level, "block_bad", global->block_bad);
		ss_json_u64(&s, level, "block_rehash", global->block_rehash);
		ss_json_u64(&s, level, "block_count", global->block_total);
		if (global->sync_time)
			ss_json_pair_iso8601(&s, level, "last_sync_at", global->sync_time);
		if (global->scrub_time)
			ss_json_pair_iso8601(&s, level, "last_scrub_at", global->scrub_time);
		if (global->status_time)
			ss_json_pair_iso8601(&s, level, "last_status_at", global->status_time);
		if (global->diff_time)
			ss_json_pair_iso8601(&s, level, "last_diff_at", global->diff_time);
		ss_json_u64(&s, level, "diff_equal", global->diff_current.diff_equal);
		ss_json_u64(&s, level, "diff_added", global->diff_current.diff_added);
		ss_json_u64(&s, level, "diff_removed", global->diff_current.diff_removed);
		ss_json_u64(&s, level, "diff_updated", global->diff_current.diff_updated);
		ss_json_u64(&s, level, "diff_moved", global->diff_current.diff_moved);
		ss_json_u64(&s, level, "diff_copied", global->diff_current.diff_copied);
		ss_json_u64(&s, level, "diff_restored", global->diff_current.diff_restored);
		ss_json_array_open(&s, &level, "diffs");
		for (tommy_node* i = tommy_list_head(&global->diff_current.file_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			ss_json_open(&s, &level);

			ss_json_str(&s, level, "change", change_name(file->change));
			if (file->source_disk[0])
				ss_json_str(&s, level, "source_disk", file->source_disk);
			if (file->source_path[0])
				ss_json_str(&s, level, "source_path", file->source_path);
			ss_json_str(&s, level, "disk", file->disk);
			ss_json_str(&s, level, "path", file->path);
			ss_json_close(&s, &level);
		}
		ss_json_array_close(&s, &level);
	} else {
		ss_json_str(&s, level, "health", health_name(HEALTH_PENDING));
	}
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * Hook for internal CivetWeb messages.
 * \param conn    The connection associated with the message (can be NULL for global errors).
 * \param message The actual error or warning string.
 * \return 0 to let CivetWeb also write to its own error_log_file (if configured), 1 to tell CivetWeb the message has been handled.
 */
static int log_internal_callback(const struct mg_connection* conn, const char* message)
{
	(void)conn;
	log_msg(LVL_WARNING, "civetweb internal: %s", message);
	return 1;
}

int rest_init(struct snapraid_state* state)
{
	const char* options[20];
	int i;

	if (!state->config.net_enabled)
		return 0;

	i = 0;
	if (state->config.net_port[0] == 0) {
		sncpy(state->config.net_port, sizeof(state->config.net_port), "127.0.0.1:8080");
	}
	options[i++] = "listening_ports";
	options[i++] = state->config.net_port;
	if (state->config.net_acl[0] != 0) {
		options[i++] = "access_control_list";
		options[i++] = state->config.net_acl;
	}
	options[i++] = "num_threads";
	options[i++] = "4";
	options[i++] = "request_timeout_ms";
	options[i++] = "10000";
	options[i++] = 0;

	if (mg_init_library(MG_FEATURES_ALL) == 0) {
		log_msg(LVL_ERROR, "failed to initialize web server, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	memset(&state->rest_callbacks, 0, sizeof(state->rest_callbacks));

	state->rest_callbacks.log_message = log_internal_callback;

	state->rest_context = mg_start(&state->rest_callbacks, state, options);
	if (!state->rest_context) {
		log_msg(LVL_ERROR, "failed to start web server, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	mg_set_request_handler(state->rest_context, "/api/v1/sync", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/scrub", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/probe", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/up", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/down", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/smart", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/diff", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/status", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/check", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/fix", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/maintenance", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/heal", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/undelete", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/down_idle", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/stop", handler_stop, state);
	mg_set_request_handler(state->rest_context, "/api/v1/report", handler_report, state);
	mg_set_request_handler(state->rest_context, "/api/v1/disks", handler_disks, state);
	mg_set_request_handler(state->rest_context, "/api/v1/activity", handler_activity, state);
	mg_set_request_handler(state->rest_context, "/api/v1/queue", handler_queue, state);
	mg_set_request_handler(state->rest_context, "/api/v1/history", handler_history, state);
	mg_set_request_handler(state->rest_context, "/api/v1/config", handler_config, state);
	mg_set_request_handler(state->rest_context, "/api/v1/array", handler_array, state);
	mg_set_request_handler(state->rest_context, "/api", handler_not_found, state);

	log_msg(LVL_INFO, "web server started");

	return 0;
}

void rest_done(struct snapraid_state* state)
{
	if (!state->config.net_enabled)
		return;

	mg_stop(state->rest_context);

	mg_exit_library();

	log_msg(LVL_INFO, "web server stopped");
}

