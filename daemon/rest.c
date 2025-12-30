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
#include "rest.h"


#define JSMN_STRICT
#include "../jsmn/jsmn.h"

#define JSON_INITIAL_SIZE 512 /**< Initial size for building JSON text */
#define JSON_MAX_SIZE 16384 /**< Max size of the JSON text */

#define ESC_MAX 256

static char* escape(const char* src, char* dst)
{
	char* dst_begin = dst;
	char* dst_end = dst_begin + ESC_MAX;

	while (*src && dst_end - dst > 1) {
		switch (*src) {
		case '"':
		case '\\':
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = *src++;
			}
			break;
		case '\n':
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 'n';
				++src;
			}
			break;
		case '\r':
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 'r';
				++src;
			}
			break;
		case '\t':
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 't';
				++src;
			}
			break;
		default:
			*dst++ = *src++;
			break;
		}
	}

	*dst = 0;

	return dst_begin;
}

static int send_json_success(struct mg_connection *conn, int status) 
{
	char body[256];
	
	int body_len = snprintf(body, sizeof(body), "{\n  \"success\": true\n}\n");

	mg_printf(conn, "HTTP/1.1 %d %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n", 
		status, mg_get_response_code_text(conn, status), body_len);

	mg_write(conn, body, body_len);

	return status;
}

static int send_json_error(struct mg_connection *conn, int status, const char* message) 
{
	char body[256];
	
	int body_len = snprintf(body, sizeof(body), 
		"{\n  \"success\": false,\n  \"message\": \"%s\"\n}\n", message);

	mg_printf(conn, "HTTP/1.1 %d %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n", 
		status, mg_get_response_code_text(conn, status), body_len);

	mg_write(conn, body, body_len);

	return status;
}

static int handler_not_found(struct mg_connection* conn, void* cbdata)
{
	(void)cbdata;
	return send_json_error(conn, 404, "Resource not found");
}

/**
 * Max number of JSON tokens
 */
#define JSMN_TOKEN_MAX 64

#define json_const(v) v, sizeof(v) - 1

char* json_token(char* js, jsmntok_t* jv)
{
	js[jv[0].end] = 0;
	return &js[jv[0].start];
}

int json_entry(const char* js, jsmntok_t* jv, const char* field, ssize_t field_len)
{
	/* check if the field is matching */
	if (jv[0].type != JSMN_STRING
		|| field_len != jv[0].end - jv[0].start
		|| strncmp(js + jv[0].start, field, field_len) != 0)
		return -1;

	/* ensure that there is only one child  */
	if (jv[0].size != 1)
		return -1;

	/* STRING and PRIMITIVE should have no childs */
	if ((jv[1].type == JSMN_STRING || jv[1].type == JSMN_PRIMITIVE) && jv[1].size != 0)
		return -1;

	return 0;
}

int json_type(const char* js, jsmntok_t* jv, const char* field, ssize_t field_len, unsigned type)
{
	if (json_entry(js, jv, field, field_len) != 0)
		return -1;

	/* ensure that there is has the correct type  */
	if (jv[1].type != type)
		return -1;

	return 0;
}

int json_null(const char* js, jsmntok_t* jv)
{
	if (jv[0].type != JSMN_PRIMITIVE
		|| 4 != jv[0].end - jv[0].start
		|| strncmp(js + jv[0].start, "null", 4) != 0)
		return -1;
	return 0;
}

int json_value(const char* js, jsmntok_t* jv, int low, int high, int* out)
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

int json_boolean(const char* js, jsmntok_t* jv, int* out)
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

int json_string(const char* js, jsmntok_t* jv, char* out, size_t out_size)
{
	size_t len = jv[0].end - jv[0].start;

	if (jv[0].type != JSMN_STRING
		|| len + 1 > out_size)
		return -1;

	memcpy(out, &js[jv[0].start], len);
	out[len] = 0;

	return 0;
}

int json_string_inplace(char* js, jsmntok_t* jv, char** out)
{
	if (jv[0].type != JSMN_STRING)
		return -1;

	*out = json_token(js, jv);

	return 0;
}

void json_error_parse(char* str, size_t str_size, int jc)
{
	switch (jc) {
	case 0 : snprintf(str, str_size, "Empty JSON"); break;
	case JSMN_ERROR_NOMEM : snprintf(str, str_size, "JSON too long"); break;
	case JSMN_ERROR_INVAL : snprintf(str, str_size, "Invalid character inside JSON string"); break;
	case JSMN_ERROR_PART : snprintf(str, str_size, "Partial JSON"); break;
	default : snprintf(str, str_size, "Unknown JSON error"); break;
	};
}

void json_error_arg(char* str, size_t str_size, char* js, jsmntok_t* je, jsmntok_t* ja)
{
	snprintf(str, str_size, "Invalid JSON argument %s for %s", json_token(js, ja), json_token(js, je));
}

void json_error_entry(char* str, size_t str_size, char* js, jsmntok_t* jv)
{
	snprintf(str, str_size, "Unrecognized JSON token %s", json_token(js, jv));
}

int json_read(struct mg_connection* conn, char** js, ssize_t* jl, char* msg, size_t msg_size)
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

/**
 * PATCH /api/v1/config 
 */
static int handler_config_patch(struct mg_connection* conn, void* cbdata) 
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	int ret;	
	jsmntok_t jv[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	ssize_t jl;
	char* js;
	int jc;

	ret = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (ret != 200)
		return send_json_error(conn, ret, msg);

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
			if (json_entry(js, &jv[j], json_const("scheduled_run")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& parse_scheduled_run(buf, &state->config) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("probe_interval_minutes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 1440, &state->config.probe_interval_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.probe_interval_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("spindown_idle_minutes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 1440, &state->config.spindown_idle_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.spindown_idle_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("report_differences")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.report_differences) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.report_differences);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("suspend_on_deletes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.suspend_on_deletes) == 0) {
				} else {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.suspend_on_deletes);
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_percentage")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 100, &state->config.scrub_percentage) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.scrub_percentage);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("pre_run_script")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.pre_run_script, sizeof(state->config.pre_run_script)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("post_run_script")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.post_run_script, sizeof(state->config.post_run_script)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("log_directory")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.log_directory, sizeof(state->config.log_directory)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("log_retention_days")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.log_retention_days) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.log_retention_days);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_enabled")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.notify_syslog_enabled) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j-1]), state->config.notify_syslog_enabled);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& parse_level(buf, &state->config.notify_syslog_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_heartbeat_url")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.notify_heartbeat_url, sizeof(state->config.notify_heartbeat_url)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_apprise_url")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.notify_apprise_url, sizeof(state->config.notify_apprise_url)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_apprise_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& parse_level(buf, &state->config.notify_apprise_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_email_recipient")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.notify_email_recipient, sizeof(state->config.notify_email_recipient)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_email_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& parse_level(buf, &state->config.notify_email_level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j-1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j-1], &jv[j]);
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
}

/**
 * GET /api/v1/config
 */
static int handler_config_get(struct mg_connection* conn, void* cbdata) 
{
	struct snapraid_state* state = cbdata;
	struct snapraid_config* config = &state->config;
	int tab = 0;
	ss_t s;
	char esc_buf[ESC_MAX];
	char schedule_buf[64];

	state_lock();

	ss_init(&s, JSON_INITIAL_SIZE);

	config_schedule_str(config, schedule_buf, sizeof(schedule_buf));

	ss_jsonf(&s, tab, "{\n");
	++tab;

	ss_jsonf(&s, tab, "\"scheduled_run\": \"%s\",\n", escape(schedule_buf, esc_buf));
	ss_jsonf(&s, tab, "\"scrub_percentage\": %d,\n", config->scrub_percentage);

	ss_jsonf(&s, tab, "\"probe_interval_minutes\": %d,\n", config->probe_interval_minutes);
	ss_jsonf(&s, tab, "\"spindown_idle_minutes\": %d,\n", config->spindown_idle_minutes);

	ss_jsonf(&s, tab, "\"report_differences\": %s,\n", config->report_differences ? "true" : "false");
	ss_jsonf(&s, tab, "\"suspend_on_deletes\": %d,\n", config->suspend_on_deletes);
	ss_jsonf(&s, tab, "\"pre_run_script\": \"%s\",\n", escape(config->pre_run_script, esc_buf));
	ss_jsonf(&s, tab, "\"post_run_script\": \"%s\",\n", escape(config->post_run_script, esc_buf));

	ss_jsonf(&s, tab, "\"log_directory\": \"%s\",\n", escape(config->log_directory, esc_buf));
	ss_jsonf(&s, tab, "\"log_retention_days\": %d,\n", config->log_retention_days);

	ss_jsonf(&s, tab, "\"notify_syslog_enabled\": %s,\n", config->notify_syslog_enabled ? "true" : "false");
	ss_jsonf(&s, tab, "\"notify_syslog_level\": \"%s\",\n", config_level_str(config->notify_syslog_level));

	ss_jsonf(&s, tab, "\"notify_heartbeat_url\": \"%s\",\n", escape(config->notify_heartbeat_url, esc_buf));
	ss_jsonf(&s, tab, "\"notify_apprise_url\": \"%s\",\n", escape(config->notify_apprise_url, esc_buf));
	ss_jsonf(&s, tab, "\"notify_apprise_level\": \"%s\",\n", config_level_str(config->notify_apprise_level));
	
	ss_jsonf(&s, tab, "\"notify_email_recipient\": \"%s\",\n", escape(config->notify_email_recipient, esc_buf));
	ss_jsonf(&s, tab, "\"notify_email_level\": \"%s\"\n", config_level_str(config->notify_email_level));

	--tab;
	ss_jsonf(&s, tab, "}\n");

	state_unlock();

	// Standard Response Headers
	mg_printf(conn, "HTTP/1.1 200 OK\r\n");
	mg_printf(conn, "Content-Type: application/json\r\n");
	mg_printf(conn, "Content-Length: %lu\r\n", (unsigned long)ss_len(&s));
	mg_printf(conn, "Connection: close\r\n");
	mg_printf(conn, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s)); 

	ss_done(&s);
	return 200;
}
 
static int handler_config(struct mg_connection* conn, void* cbdata) 
{
	const struct mg_request_info* ri = mg_get_request_info(conn);
	if (strcmp(ri->request_method, "GET") == 0)
		return handler_config_get(conn, cbdata);
	if (strcmp(ri->request_method, "PATCH") == 0)
		return handler_config_patch(conn, cbdata);
	return send_json_error(conn, 405, "Only GET/PATCH is allowed for this endpoint");
}

/**
 * POST /api/v1/sync, /api/v1/probe, /api/v1/up, /api/v1/down, /api/v1/smart 
 */
static int handler_action(struct mg_connection* conn, void* cbdata) 
{
	char msg[128];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	const char* path = ri->local_uri;
	int ret;
	jsmntok_t jv[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	ssize_t jl;
	char* js;
	int jc;
	char* argv[RUNNER_ARG_MAX];
	int argc;

	argc = 0;

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	ret = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (ret != 200)
		return send_json_error(conn, ret, msg);

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
			if (json_type(js, &jv[j], json_const("args"), JSMN_ARRAY) == 0) {
				int j1 = j;
				int c1 = jv[++j].size;
				++j;
				while (c1-- > 0) {
					if (json_string_inplace(js, &jv[j], &argv[argc]) == 0) {
						++argc;
						if (argc >= RUNNER_ARG_MAX) {
							snprintf(msg, sizeof(msg), "Too many arguments");
							goto bad;
						}
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

	/* arg terminator */
	argv[argc] = 0;

	if (strcmp(path, "/api/v1/sync") == 0)
		ret = runner(state, CMD_SYNC, argc, argv, msg, sizeof(msg));
	else if (strcmp(path, "/api/v1/probe") == 0)
		ret = runner(state, CMD_PROBE, argc, argv, msg, sizeof(msg));
	else if (strcmp(path, "/api/v1/up") == 0)
		ret = runner(state, CMD_UP, argc, argv, msg, sizeof(msg));
	else if (strcmp(path, "/api/v1/down") == 0)
		ret = runner(state, CMD_DOWN, argc, argv, msg, sizeof(msg));
	else if (strcmp(path, "/api/v1/smart") == 0)
		ret = runner(state, CMD_SMART, argc, argv, msg, sizeof(msg));
	else {
		sncpy(msg, sizeof(msg), "Resource not found");
		ret = 404;
	}

	free(js);

	if (ret != 200)
		return send_json_error(conn, ret, msg);

	return send_json_success(conn, 200);

bad:
	free(js);
	return send_json_error(conn, 400, "Unrecognized json");
}

static void json_device_list(ss_t* s, int tab, tommy_list* list)
{
	tommy_node* i;
	char esc_buf[ESC_MAX];

	++tab;
	for (i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* dev = i->data;
		ss_jsonf(s, tab, "{\n");
		++tab;
		if (*dev->family)
			ss_jsonf(s, tab, "\"family\": \"%s\",\n", escape(dev->family, esc_buf));
		if (*dev->model)
			ss_jsonf(s, tab, "\"model\": \"%s\",\n", escape(dev->model, esc_buf));
		if (*dev->serial)
			ss_jsonf(s, tab, "\"serial\": \"%s\",\n", escape(dev->serial, esc_buf));
		if (dev->power != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"power\": \"%s\",\n", dev->power ? "active" : "standby");
		if (dev->health != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"health\": \"%s\",\n", dev->health ? "failing" : "ok");
		if (dev->size != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"size\": %" PRIu64 ",\n", dev->size);
		if (dev->rotational != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"rotational\": %" PRIu64 ",\n", dev->rotational);
		if (dev->error != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"error\": %" PRIu64 ",\n", dev->error);
		if (dev->smart[SMART_REALLOCATED_SECTOR_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_reallocated_sector_count\": %" PRIu64 ",\n", dev->smart[SMART_REALLOCATED_SECTOR_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_uncorrectable_error_cnt\": %" PRIu64 ",\n", dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] & 0xFFFF);
		if (dev->smart[SMART_COMMAND_TIMEOUT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_command_timeout\": %" PRIu64 ",\n", dev->smart[SMART_COMMAND_TIMEOUT] & 0xFFFF);
		if (dev->smart[SMART_CURRENT_PENDING_SECTOR] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_current_pending_sector\": %" PRIu64 ",\n", dev->smart[SMART_CURRENT_PENDING_SECTOR] & 0xFFFFFFFF);
		if (dev->smart[SMART_OFFLINE_UNCORRECTABLE] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_offline_uncorrectable\": %" PRIu64 ",\n", dev->smart[SMART_OFFLINE_UNCORRECTABLE] & 0xFFFFFFFF);
		if (dev->smart[SMART_START_STOP_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_start_stop_count\": %" PRIu64 ",\n", dev->smart[SMART_START_STOP_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_LOAD_CYCLE_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_power_on_hours\": %" PRIu64 ",\n", dev->smart[SMART_LOAD_CYCLE_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_POWER_ON_HOURS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_load_cycle_count\": %" PRIu64 ",\n", dev->smart[SMART_POWER_ON_HOURS] & 0xFFFFFFFF);
		if (dev->smart[SMART_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_temperature_celsius\": %" PRIu64 ",\n", dev->smart[SMART_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		else if (dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"smart_temperature_celsius\": %" PRIu64 ",\n", dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		ss_jsonf(s, tab, "\"device_node\": \"%s\"\n", escape(dev->file, esc_buf));
		--tab;
		ss_jsonf(s, tab, "}%s\n", i->next ? "," : "");
		--tab;
	}
	--tab;
}

/**
 * GET /api/v1/disks
 * Returns detailed disk status lists
 */
static int handler_disks(struct mg_connection* conn, void* cbdata) 
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	tommy_node* i;
	tommy_node* j;
	int tab = 0;
	ss_t s;
	char esc_buf[ESC_MAX];

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	state_lock();

	ss_init(&s, JSON_INITIAL_SIZE);

	ss_jsonf(&s, 0, "{\n");
	++tab;
	ss_jsonf(&s, 1, "\"data_disks\": [\n");
	for (i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_data* data = i->data;

		++tab;
		ss_jsonf(&s, tab, "{\n");
		++tab;
		ss_jsonf(&s, tab, "\"name\": \"%s\",\n", escape(data->name, esc_buf));
		ss_jsonf(&s, tab, "\"mount_dir\": \"%s\",\n", escape(data->dir, esc_buf));
		if (*data->uuid)
			ss_jsonf(&s, tab, "\"uuid\": \"%s\",\n", escape(data->uuid, esc_buf));
		if (*data->content_uuid)
			ss_jsonf(&s, tab, "\"stored_uuid\": \"%s\",\n", escape(data->content_uuid, esc_buf));
		if (data->content_size != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"allocated_space_bytes\": %" PRIu64 ",\n", data->content_size);
		if (data->content_free != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"free_space_bytes\": %" PRIu64 ",\n", data->content_free);
		if (data->access_count != 0) {
			ss_jsonf(&s, tab, "\"access_count\": %" PRIi64 ",\n", data->access_count);
			ss_jsonf(&s, tab, "\"access_count_initial_time\": %" PRIi64 ",\n", data->access_count_initial_time);
			ss_jsonf(&s, tab, "\"access_count_idle_duration\": %" PRIi64 ",\n", data->access_count_latest_time - data->access_count_initial_time);
		}
		ss_jsonf(&s, tab, "\"devices\": [\n");
		json_device_list(&s, tab, &data->device_list); 
		ss_jsonf(&s, tab, "]\n");
		--tab;
		ss_jsonf(&s, tab, "}%s\n", i->next ? "," : "");
		--tab;
	}
	ss_jsonf(&s, tab, "],\n");
	ss_jsonf(&s, tab, "\"parity_disks\": [\n");
	for (i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_parity* parity = i->data;

		++tab;
		ss_jsonf(&s, tab, "{\n");
		++tab;
		ss_jsonf(&s, tab, "\"name\": \"%s\",\n", escape(parity->name, esc_buf));
		if (parity->content_size != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"allocated_space_bytes\": %" PRIu64 ",\n", parity->content_size);
		if (parity->content_free != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"free_space_bytes\": %" PRIu64 ",\n", parity->content_free);
		if (parity->access_count != 0) {
			ss_jsonf(&s, tab, "\"access_count\": %" PRIi64 ",\n", parity->access_count);
			ss_jsonf(&s, tab, "\"access_count_initial_time\": %" PRIi64 ",\n", parity->access_count_initial_time);
			ss_jsonf(&s, tab, "\"access_count_idle_duration\": %" PRIi64 ",\n", parity->access_count_latest_time - parity->access_count_initial_time);
		}
		ss_jsonf(&s, tab, "\"splits\": [\n");

		for (j = tommy_list_head(&parity->split_list); j; j = j->next) {
			struct snapraid_split* split = j->data;

			++tab;
			ss_jsonf(&s, tab, "{\n");
			++tab;
			ss_jsonf(&s, tab, "\"parity_path\": \"%s\",\n", escape(split->path, esc_buf));
			if (*split->uuid)
				ss_jsonf(&s, tab, "\"uuid\": \"%s\",\n", escape(split->uuid, esc_buf));
			if (*split->content_uuid)
				ss_jsonf(&s, tab, "\"stored_uuid\": \"%s\",\n", escape(split->content_uuid, esc_buf));
			ss_jsonf(&s, tab, "\"devices\": [\n");
			json_device_list(&s, tab, &split->device_list); 
			ss_jsonf(&s, tab, "]\n");
			--tab;
			ss_jsonf(&s, tab, "}%s\n", j->next ? "," : "");
			--tab;
		}

		ss_jsonf(&s, tab, "]\n");
		--tab;
		ss_jsonf(&s, tab, "}%s\n", i->next ? "," : "");
		--tab;
	}
	ss_jsonf(&s, tab, "]\n");
	--tab;
	ss_jsonf(&s, tab, "}\n");

	state_unlock();

	mg_printf(conn, "HTTP/1.1 200 OK\r\n");
	mg_printf(conn, "Content-Type: application/json\r\n");
	mg_printf(conn, "Content-Length: %lu\r\n", ss_len(&s));
	mg_printf(conn, "Connection: close\r\n");
	mg_printf(conn, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s)); 

	ss_done(&s);

	return 200;
}

/**
 * GET /api/v1/task/progress
 * Poll current task progress for front-end updates
 */
static int handler_progress(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int tab = 0;
	ss_t s;
	char esc_buf[ESC_MAX];
	tommy_node* i;

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	ss_jsons(&s, tab, "{\n");
	++tab;
	ss_jsonf(&s, tab, "\"command\": \"%s\",\n", runner_cmd(state->runner.cmd));
	if (state->runner.running) {
		switch (state->process.state) {
		case PROCESS_STATE_INIT : ss_jsonf(&s, tab, "\"status\": \"initializing\",\n"); break;
		case PROCESS_STATE_BEGIN : ss_jsonf(&s, tab, "\"status\": \"starting\",\n"); break;
		case PROCESS_STATE_POS : ss_jsonf(&s, tab, "\"status\": \"processing\",\n"); break;
		case PROCESS_STATE_END : ss_jsonf(&s, tab, "\"status\": \"finishing\",\n"); break;
		case PROCESS_STATE_SIGINT : ss_jsonf(&s, tab, "\"status\": \"interrupting\",\n"); break;
		}
	} else {
		switch (state->process.state) {
		case PROCESS_STATE_SIGINT : 
			ss_jsonf(&s, tab, "\"status\": \"signaled\",\n"); 
			ss_jsonf(&s, tab, "\"exit_sig\": %d,\n", state->process.exit_sig); 
			break;
		default: 
			ss_jsonf(&s, tab, "\"status\": \"terminated\",\n"); 
			ss_jsonf(&s, tab, "\"exit_code\": %d,\n", state->process.exit_code); 
			break;
		}
	}
	if (state->process.state >= PROCESS_STATE_BEGIN) {
		ss_jsonf(&s, tab, "\"block_begin\": %u,\n", state->process.block_begin);
		ss_jsonf(&s, tab, "\"block_end\": %u,\n", state->process.block_end);
		ss_jsonf(&s, tab, "\"block_count\": %u,\n", state->process.block_count);
	}
	if (state->process.state >= PROCESS_STATE_POS) {
		ss_jsonf(&s, tab, "\"progress\": %d,\n", state->process.progress);
		ss_jsonf(&s, tab, "\"speed_mbs\": %u,\n", state->process.speed_mbs);
		ss_jsonf(&s, tab, "\"eta_seconds\": %u,\n", state->process.eta_seconds); 
		ss_jsonf(&s, tab, "\"cpu_usage\": %u,\n", state->process.cpu_usage); 
		ss_jsonf(&s, tab, "\"elapsed_seconds\": %u,\n", state->process.elapsed_seconds);
		ss_jsonf(&s, tab, "\"block_idx\": %u,\n", state->process.block_idx);
		ss_jsonf(&s, tab, "\"block_done\": %u,\n", state->process.block_done);
		ss_jsonf(&s, tab, "\"size_done\": %" PRIu64 ",\n", state->process.size_done);
	}
	ss_jsonf(&s, tab, "\"messages\": [\n");
	for (i = tommy_list_head(&state->runner.message_list); i; i = i->next) {
		struct snapraid_message* message = i->data;
		++tab;
		ss_jsonf(&s, tab, "\"%s\"%s\n", escape(message->str, esc_buf), i->next ? "," : "");
		--tab;
	}

	ss_jsonf(&s, tab, "]\n");

#if 0
	ss_jsonf(&s, tab, "\"errors\": [\n");
	for (i = 0; i < 1; i++) { // TODO dummy loop for TaskError items
		++tab;
		ss_jsonf(&s, tab, "{\n");
		++tab;
		ss_jsonf(&s, tab, "\"reference_type\": \"file\",\n");
		ss_jsonf(&s, tab, "\"message\": \"checksum error\",\n");
		ss_jsonf(&s, tab, "\"disk_name\": \"d1\",\n");
		ss_jsonf(&s, tab, "\"path\": \"/mnt/d1/data/file.txt\",\n");
		ss_jsonf(&s, tab, "\"block_number\": 123456\n");
		--tab;
		ss_jsonf(&s, tab, "}\n");
		--tab;
	}
	ss_jsonf(&s, tab, "],\n");
#endif
	--tab;
	ss_jsonf(&s, tab, "}\n");

	mg_printf(conn, "HTTP/1.1 200 OK\r\n");
	mg_printf(conn, "Content-Type: application/json\r\n");
	mg_printf(conn, "Content-Length: %lu\r\n", ss_len(&s));
	mg_printf(conn, "Connection: close\r\n");
	mg_printf(conn, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s)); 

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

int rest_init(struct snapraid_state* state, const char** options)
{
	if (mg_init_library(MG_FEATURES_ALL) == 0) {
		log_msg(LVL_ERROR, "failed to initialize civetweb, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	memset(&state->rest_callbacks, 0, sizeof(state->rest_callbacks));

	state->rest_callbacks.log_message = log_internal_callback;

	state->rest_context = mg_start(&state->rest_callbacks, state, options);
	if (!state->rest_context) {
		log_msg(LVL_ERROR, "failed to start civetweb, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	mg_set_request_handler(state->rest_context, "/api/v1/sync", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/probe", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/up", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/down", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/smart", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/disks", handler_disks, state);
	mg_set_request_handler(state->rest_context, "/api/v1/progress", handler_progress, state);
	mg_set_request_handler(state->rest_context, "/api/v1/config", handler_config, state);
	mg_set_request_handler(state->rest_context, "/api", handler_not_found, state);

	return 0;
}

void rest_done(struct snapraid_state* state)
{
	mg_stop(state->rest_context);

	mg_exit_library();
}
