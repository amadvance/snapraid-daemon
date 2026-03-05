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
#include "daemon.h"
#include "smart.h"
#include "web.h"
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

static int json_int(const char* js, jsmntok_t* jv, int low, int high, int* out)
{
	char buf[32];
	size_t len = jv[0].end - jv[0].start;

	if (jv[0].type != JSMN_PRIMITIVE || len >= 32)
		return -1;

	memcpy(buf, js + jv[0].start, len);
	buf[len] = 0;

	int v;
	if (strint(&v, buf) != 0)
		return -1;

	if (v < low || v > high)
		return -1;

	*out = v;
	return 0;
}

static int json_double(const char* js, jsmntok_t* jv, double low, double high, double* out)
{
	char buf[32];
	size_t len = jv[0].end - jv[0].start;

	if (jv[0].type != JSMN_PRIMITIVE || len >= 32)
		return -1;

	memcpy(buf, js + jv[0].start, len);
	buf[len] = 0;

	double v;
	if (strdouble(&v, buf) != 0)
		return -1;

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

static void json_error_duplicate(char* str, size_t str_size, char* js, jsmntok_t* jv)
{
	snprintf(str, str_size, "Duplicate parameter '%s'.", json_token(js, jv));
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
			ss_done(&s);
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

static void send_headers(struct mg_connection* conn, ss_t* s)
{
	int net_security_headers;
	char net_allowed_origin[CONFIG_MAX];
	time_t now = time(0);

	/* obtain the security configuration */
	state_lock();
	net_security_headers = state_ptr()->config.net_security_headers;
	sncpy(net_allowed_origin, sizeof(net_allowed_origin), state_ptr()->config.net_allowed_origin);
	state_unlock();

	http_headers(conn, s, now, 0, net_security_headers, net_allowed_origin);
}

static int send_json_answer(struct mg_connection* conn, int status, ss_t* body)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	size_t body_len = ss_len(body);
	int z = mg_accept_z(conn);

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s);
	ss_prints(&s, "Content-Type: application/json\r\n");
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
		mg_write_gzip(conn, ss_ptr(body), ss_len(body));
		break;
#endif
#if HAVE_ZSTD
	case Z_ZSTD :
		mg_write_zstd(conn, ss_ptr(body), ss_len(body));
		break;
#endif
	default :
		mg_write(conn, ss_ptr(body), ss_len(body));
	}

	/*
	 * If mg_write_* fails we just proceed to close the socket
	 * We already sent 200 OK headers, so we can't send a 500 now.
	 * We simply stop here. Do NOT send the "0\r\n\r\n".
	 * By exiting the handler, the connection will close.
	 */

	return status;
}

static int send_json_success(struct mg_connection* conn, int status)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	char body[KEYWORD_MAX];
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

	char body[KEYWORD_MAX + MSG_MAX];
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

static int send_no_content(struct mg_connection* conn)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	ss_prints(&s, "HTTP/1.1 204 No Content\r\n");
	send_headers(conn, &s);
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

static void json_pulse(ss_t* s, int level, struct snapraid_pulse* pulse)
{
	ss_json_object_open(s, &level, "pulse");
	ss_json_pair_iso8601(s, level, "current_at", time(0));
	ss_json_i64(s, level, "array", pulse->array);
	ss_json_i64(s, level, "config", pulse->config);
	ss_json_i64(s, level, "disks", pulse->disks);
	ss_json_i64(s, level, "tasks", pulse->tasks);
	ss_json_i64(s, level, "activity", pulse->activity);
	ss_json_close(s, &level);
}

/**
 * GET /snapraid/v1/state
 */
static int handler_state(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	int level = 0;
	ss_t s;

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	if (state->runner.latest && state->runner.latest->running) {
		struct snapraid_task* task = state->runner.latest;
		ss_json_str(&s, level, "active_command", command_name(task->cmd));
		if (!tommy_list_empty(&state->runner.waiting_list)) {
			struct snapraid_task* next_task = tommy_list_head(&state->runner.waiting_list)->data;
			ss_json_str(&s, level, "next_command", command_name(next_task->cmd));
		}
		if (task->cmd == CMD_SYNC || task->cmd == CMD_SCRUB
			|| task->cmd == CMD_FIX || task->cmd == CMD_CHECK) {
			switch (task->state) {
			case PROCESS_STATE_RUN :
				ss_json_int(&s, level, "progress", task->progress);
				ss_json_uint(&s, level, "eta_seconds", task->eta_seconds);
				break;
			}
		}
	}

	ss_json_str(&s, level, "health", health_name(state->global.health));
	if (state->global.health != HEALTH_PASSED)
		ss_json_str(&s, level, "health_reason", state->global.health_reason);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /snapraid/v1/system
 */
static int handler_system(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	struct snapraid_system* system = &state->system;
	int level = 0;
	ss_t s;

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	os_system_refresh(&state->system);

	ss_json_open(&s, &level);
	ss_json_str(&s, level, "hostname", system->hostname);
	ss_json_str(&s, level, "os_distribution", system->os_distribution);
	if (system->kernel_version[0])
		ss_json_str(&s, level, "os_kernel_version", system->kernel_version);
	ss_json_u64(&s, level, "uptime_seconds", system->uptime_seconds);
	ss_json_str(&s, level, "motherboard", system->motherboard);
	ss_json_str(&s, level, "cpu_model", system->cpu_model);
	ss_json_u64(&s, level, "memory_total_bytes", system->memory_total_bytes);
	ss_json_u64(&s, level, "memory_free_bytes", system->memory_free_bytes);
	ss_json_bool(&s, level, "is_ecc", system->is_ecc);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * PATCH /snapraid/v1/config
 */
static int handler_config_patch(struct mg_connection* conn, void* cbdata)
{
	char msg[MSG_MAX];
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

	pulse(state, PULSE_CONFIG);

	jsmn_init(&jp);
	jc = jsmn_parse(&jp, js, jl, jv, JSMN_TOKEN_MAX);
	if (jc <= 0) {
		json_error_parse(msg, sizeof(msg), jc);
		goto bad;
	} else {
		int j = 0;
		if (jv[j].type != JSMN_OBJECT) {
			snprintf(msg, sizeof(msg), "Missing root JSON object");
			goto bad;
		}
		int c0 = jv[j++].size;
		while (c0-- > 0) {
			char keyword[KEYWORD_MAX];
			if (json_entry(js, &jv[j], json_const("maintenance_schedule")) == 0) {
				++j;
				if (json_string(js, &jv[j], keyword, sizeof(keyword)) == 0
					&& config_parse_maintenance_schedule(keyword, &state->config) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("probe_interval_minutes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1440, &state->config.probe_interval_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.probe_interval_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("spindown_idle_minutes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1440, &state->config.spindown_idle_minutes) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.spindown_idle_minutes);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_deletes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 10000, &state->config.sync_threshold_deletes) == 0) {
				} else {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_threshold_deletes);
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_updates")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 10000, &state->config.sync_threshold_updates) == 0) {
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
				if (json_double(js, &jv[j], 0, 100, &state->config.scrub_percentage) == 0) {
					config_set_double(&state->config, json_token(js, &jv[j - 1]), state->config.scrub_percentage);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_older_than")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1000, &state->config.scrub_older_than) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.scrub_older_than);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("hook_run_as_user")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.hook_run_as_user, sizeof(state->config.hook_run_as_user)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("hook_script")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], state->config.hook_script, sizeof(state->config.hook_script)) == 0) {
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
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_int(js, &jv[j], 0, 10000, &state->config.log_retention_days) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.log_retention_days);
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_enabled")) == 0) {
				++j;
				int syslog;
				if (json_boolean(js, &jv[j], &syslog) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), syslog);

					log_lock();
					state->log.syslog = syslog;
					log_unlock();
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_level")) == 0) {
				++j;
				int level;
				if (json_string(js, &jv[j], keyword, sizeof(keyword)) == 0
					&& config_parse_level(keyword, &level) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));

					log_lock();
					state->log.syslog_level = level;
					log_unlock();
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
				if (json_string(js, &jv[j], keyword, sizeof(keyword)) == 0
					&& config_parse_level(keyword, &state->config.notify_result_level) == 0) {
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

	(void)config_save_locked(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_success(conn, 200);

bad:
	(void)config_save_locked(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_error(conn, 400, msg);

forbidden:
	(void)config_save_locked(&state->config); /* error logged inside */

	state_unlock();

	free(js);
	return send_json_error(conn, 403, msg);
}

/**
 * GET /snapraid/v1/config
 */
static int handler_config_get(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	struct snapraid_config* config = &state->config;
	int level = 0;
	ss_t s;
	char schedule_buf[64];

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	config_schedule_str(config, schedule_buf, sizeof(schedule_buf));

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	ss_json_bool(&s, level, "config_full_access", config->net_config_full_access);
	ss_json_str(&s, level, "maintenance_schedule", schedule_buf);
	ss_json_int(&s, level, "sync_threshold_deletes", config->sync_threshold_deletes);
	ss_json_int(&s, level, "sync_threshold_updates", config->sync_threshold_updates);
	ss_json_bool(&s, level, "sync_prehash", config->sync_prehash);
	ss_json_bool(&s, level, "sync_force_zero", config->sync_force_zero);
	ss_json_double(&s, level, "scrub_percentage", config->scrub_percentage);
	ss_json_int(&s, level, "scrub_older_than", config->scrub_older_than);

	ss_json_int(&s, level, "probe_interval_minutes", config->probe_interval_minutes);
	ss_json_int(&s, level, "spindown_idle_minutes", config->spindown_idle_minutes);

	ss_json_str(&s, level, "hook_run_as_user", config->hook_run_as_user);
	ss_json_str(&s, level, "hook_script", config->hook_script);

	ss_json_str(&s, level, "log_directory", config->log_directory);
	ss_json_int(&s, level, "log_retention_days", config->log_retention_days);

	log_lock();
	ss_json_bool(&s, level, "notify_syslog_enabled", state->log.syslog);
	ss_json_str(&s, level, "notify_syslog_level", config_level_str(state->log.syslog_level));
	log_unlock();

	ss_json_str(&s, level, "notify_run_as_user", config->notify_run_as_user);
	ss_json_str(&s, level, "notify_heartbeat", config->notify_heartbeat);
	ss_json_str(&s, level, "notify_result", config->notify_result);
	ss_json_str(&s, level, "notify_result_level", config_level_str(config->notify_result_level));

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
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") == 0)
		return handler_config_get(conn, cbdata);

	if (strcmp(ri->request_method, "PATCH") == 0)
		return handler_config_patch(conn, cbdata);

	return send_json_error(conn, 405, "Only GET/PATCH is allowed for this endpoint");
}

/**
 * POST /snapraid/v1/COMMAND
 */
static int handler_action(struct mg_connection* conn, void* cbdata)
{
	char msg[MSG_MAX];
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
	int spindown = 0;

	sl_init(&arg_list);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	int cmd = 0;
	int has_filters = 0;
	int has_spindown = 0;
	if (strncmp(path, "/snapraid/v1/", 13) == 0)
		cmd = command_parse(path + 13);
	switch (cmd) {
	case 0 :
		return send_json_error(conn, 404, "Resource not found");
	case CMD_MAINTENANCE :
	case CMD_HEAL :
		has_spindown = 1;
		break;
	case CMD_UNDELETE :
		has_spindown = 1;
		has_filters = 1;
		break;
	default :
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
		int j = 0;
		if (jv[j].type != JSMN_OBJECT) {
			snprintf(msg, sizeof(msg), "Missing root JSON object");
			goto bad;
		}
		int c0 = jv[j++].size;
		while (c0-- > 0) {
			if (has_filters && json_type(js, &jv[j], json_const("filters"), JSMN_ARRAY) == 0) {
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
			} else if (has_spindown && json_entry(js, &jv[j], json_const("spindown_on_finish")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &spindown) == 0) {
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

	switch (cmd) {
	case CMD_MAINTENANCE :
		schedule_maintenance(state, spindown, msg, sizeof(msg), &status);
		break;
	case CMD_HEAL :
		schedule_heal(state, spindown, msg, sizeof(msg), &status);
		break;
	case CMD_UNDELETE :
		schedule_undelete(state, spindown, &arg_list, msg, sizeof(msg), &status);
		break;
	case CMD_SUSPEND_IDLE :
		schedule_suspend_idle(state, msg, sizeof(msg), &status);
		break;
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
 * POST /snapraid/v1/schedule
 */
static int handler_schedule(struct mg_connection* conn, void* cbdata)
{
	char msg[MSG_MAX];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int status;
	jsmntok_t jv[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	ssize_t jl;
	char* js;
	int jc;
	tommy_list scheds;

	tommy_list_init(&scheds);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	status = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (status != 200)
		return send_json_error(conn, status, msg);

	jsmn_init(&jp);
	jc = jsmn_parse(&jp, js, jl, jv, JSMN_TOKEN_MAX);
	if (jc < 0) {
		json_error_parse(msg, sizeof(msg), jc);
		goto bad;
	} else {
		int j = 0;
		if (jv[j].type != JSMN_OBJECT) {
			snprintf(msg, sizeof(msg), "Missing root JSON object");
			goto bad;
		}
		int c0 = jv[j++].size;
		while (c0-- > 0) {
			if (json_type(js, &jv[j], json_const("tasks"), JSMN_ARRAY) == 0) {
				int c1 = jv[++j].size;
				++j;
				while (c1-- > 0) {
					if (jv[j].type != JSMN_OBJECT) {
						snprintf(msg, sizeof(msg), "Missing array JSON object");
						goto bad;
					}
					struct snapraid_schedule* sched = schedule_alloc();
					int c2 = jv[j++].size;
					while (c2-- > 0) {
						if (json_entry(js, &jv[j], json_const("command")) == 0) {
							if (sched->cmd != 0) {
								json_error_duplicate(msg, sizeof(msg), js, &jv[j]);
								schedule_free(sched);
								goto bad;
							}
							++j;
							char cmd[KEYWORD_MAX];
							if (json_string(js, &jv[j], cmd, sizeof(cmd)) == 0) {
								sched->cmd = command_parse(cmd);
								if (!sched->cmd) {
									json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
									schedule_free(sched);
									goto bad;
								}
							} else {
								json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
								schedule_free(sched);
								goto bad;
							}
							++j;
						} else if (json_type(js, &jv[j], json_const("args"), JSMN_ARRAY) == 0) {
							if (!tommy_list_empty(&sched->args)) {
								json_error_duplicate(msg, sizeof(msg), js, &jv[j]);
								schedule_free(sched);
								goto bad;
							}
							int j3 = j;
							int c3 = jv[++j].size;
							++j;
							while (c3-- > 0) {
								char* val;
								if (json_string_inplace(js, &jv[j], &val) == 0) {
									sl_insert_str(&sched->args, val);
								} else {
									json_error_arg(msg, sizeof(msg), js, &jv[j3], &jv[j]);
									schedule_free(sched);
									goto bad;
								}
								++j;
							}
						} else {
							json_error_entry(msg, sizeof(msg), js, &jv[j]);
							schedule_free(sched);
							goto bad;
						}
					}
					tommy_list_insert_tail(&scheds, &sched->node, sched);
				}
			} else {
				json_error_entry(msg, sizeof(msg), js, &jv[j]);
				goto bad;
			}
		}
	}

	if (tommy_list_empty(&scheds))
		goto bad;

	schedule_commands(state, &scheds, msg, sizeof(msg), &status);

	free(js);
	tommy_list_foreach(&scheds, schedule_free);

	if (status >= 200 && status <= 299)
		return send_json_success(conn, status);
	else
		return send_json_error(conn, status, msg);

bad:
	free(js);
	return send_json_error(conn, 400, "Unrecognized json");
}

/**
 * POST /snapraid/v1/stop
 */
static int handler_stop(struct mg_connection* conn, void* cbdata)
{
	char msg[MSG_MAX];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int status;
	pid_t pid = 0;
	int number = 0;
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

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
 * POST /snapraid/v1/report
 */
static int handler_report(struct mg_connection* conn, void* cbdata)
{
	char msg[MSG_MAX];
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int status;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	runner(state, 0, CMD_REPORT, 0, 0, msg, sizeof(msg), &status);

	if (status >= 200 && status <= 299)
		return send_json_success(conn, status);
	else
		return send_json_error(conn, status, msg);
}

#define TEMP_COUNT 144

static void json_temp_list(ss_t* s, int level, tommy_list* list, int64_t reference)
{
	int64_t base = reference - SECONDS_IN_A_DAY;
	int64_t delta = (SECONDS_IN_A_DAY + TEMP_COUNT - 1) / TEMP_COUNT;

	int vect[TEMP_COUNT];
	memset(vect, 0, sizeof(vect));

	for (tommy_node* i = tommy_list_head(list); i != 0; i = i->next) {
		struct snapraid_temp* entry = i->data;

		if (entry->time_at < base)
			continue;

		int index = (entry->time_at - base) / delta;
		if (index < 0) /* safety check, it should never happen */
			continue;
		if (index >= TEMP_COUNT) /* safety check, it should never happen */
			index = TEMP_COUNT - 1;

		vect[index] = entry->temp;
	}

	ss_json_array_open(s, &level, "temp_history_24h");
	for (int j = 0; j < TEMP_COUNT; ++j) {
		if (j % 16 == 0) {
			if (j != 0)
				ss_prints(s, ",\n");
			ss_json_tab(s, level);
		} else {
			ss_prints(s, ", ");
		}
		ss_printf(s, "%d", vect[j]);
		if (j + 1 == TEMP_COUNT)
			ss_prints(s, "\n");
	}
	ss_json_array_close(s, &level);
}

#define SCRUB_COUNT 30

static unsigned day_ago(int64_t ref, int64_t now)
{
	/* in case some dates is in the future */
	if (now < ref)
		return 0;

	return (now - ref) / SECONDS_IN_A_DAY;
}

static void json_scrub_list(ss_t* s, int level, tommy_list* list, int64_t reference)
{
	if (tommy_list_empty(list))
		return;

	tommy_node* first = tommy_list_head(list);
	tommy_node* last = tommy_list_tail(list);

	struct snapraid_bucket* first_bucket = first->data;
	struct snapraid_bucket* last_bucket = last->data;

	int64_t oldest = first_bucket->time_at;
	int64_t newest = last_bucket->time_at;
	int64_t median = oldest;

	/* compute graph limits */
	uint64_t bar_scrubbed[SCRUB_COUNT];
	uint64_t bar_new[SCRUB_COUNT];
	uint64_t barmax = 0;
	uint64_t total = 0;
	uint64_t partial = 0;
	memset(bar_scrubbed, 0, sizeof(bar_scrubbed));
	memset(bar_new, 0, sizeof(bar_new));

	/* get the total */
	for (tommy_node* j = tommy_list_head(list); j != 0; j = j->next) {
		struct snapraid_bucket* bucket = j->data;
		total += bucket->count_scrubbed + bucket->count_justsynced;
	}

	/* get the median */
	for (tommy_node* j = tommy_list_head(list); j != 0; j = j->next) {
		struct snapraid_bucket* bucket = j->data;

		if (partial < total / 2)
			median = bucket->time_at;
		partial += bucket->count_scrubbed + bucket->count_justsynced;

		unsigned column = (bucket->time_at - oldest) * SCRUB_COUNT / (newest - oldest + 1);

		bar_scrubbed[column] += bucket->count_scrubbed;
		bar_new[column] += bucket->count_justsynced;

		if (bar_scrubbed[column] + bar_new[column] > barmax)
			barmax = bar_scrubbed[column] + bar_new[column];
	}

	unsigned dayoldest = day_ago(oldest, reference);
	unsigned daymedian = day_ago(median, reference);
	unsigned daynewest = day_ago(newest, reference);

	ss_json_object_open(s, &level, "scrub_history");
	ss_json_uint(s, level, "x_axis_low", dayoldest);
	ss_json_uint(s, level, "x_axis_high", daynewest);
	ss_json_uint(s, level, "x_axis_median", daymedian);
	ss_json_uint(s, level, "y_axis_low", 0);
	ss_json_double(s, level, "y_axis_high", barmax * (double)100 / total);
	ss_json_array_open(s, &level, "points");
	for (int i = 0; i < SCRUB_COUNT; ++i) {
		unsigned days_ago = dayoldest - (dayoldest - daynewest) * i / (SCRUB_COUNT - 1);
		ss_json_tab(s, level);

		double scrubbed = bar_scrubbed[i] * (double)100 / total;
		double justsynced = bar_new[i] * (double)100 / total;

		/* avoid to show number too small */
		if (scrubbed < 1E-3)
			scrubbed = 0;
		if (justsynced < 1E-3)
			justsynced = 0;

		ss_printf(s, "{ \"ago\": %u, \"scrubbed\": %.3g, \"new\": %.3g }", days_ago, scrubbed, justsynced);
		if (i == SCRUB_COUNT - 1)
			ss_prints(s, "\n");
		else
			ss_prints(s, ",\n");
	}
	ss_json_array_close(s, &level);
	ss_json_close(s, &level);
}

static void json_device_list(ss_t* s, int level, tommy_list* list, time_t reference)
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
		if (*dev->interf)
			ss_json_str(s, level, "interface", dev->interf);
		ss_json_str(s, level, "power", power_name(dev->power));
		if (dev->size != SMART_UNASSIGNED)
			ss_json_u64(s, level, "size_bytes", dev->size);
		if (dev->rotational != SMART_UNASSIGNED)
			ss_json_u64(s, level, "rotational", dev->rotational);
		if (dev->error_protocol.value != SMART_UNASSIGNED)
			json_tracked(s, level, "error_protocol", &dev->error_protocol, 0);
		if (dev->error_medium.value != SMART_UNASSIGNED)
			json_tracked(s, level, "error_medium", &dev->error_medium, 0);
		if (dev->wear_level != SMART_UNASSIGNED)
			ss_json_u64(s, level, "wear_level", dev->wear_level);
		if (dev->afr != 0)
			ss_json_double(s, level, "annual_failure_rate", dev->afr);
		if (dev->prob != 0)
			ss_json_double(s, level, "failure_probability", dev->prob);
		json_temp_list(s, level, &dev->temp_list, reference);
		ss_json_object_open(s, &level, "smart");
		if (dev->smart_time)
			ss_json_pair_iso8601(s, level, "measured_at", dev->smart_time);
		/* low level attributes */
		json_smart_list(s, level, dev);
		if (dev->smart[9].raw.value != SMART_UNASSIGNED)
			ss_json_u64(s, level, "power_on_hours", dev->smart[9].raw.value & 0xFFFFFF);
		/* high level attributes */
		uint64_t temp = SMART_UNASSIGNED;
		uint64_t temp_min = SMART_UNASSIGNED;
		uint64_t temp_max = SMART_UNASSIGNED;
		smart_temperature_range(dev, &temp, &temp_min, &temp_max);
		if (temp != SMART_UNASSIGNED) {
			ss_json_u64(s, level, "temperature_celsius", temp);
			if (temp_min != SMART_UNASSIGNED)
				ss_json_u64(s, level, "temperature_min_celsius", temp_min);
			if (temp_max != SMART_UNASSIGNED)
				ss_json_u64(s, level, "temperature_max_celsius", temp_max);
		}
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

static void json_disk_list(ss_t* s, int level, tommy_list* list, int64_t reference)
{
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		ss_json_open(s, &level);
		ss_json_str(s, level, "name", disk->name);
		ss_json_str(s, level, "health", health_name(health_disk(disk, 0, 0)));
		if (disk->total_space_bytes != 0)
			ss_json_u64(s, level, "total_space_bytes", disk->total_space_bytes);
		if (disk->free_space_bytes != 0)
			ss_json_u64(s, level, "free_space_bytes", disk->free_space_bytes);
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
			ss_json_str(s, level, "path", split->path);
			if (*split->uuid)
				ss_json_str(s, level, "uuid", split->uuid);
			if (*split->content_uuid)
				ss_json_str(s, level, "stored_uuid", split->content_uuid);
			if (split->fslabel[0])
				ss_json_str(s, level, "label", split->fslabel);
			if (split->fstype[0])
				ss_json_str(s, level, "type", split->fstype);
			ss_json_close(s, &level);
		}
		ss_json_array_close(s, &level);

		ss_json_array_open(s, &level, "devices");
		json_device_list(s, level, &disk->device_list, reference);
		ss_json_array_close(s, &level);
		ss_json_close(s, &level);
	}
}

/**
 * GET /snapraid/v1/disks
 * Returns detailed disk status lists
 */
static int handler_disks(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	ss_json_array_open(&s, &level, "data_disks");
	json_disk_list(&s, level, &state->data_list, state->global.last_time);
	ss_json_array_close(&s, &level);
	ss_json_array_open(&s, &level, "parity_disks");
	json_disk_list(&s, level, &state->parity_list, state->global.last_time);
	ss_json_array_close(&s, &level);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

static void json_task(ss_t* s, int level, struct snapraid_task* task, struct snapraid_pulse* pulse)
{
	ss_json_open(s, &level);
	if (pulse)
		json_pulse(s, level, pulse);
	ss_json_int(s, level, "number", task->number);
	ss_json_str(s, level, "command", command_name(task->cmd));
	if (task->high_cmd)
		ss_json_str(s, level, "high_command", command_name(task->high_cmd));
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
			ss_json_uint(s, level, "blocks_count", task->block_count);
			ss_json_uint(s, level, "block_idx", task->block_idx);
			ss_json_uint(s, level, "blocks_done", task->block_done);
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
		struct snapraid_message* message = i->data;
		ss_json_open(s, &level);
		switch (message->level) {
		case MESSAGE_LEVEL_FATAL :
			ss_json_str(s, level, "level", "fatal");
			ss_json_str(s, level, "type", message->type == MESSAGE_TYPE_HARDWARE ? "hardware" : "soft");
			ss_json_str(s, level, "text", message->msg);
			break;
		case MESSAGE_LEVEL_ERROR :
			ss_json_str(s, level, "level", "error");
			ss_json_str(s, level, "type", message->type == MESSAGE_TYPE_HARDWARE ? "hardware" : "soft");
			ss_json_str(s, level, "text", message->msg);
			break;
		case MESSAGE_LEVEL_INFO :
			ss_json_str(s, level, "level", "info");
			ss_json_str(s, level, "text", message->msg);
			break;
		}
		ss_json_close(s, &level);
	}
	ss_json_array_close(s, &level);

	switch (task->cmd) {
	case CMD_SYNC :
	case CMD_SCRUB :
		ss_json_i64(s, level, "error_soft", task->error_soft + task->hash_error_soft);
		ss_json_i64(s, level, "error_io", task->error_io);
		ss_json_i64(s, level, "error_data", task->error_data);
		break;
	case CMD_FIX :
	case CMD_CHECK :
		ss_json_i64(s, level, "error_unrecoverable", task->error_unrecoverable);
		ss_json_i64(s, level, "error_soft", task->error_soft + task->hash_error_soft);
		ss_json_i64(s, level, "error_io", task->error_io);
		ss_json_i64(s, level, "error_data", task->error_data);
		break;
	}
	ss_json_close(s, &level);
}

/**
 * GET /snapraid/v1/activity
 */
static int handler_activity(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	struct snapraid_task* task = state->runner.latest;
	if (!task) {
		state_unlock();
		ss_done(&s);
		return send_no_content(conn);
	}

	json_task(&s, level, task, &state->pulse);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /snapraid/v1/tasks
 */
static int handler_tasks(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	ss_json_array_open(&s, &level, "pending");
	for (tommy_node* i = tommy_list_head(&state->runner.waiting_list); i; i = i->next) {
		struct snapraid_task* task = i->data;

		json_task(&s, level, task, 0);
	}
	ss_json_array_close(&s, &level);

	ss_json_array_open(&s, &level, "active");
	if (state->runner.latest && state->runner.latest->running)
		json_task(&s, level, state->runner.latest, 0);
	ss_json_array_close(&s, &level);

	ss_json_array_open(&s, &level, "history");
	for (tommy_node* i = tommy_list_head(&state->runner.history_list); i; i = i->next) {
		struct snapraid_task* task = i->data;

		json_task(&s, level, task, 0);
	}
	ss_json_array_close(&s, &level);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

/**
 * GET /snapraid/v1/array
 */
static int handler_array(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	struct snapraid_global* global = &state->global;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	uint64_t total_space_bytes = 0;
	uint64_t free_space_bytes = 0;

	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		if (disk->total_space_bytes != 0)
			total_space_bytes += disk->total_space_bytes;
		if (disk->free_space_bytes != 0)
			free_space_bytes += disk->free_space_bytes;
	}

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	ss_json_str(&s, level, "daemon_version", PACKAGE_VERSION);
	ss_json_str(&s, level, "daemon_conf", state->config.conf);
	ss_json_str(&s, level, "health", health_name(state->global.health));
	if (*global->version) { /* engine was run */
		ss_json_str(&s, level, "engine_version", global->version);
		ss_json_str(&s, level, "engine_conf", global->conf_engine);
		if (*global->content)
			ss_json_str(&s, level, "engine_content", global->content);
	}
	if (global->last_time)
		ss_json_pair_iso8601(&s, level, "last_command_at", global->last_time);
	if (*global->last_cmd)
		ss_json_str(&s, level, "last_command", global->last_cmd);
	if (global->blocksize) { /* engine was run and it has a configuration file */
		ss_json_int(&s, level, "block_size_bytes", global->blocksize);
		ss_json_int(&s, level, "data_disks_count", tommy_list_count(&state->data_list));
		ss_json_int(&s, level, "parity_disks_count", tommy_list_count(&state->parity_list));
		if (total_space_bytes != 0)
			ss_json_u64(&s, level, "total_space_bytes", total_space_bytes);
		if (free_space_bytes != 0)
			ss_json_u64(&s, level, "free_space_bytes", free_space_bytes);
		ss_json_double(&s, level, "annual_failure_rate", afr_array(state));
		ss_json_double(&s, level, "failure_probability", fp_array(state));
		ss_json_u64(&s, level, "files_count", global->file_total);
		ss_json_u64(&s, level, "blocks_bad", global->block_bad);
		ss_json_u64(&s, level, "blocks_rehash", global->block_rehash);
		ss_json_u64(&s, level, "blocks_unsynced", global->block_unsynced);
		ss_json_u64(&s, level, "blocks_unscrubbed", global->block_unscrubbed);
		ss_json_u64(&s, level, "blocks_count", global->block_total);
		if (global->sync_time)
			ss_json_pair_iso8601(&s, level, "last_sync_at", global->sync_time);
		if (global->scrub_time)
			ss_json_pair_iso8601(&s, level, "last_scrub_at", global->scrub_time);
		if (global->diff_time)
			ss_json_pair_iso8601(&s, level, "last_diff_at", global->diff_time);
		if (global->fix_time)
			ss_json_pair_iso8601(&s, level, "last_fix_at", global->fix_time);
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
		ss_json_u64(&s, level, "fix_recovered", global->fix_current.fix_recovered);
		ss_json_u64(&s, level, "fix_unrecoverable", global->fix_current.fix_unrecoverable);
		ss_json_array_open(&s, &level, "fixes");
		for (tommy_node* i = tommy_list_head(&global->fix_current.file_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			ss_json_open(&s, &level);

			ss_json_str(&s, level, "result", change_name(file->change));
			ss_json_str(&s, level, "disk", file->disk);
			ss_json_str(&s, level, "path", file->path);
			ss_json_close(&s, &level);
		}
		ss_json_array_close(&s, &level);
		json_scrub_list(&s, level, &state->global.bucket_list, state->global.last_time);
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

/**
 * Internal hook of CivetWeb
 */
void civetweb_log_access(const struct mg_connection* conn, int status_code, int num_bytes_sent)
{
	const struct mg_request_info* ri = mg_get_request_info(conn);
	char date[64];
	time_t curtime = time(0);
	struct tm* timeptr = gmtime(&curtime);

	/* format timestamp: [day/month/year:hour:minute:second +0000] */
	strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S +0000", timeptr);

	/* get specific headers (Referer and User-Agent) */
	const char* referer = mg_get_header(conn, "Referer");
	const char* user_agent = mg_get_header(conn, "User-Agent");

	/*
	 * Print in Apache Combined Log Format:
	 * 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/main.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
	 */
	log_msg(LVL_DEBUG,
		"%s - - [%s] \"%s %s HTTP/%s\" %d %d \"%s\" \"%s\"",
		ri->remote_addr[0] ? ri->remote_addr : "-", /* ri->remote_addr is remote_addr[48]; */
		date,
		ri->request_method ? ri->request_method : "-",
		ri->local_uri ? ri->local_uri : "-",
		ri->http_version ? ri->http_version : "-",
		status_code,
		num_bytes_sent,
		referer ? referer : "-",
		user_agent ? user_agent : "-");
}

/**
 * Internal hook of CivetWeb
 */
void civetweb_log_message(const struct mg_connection* conn, const char* str)
{
	log_internal_callback(conn, str);
}

int rest_init(struct snapraid_state* state)
{
	const char* options[20];
	int i;

	if (!state->config.net_enabled)
		return 0;

	i = 0;
	if (state->config.net_port[0] == 0) {
		sncpy(state->config.net_port, sizeof(state->config.net_port), "127.0.0.1:7627");
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

	mg_set_request_handler(state->rest_context, "/snapraid/v1/maintenance", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/heal", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/undelete", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/suspend_idle", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/schedule", handler_schedule, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/stop", handler_stop, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/report", handler_report, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/disks", handler_disks, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/activity", handler_activity, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/tasks", handler_tasks, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/config", handler_config, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/array", handler_array, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/state", handler_state, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/system", handler_system, state);
	mg_set_request_handler(state->rest_context, "/snapraid", handler_not_found, state);

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

