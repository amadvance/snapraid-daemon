// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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

/**
 * Initial size for building Prometheus metrics text
 */
#define METRICS_INITIAL_SIZE 32768

/**
 * Max distinct (command, status, health) tuples for snapraid_tasks_history_size
 */
#define METRICS_TASK_TUPLES_MAX 256

/**
 * Max commands tracked for latest-terminated-task metrics
 */
#define METRICS_LATEST_TASK_MAX 32

/****************************************************************************/
/* json */

#define json_const(v) v, sizeof(v) - 1

/**
 * Returns the raw string as it's in the received raw buffer.
 * Note that this means that the string is ESCAPED by the client if it needed to be.
 */
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

static int json_bool_or_int(const char* js, jsmntok_t* jv, int* out)
{
	if (json_boolean(js, jv, out) == 0)
		return 0;

	if (json_int(js, jv, 0, 1, out) == 0)
		return 0;

	return -1;
}

static int json_string(const char* js, jsmntok_t* jv, char* out, size_t out_size)
{
	size_t len = jv[0].end - jv[0].start;

	if (jv[0].type != JSMN_STRING
		|| len + 1 > out_size)
		return -1;

	if (json_unescape(&js[jv[0].start], len, out, out_size) != 0)
		return -1;

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
	const char* entry = json_token(js, je);
	const char* arg = json_token(js, ja);
	snprintf(str, str_size, "Invalid value %s for %s", arg, entry);
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

	http_headers_secure(conn, s, now, net_security_headers, net_allowed_origin);
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

static int send_text_answer(struct mg_connection* conn, int status, ss_t* body)
{
	ss_t s;
	ss_init(&s, HTTP_HEADERS_MAX);

	size_t body_len = ss_len(body);
	int z = mg_accept_z(conn);

	ss_printf(&s, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	send_headers(conn, &s);
	ss_prints(&s, "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n");
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
		mg_write_gzip(conn, ss_ptr(body), body_len);
		break;
#endif
#if HAVE_ZSTD
	case Z_ZSTD :
		mg_write_zstd(conn, ss_ptr(body), body_len);
		break;
#endif
	default :
		mg_write(conn, ss_ptr(body), body_len);
	}

	return status;
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
	ss_json_i64(s, level, "disks", pulse->disks_attr + pulse->disks_ui);
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
	struct snapraid_config transient;

	status = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (status != 200)
		return send_json_error(conn, status, msg);

	state_lock();

	config_dup_locked(state, &transient);

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
					&& config_parse_maintenance_schedule(keyword, &transient) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("probe_interval_minutes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1440, &transient.probe_interval_minutes) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("spindown_idle_minutes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1440, &transient.spindown_idle_minutes) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_deletes")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 10000, &transient.sync_threshold_deletes) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_threshold_updates")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 10000, &transient.sync_threshold_updates) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_prehash")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &transient.sync_prehash) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("sync_prevent_truncations")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &transient.sync_prevent_truncations) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_percentage")) == 0) {
				++j;
				if (json_double(js, &jv[j], 0, 100, &transient.scrub_percentage) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("touch_zero_subseconds")) == 0) {
				++j;
				if (json_bool_or_int(js, &jv[j], &transient.touch_zero_subseconds) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("scrub_older_than")) == 0) {
				++j;
				if (json_int(js, &jv[j], 0, 1000, &transient.scrub_older_than) == 0) {
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
				if (json_string(js, &jv[j], transient.hook_run_as_user, sizeof(transient.hook_run_as_user)) == 0) {
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
				if (json_string(js, &jv[j], transient.hook_script, sizeof(transient.hook_script)) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_enabled")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &transient.notify_syslog) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_syslog_level")) == 0) {
				++j;
				if (json_string(js, &jv[j], keyword, sizeof(keyword)) == 0
					&& config_parse_level(keyword, &transient.notify_syslog_level) == 0) {
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
				if (json_string(js, &jv[j], transient.notify_run_as_user, sizeof(transient.notify_run_as_user)) == 0) {
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
				if (json_string(js, &jv[j], transient.notify_heartbeat, sizeof(transient.notify_heartbeat)) == 0) {
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
				if (json_string(js, &jv[j], transient.notify_result, sizeof(transient.notify_result)) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_result_level")) == 0) {
				if (!state->config.net_config_full_access) {
					json_error_forbidden(msg, sizeof(msg), js, &jv[j]);
					goto forbidden;
				}
				++j;
				if (json_string(js, &jv[j], keyword, sizeof(keyword)) == 0
					&& config_parse_level(keyword, &transient.notify_result_level) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_differences")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &transient.notify_differences) == 0) {
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

	if (config_apply_locked(state, &transient) != 0) {
		snprintf(msg, sizeof(msg), "Failed to apply the configuration");
		goto bad;
	}

	config_free(&transient);

	(void)config_save_locked(state); /* error logged inside */

	pulse(state, PULSE_CONFIG);

	state_unlock();

	free(js);
	return send_json_success(conn, 200);

bad:
	config_free(&transient);

	state_unlock();

	free(js);
	return send_json_error(conn, 400, msg);

forbidden:
	config_free(&transient);

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
	ss_json_bool(&s, level, "sync_prevent_truncations", config->sync_prevent_truncations);
	ss_json_double(&s, level, "scrub_percentage", config->scrub_percentage);
	ss_json_int(&s, level, "scrub_older_than", config->scrub_older_than);
	ss_json_bool(&s, level, "touch_zero_subseconds", config->touch_zero_subseconds);

	ss_json_int(&s, level, "probe_interval_minutes", config->probe_interval_minutes);
	ss_json_int(&s, level, "spindown_idle_minutes", config->spindown_idle_minutes);

	ss_json_str(&s, level, "hook_run_as_user", config->hook_run_as_user);
	ss_json_str(&s, level, "hook_script", config->hook_script);

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
	int apply_spindown = 0;
	int ignore_threshold = 0;

	sl_init(&arg_list);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	int cmd = 0;
	int has_filters = 0;
	int has_spindown = 0;
	int has_threshold = 0;
	if (strncmp(path, "/snapraid/v1/", 13) == 0)
		cmd = command_parse(path + 13);
	switch (cmd) {
	case 0 :
		return send_json_error(conn, 404, "Resource not found");
	case CMD_MAINTENANCE :
		has_threshold = 1;
		has_spindown = 1;
		break;
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
					char val[CONFIG_MAX];
					if (json_string(js, &jv[j], val, sizeof(val)) == 0) {
						sl_insert_str(&arg_list, val);
					} else {
						json_error_arg(msg, sizeof(msg), js, &jv[j1], &jv[j]);
						goto bad;
					}
					++j;
				}
			} else if (has_spindown && json_entry(js, &jv[j], json_const("spindown_on_finish")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &apply_spindown) == 0) {
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (has_threshold && json_entry(js, &jv[j], json_const("ignore_thresholds")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &ignore_threshold) == 0) {
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
		schedule_maintenance(state, apply_spindown, !ignore_threshold /* invert ignore logic */, msg, sizeof(msg), &status);
		break;
	case CMD_HEAL :
		schedule_heal(state, apply_spindown, msg, sizeof(msg), &status);
		break;
	case CMD_UNDELETE :
		schedule_undelete(state, apply_spindown, &arg_list, msg, sizeof(msg), &status);
		break;
	case CMD_SUSPEND_IDLE :
		schedule_suspend_idle(state, msg, sizeof(msg), &status);
		break;
	case CMD_REFRESH :
		schedule_refresh(state, msg, sizeof(msg), &status);
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
								char val[CONFIG_MAX];
								if (json_string(js, &jv[j], val, sizeof(val)) == 0) {
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
	tommy_list_foreach(&scheds, schedule_free);
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
 * POST /snapraid/v1/hold_off
 */
static int handler_hold_off(struct mg_connection* conn, void* cbdata)
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
	int level = 0;
	ss_t s;

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	status = json_read(conn, &js, &jl, msg, sizeof(msg));
	if (status != 200)
		return send_json_error(conn, status, msg);

	int hold_off = -1;

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
			if (json_entry(js, &jv[j], json_const("enabled")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &hold_off) == 0) {
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
	if (hold_off < 0)
		goto bad;

	free(js);

	status = 200;
	state_lock();
	state->runner.hold_off = hold_off;
	pulse(state, PULSE_ARRAY);
	state_unlock();

	ss_init(&s, JSON_INITIAL_SIZE);

	ss_json_open(&s, &level);
	ss_json_bool(&s, level, "success", 1);
	if (hold_off)
		ss_json_str(&s, level, "message", "Hold off enabled");
	else
		ss_json_str(&s, level, "message", "Hold off disabled");
	ss_json_close(&s, &level);

	send_json_answer(conn, status, &s);

	ss_done(&s);

	return send_json_success(conn, status);
bad:
	free(js);
	return send_json_error(conn, 400, "Unrecognized json");
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

static void json_id_list(ss_t* s, int level, sl_t* sl)
{
	ss_json_array_open(s, &level, "ids");
	for (tommy_node* i = tommy_list_head(sl); i != 0; i = i->next) {
		sn_t* sn = i->data;
		ss_json_elem(s, level, sn->str);
	}
	ss_json_array_close(s, &level);
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
		ss_json_str(s, level, "node", dev->file);
		json_id_list(s, level, &dev->id_list);
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
		uint64_t temp;
		uint64_t temp_min;
		uint64_t temp_max;
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
			ss_json_bool(s, level, "selftest_error_logged", dev->flags & SMARTCTL_FLAG_SELFTEST_ERROR_LOGGED);
		}
		ss_json_close(s, &level);
		ss_json_close(s, &level);
	}
}

static void json_disk_list(ss_t* s, int level, tommy_list* list, int kind, int64_t reference)
{
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		if (disk->kind != kind)
			continue;

		ss_json_open(s, &level);
		ss_json_str(s, level, "name", disk->name);
		ss_json_str(s, level, "health", health_name(health_disk(disk, 0, 0)));
		if (disk->total_space_bytes != SMART_UNASSIGNED)
			ss_json_u64(s, level, "total_space_bytes", disk->total_space_bytes);
		if (disk->free_space_bytes != SMART_UNASSIGNED)
			ss_json_u64(s, level, "free_space_bytes", disk->free_space_bytes);
		if (disk->access_count != SMART_UNASSIGNED) {
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

static int limit_parse(const struct mg_request_info* ri, const char* name, int def)
{
	char buf[16];

	if (ri->query_string == 0)
		return def;

	int ret = mg_get_var(ri->query_string, strlen(ri->query_string), name, buf, sizeof(buf));
	if (ret <= 0)
		return def;

	int v;
	if (strint(&v, buf) != 0)
		return def;
	if (v < 0)
		return def;

	return v;
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
	json_disk_list(&s, level, &state->disk_list, DISK_DATA, state->global.last_time);
	ss_json_array_close(&s, &level);
	ss_json_array_open(&s, &level, "parity_disks");
	json_disk_list(&s, level, &state->disk_list, DISK_PARITY, state->global.last_time);
	ss_json_array_close(&s, &level);
	ss_json_array_open(&s, &level, "extra_disks");
	json_disk_list(&s, level, &state->disk_list, DISK_EXTRA, state->global.last_time);
	ss_json_array_close(&s, &level);
	ss_json_close(&s, &level);

	state_unlock();

	send_json_answer(conn, 200, &s);

	ss_done(&s);

	return 200;
}

static void json_task(ss_t* s, int level, struct snapraid_task* task, struct snapraid_pulse* pulse, int limit_messages)
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
		if (--limit_messages < 0)
			break;
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
		case MESSAGE_LEVEL_VERBOSE :
			ss_json_str(s, level, "level", "verbose");
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

	int limit_messages = limit_parse(ri, "limit_messages", INT_MAX);

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	struct snapraid_task* task = state->runner.latest;
	if (!task) {
		state_unlock();
		ss_done(&s);
		return send_no_content(conn);
	}

	json_task(&s, level, task, &state->pulse, limit_messages);

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

	int limit_history = limit_parse(ri, "limit_history", INT_MAX);
	int limit_messages = limit_parse(ri, "limit_messages", INT_MAX);

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_json_open(&s, &level);
	json_pulse(&s, level, &state->pulse);
	ss_json_array_open(&s, &level, "pending");
	/* backward order, like is shown in the UI */
	tommy_node* i = tommy_list_tail(&state->runner.waiting_list);
	while (i != 0) {
		struct snapraid_task* task = i->data;
		json_task(&s, level, task, 0, limit_messages);

		if (i == tommy_list_head(&state->runner.waiting_list))
			break;
		i = i->prev;
	}
	ss_json_array_close(&s, &level);

	ss_json_array_open(&s, &level, "active");
	if (state->runner.latest && state->runner.latest->running)
		json_task(&s, level, state->runner.latest, 0, limit_messages);
	ss_json_array_close(&s, &level);

	ss_json_array_open(&s, &level, "history");
	/* backward order, like is shown in the UI */
	i = tommy_list_tail(&state->runner.history_list);
	while (i != 0) {
		struct snapraid_task* task = i->data;
		if (--limit_history < 0)
			break;
		json_task(&s, level, task, 0, limit_messages);

		if (i == tommy_list_head(&state->runner.history_list))
			break;
		i = i->prev;
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

	int limit_diffs = limit_parse(ri, "limit_diffs", INT_MAX);
	int limit_fixes = limit_parse(ri, "limit_fixes", INT_MAX);

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	uint64_t total_space_bytes = 0;
	uint64_t free_space_bytes = 0;
	int data_count = 0;
	for (tommy_node* i = tommy_list_head(&state->disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		if (disk->kind != DISK_DATA)
			continue;

		++data_count;
		if (disk->total_space_bytes == SMART_UNASSIGNED
			|| total_space_bytes == SMART_UNASSIGNED) {
			total_space_bytes = SMART_UNASSIGNED;
		} else {
			total_space_bytes += disk->total_space_bytes;
		}
		if (disk->free_space_bytes == SMART_UNASSIGNED
			|| free_space_bytes == SMART_UNASSIGNED) {
			free_space_bytes = SMART_UNASSIGNED;
		} else {
			free_space_bytes += disk->free_space_bytes;
		}
	}
	if (!data_count) {
		total_space_bytes = SMART_UNASSIGNED;
		free_space_bytes = SMART_UNASSIGNED;
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
		ss_json_int(&s, level, "data_disks_count", disk_count(&state->disk_list, DISK_DATA));
		ss_json_int(&s, level, "parity_disks_count", disk_count(&state->disk_list, DISK_PARITY));
		ss_json_int(&s, level, "extra_disks_count", disk_count(&state->disk_list, DISK_EXTRA));
		if (total_space_bytes != SMART_UNASSIGNED)
			ss_json_u64(&s, level, "total_space_bytes", total_space_bytes);
		if (free_space_bytes != SMART_UNASSIGNED)
			ss_json_u64(&s, level, "free_space_bytes", free_space_bytes);
		double afr = afr_array(state);
		if (afr != 0)
			ss_json_double(&s, level, "annual_failure_rate", afr);
		double fp = fp_array(state);
		if (fp != 0)
			ss_json_double(&s, level, "failure_probability", fp);
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
		ss_json_bool(&s, level, "hold_off", state->runner.hold_off);
		ss_json_u64(&s, level, "diff_equal", global->diff_current.diff_equal);
		ss_json_u64(&s, level, "diff_added", global->diff_current.diff_added);
		ss_json_u64(&s, level, "diff_removed", global->diff_current.diff_removed);
		ss_json_u64(&s, level, "diff_updated", global->diff_current.diff_updated);
		ss_json_u64(&s, level, "diff_moved", global->diff_current.diff_moved);
		ss_json_u64(&s, level, "diff_copied", global->diff_current.diff_copied);
		ss_json_u64(&s, level, "diff_relocated", global->diff_current.diff_relocated);
		ss_json_u64(&s, level, "diff_restored", global->diff_current.diff_restored);
		ss_json_array_open(&s, &level, "diffs");
		for (tommy_node* i = tommy_list_head(&global->diff_current.file_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (--limit_diffs < 0)
				break;
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
			if (--limit_fixes < 0)
				break;
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

/****************************************************************************/
/* metrics */

#define METRICS_DISK_ROLE_COUNT 3

static const struct {
	int kind;
	const char* role;
} METRICS_DISK_ROLES[METRICS_DISK_ROLE_COUNT] = {
	{ DISK_DATA, "data" },
	{ DISK_PARITY, "parity" },
	{ DISK_EXTRA, "extra" }
};

static int metrics_health_numeric(int health)
{
	switch (health) {
	case HEALTH_PENDING : return 0;
	case HEALTH_PASSED : return 1;
	case HEALTH_CORRUPT : return 2;
	case HEALTH_PREFAIL : return 3;
	case HEALTH_FAILING : return 4;
	}

	return 0;
}

static const char* metrics_task_status(struct snapraid_task* task)
{
	if (task->running) {
		switch (task->state) {
		case PROCESS_STATE_START : return "starting";
		case PROCESS_STATE_RUN : return "processing";
		case PROCESS_STATE_TERM : return "finalizing";
		case PROCESS_STATE_SIGNAL : return "stopping";
		}
	} else {
		switch (task->state) {
		case PROCESS_STATE_QUEUE : return "queued";
		case PROCESS_STATE_SIGNAL : return "signaled";
		case PROCESS_STATE_CANCEL : return "canceled";
		case PROCESS_STATE_TERM : return "terminated";
		}
	}
	return "";
}

struct metrics_task_tuple {
	const char* command;
	const char* status;
	const char* health;
	int count;
};

struct metrics_latest_task {
	int cmd;
	struct snapraid_task* task;
};

static void ss_prints_prometheus_escaped(ss_t* s, const char* str)
{
	for (const char* p = str; *p; ++p) {
		if (*p == '\\') {
			ss_prints(s, "\\\\");
		} else if (*p == '"') {
			ss_prints(s, "\\\"");
		} else if (*p == '\n') {
			ss_prints(s, "\\n");
		} else {
			ss_printc(s, *p, 1);
		}
	}
}

/**
 * GET /metrics — Prometheus exposition format
 */
static int handler_metrics(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);

	if (strcmp(ri->request_method, "OPTIONS") == 0)
		return send_no_content(conn);

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_t s;
	ss_init(&s, METRICS_INITIAL_SIZE);

	state_lock();

	struct snapraid_global* global = &state->global;
	struct snapraid_config* config = &state->config;
	struct snapraid_runner* runner = &state->runner;
	struct snapraid_pulse* pulse = &state->pulse;

	/* array health */
	ss_prints(&s, "# HELP snapraid_array_health Array health state (pending=0, passed=1, corrupt=2, prefail=3, failing=4)\n");
	ss_prints(&s, "# TYPE snapraid_array_health gauge\n");
	ss_printf(&s, "snapraid_array_health %d\n", metrics_health_numeric(global->health));
	ss_prints(&s, "\n");

	/* build info */
	ss_prints(&s, "# HELP snapraid_build_info Daemon and engine version info (always 1)\n");
	ss_prints(&s, "# TYPE snapraid_build_info gauge\n");
	ss_printf(&s, "snapraid_build_info{daemon_version=\"%s\",engine_version=\"%s\"} 1\n",
		PACKAGE_VERSION,
		*global->version ? global->version : "");
	ss_prints(&s, "\n");

	/* array scalars (only when engine has run) */
	if (global->blocksize) {
		ss_prints(&s, "# HELP snapraid_array_block_size_bytes SnapRAID block size in bytes\n");
		ss_prints(&s, "# TYPE snapraid_array_block_size_bytes gauge\n");
		ss_printf(&s, "snapraid_array_block_size_bytes %u\n", global->blocksize);
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_array_data_disks_count Number of configured data disks\n");
		ss_prints(&s, "# TYPE snapraid_array_data_disks_count gauge\n");
		ss_printf(&s, "snapraid_array_data_disks_count %d\n", disk_count(&state->disk_list, DISK_DATA));
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_array_parity_disks_count Number of configured parity disks\n");
		ss_prints(&s, "# TYPE snapraid_array_parity_disks_count gauge\n");
		ss_printf(&s, "snapraid_array_parity_disks_count %d\n", disk_count(&state->disk_list, DISK_PARITY));
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_array_extra_disks_count Number of configured extra disks\n");
		ss_prints(&s, "# TYPE snapraid_array_extra_disks_count gauge\n");
		ss_printf(&s, "snapraid_array_extra_disks_count %d\n", disk_count(&state->disk_list, DISK_EXTRA));
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_array_files Current count of tracked files (gauge snapshot, not a counter)\n");
		ss_prints(&s, "# TYPE snapraid_array_files gauge\n");
		ss_printf(&s, "snapraid_array_files %" PRIu64 "\n", global->file_total);
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_array_blocks Total number of blocks in the array\n");
		ss_prints(&s, "# TYPE snapraid_array_blocks gauge\n");
		ss_printf(&s, "snapraid_array_blocks %" PRIu64 "\n", global->block_total);
		ss_prints(&s, "\n");
	}

	/* block integrity */
	ss_prints(&s, "# HELP snapraid_blocks_bad Number of bad blocks detected\n");
	ss_prints(&s, "# TYPE snapraid_blocks_bad gauge\n");
	ss_printf(&s, "snapraid_blocks_bad %" PRIu64 "\n", global->block_bad);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_blocks_unsynced Number of blocks not yet synced to parity\n");
	ss_prints(&s, "# TYPE snapraid_blocks_unsynced gauge\n");
	ss_printf(&s, "snapraid_blocks_unsynced %" PRIu64 "\n", global->block_unsynced);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_blocks_unscrubbed Number of blocks not yet scrubbed\n");
	ss_prints(&s, "# TYPE snapraid_blocks_unscrubbed gauge\n");
	ss_printf(&s, "snapraid_blocks_unscrubbed %" PRIu64 "\n", global->block_unscrubbed);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_blocks_rehash Number of blocks scheduled for rehash\n");
	ss_prints(&s, "# TYPE snapraid_blocks_rehash gauge\n");
	ss_printf(&s, "snapraid_blocks_rehash %" PRIu64 "\n", global->block_rehash);
	ss_prints(&s, "\n");

	/* timestamps (omitted if operation never ran) */
	if (global->sync_time || global->scrub_time || global->diff_time || global->fix_time || global->last_time) {
		ss_prints(&s, "# HELP snapraid_last_command_timestamp_seconds Unix timestamp of the last completed command\n");
		ss_prints(&s, "# TYPE snapraid_last_command_timestamp_seconds gauge\n");
		if (global->sync_time) {
			ss_printf(&s, "snapraid_last_command_timestamp_seconds{command=\"sync\"} %" PRIi64 "\n", (int64_t)global->sync_time);
		}
		if (global->scrub_time) {
			ss_printf(&s, "snapraid_last_command_timestamp_seconds{command=\"scrub\"} %" PRIi64 "\n", (int64_t)global->scrub_time);
		}
		if (global->diff_time) {
			ss_printf(&s, "snapraid_last_command_timestamp_seconds{command=\"diff\"} %" PRIi64 "\n", (int64_t)global->diff_time);
		}
		if (global->fix_time) {
			ss_printf(&s, "snapraid_last_command_timestamp_seconds{command=\"fix\"} %" PRIi64 "\n", (int64_t)global->fix_time);
		}
		if (global->last_time) {
			const char* last_c = *global->last_cmd ? global->last_cmd : "any";
			if (strcmp(last_c, "sync") != 0 && strcmp(last_c, "scrub") != 0 && strcmp(last_c, "diff") != 0 && strcmp(last_c, "fix") != 0) {
				ss_printf(&s, "snapraid_last_command_timestamp_seconds{command=\"%s\"} %" PRIi64 "\n",
					last_c, (int64_t)global->last_time);
			}
		}
		ss_prints(&s, "\n");
	}

	/* diff counts */
	ss_prints(&s, "# HELP snapraid_diff_files File diff counts from the last diff run by change type\n");
	ss_prints(&s, "# TYPE snapraid_diff_files gauge\n");
	ss_printf(&s, "snapraid_diff_files{change=\"equal\"} %" PRIi64 "\n", global->diff_current.diff_equal);
	ss_printf(&s, "snapraid_diff_files{change=\"added\"} %" PRIi64 "\n", global->diff_current.diff_added);
	ss_printf(&s, "snapraid_diff_files{change=\"removed\"} %" PRIi64 "\n", global->diff_current.diff_removed);
	ss_printf(&s, "snapraid_diff_files{change=\"updated\"} %" PRIi64 "\n", global->diff_current.diff_updated);
	ss_printf(&s, "snapraid_diff_files{change=\"moved\"} %" PRIi64 "\n", global->diff_current.diff_moved);
	ss_printf(&s, "snapraid_diff_files{change=\"copied\"} %" PRIi64 "\n", global->diff_current.diff_copied);
	ss_printf(&s, "snapraid_diff_files{change=\"relocated\"} %" PRIi64 "\n", global->diff_current.diff_relocated);
	ss_printf(&s, "snapraid_diff_files{change=\"restored\"} %" PRIi64 "\n", global->diff_current.diff_restored);
	ss_prints(&s, "\n");

	/* config thresholds */
	ss_prints(&s, "# HELP snapraid_config_sync_threshold_deletes Sync delete threshold (0 = disabled)\n");
	ss_prints(&s, "# TYPE snapraid_config_sync_threshold_deletes gauge\n");
	ss_printf(&s, "snapraid_config_sync_threshold_deletes %d\n", config->sync_threshold_deletes);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_config_sync_threshold_updates Sync update threshold (0 = disabled)\n");
	ss_prints(&s, "# TYPE snapraid_config_sync_threshold_updates gauge\n");
	ss_printf(&s, "snapraid_config_sync_threshold_updates %d\n", config->sync_threshold_updates);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_config_scrub_percentage Percentage of array scrubbed per scrub run\n");
	ss_prints(&s, "# TYPE snapraid_config_scrub_percentage gauge\n");
	ss_printf(&s, "snapraid_config_scrub_percentage %g\n", config->scrub_percentage);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_config_scrub_older_than_days Only scrub blocks older than this many days (0 = ignore)\n");
	ss_prints(&s, "# TYPE snapraid_config_scrub_older_than_days gauge\n");
	ss_printf(&s, "snapraid_config_scrub_older_than_days %d\n", config->scrub_older_than);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_config_spindown_idle_minutes Spin down disks after this many idle minutes (0 = disabled)\n");
	ss_prints(&s, "# TYPE snapraid_config_spindown_idle_minutes gauge\n");
	ss_printf(&s, "snapraid_config_spindown_idle_minutes %d\n", config->spindown_idle_minutes);
	ss_prints(&s, "\n");

	ss_prints(&s, "# HELP snapraid_config_probe_interval_minutes Interval between probe commands in minutes (0 = disabled)\n");
	ss_prints(&s, "# TYPE snapraid_config_probe_interval_minutes gauge\n");
	ss_printf(&s, "snapraid_config_probe_interval_minutes %d\n", config->probe_interval_minutes);
	ss_prints(&s, "\n");

	/* hold-off */
	ss_prints(&s, "# HELP snapraid_config_hold_off Hold-off state\n");
	ss_prints(&s, "# TYPE snapraid_config_hold_off gauge\n");
	ss_printf(&s, "snapraid_config_hold_off %d\n", runner->hold_off ? 1 : 0);
	ss_prints(&s, "\n");

	/* per-disk health */
	ss_prints(&s, "# HELP snapraid_disk_health Per-disk health state (pending=0, passed=1, corrupt=2, prefail=3, failing=4)\n");
	ss_prints(&s, "# TYPE snapraid_disk_health gauge\n");
	for (int r = 0; r < METRICS_DISK_ROLE_COUNT; ++r) {
		for (tommy_node* i = tommy_list_head(&state->disk_list); i; i = i->next) {
			struct snapraid_disk* disk = i->data;
			if (disk->kind != METRICS_DISK_ROLES[r].kind)
				continue;
			ss_prints(&s, "snapraid_disk_health{disk=\"");
			ss_prints_prometheus_escaped(&s, disk->name);
			ss_printf(&s, "\",role=\"%s\"} %d\n", METRICS_DISK_ROLES[r].role, metrics_health_numeric(health_disk(disk, 0, 0)));
		}
	}
	ss_prints(&s, "\n");

	/* per-disk I/O error counters */
	ss_prints(&s, "# HELP snapraid_disk_error Session errors per disk (cleared after clean scrub)\n");
	ss_prints(&s, "# TYPE snapraid_disk_error gauge\n");
	for (int r = 0; r < METRICS_DISK_ROLE_COUNT; ++r) {
		for (tommy_node* i = tommy_list_head(&state->disk_list); i; i = i->next) {
			struct snapraid_disk* disk = i->data;
			if (disk->kind != METRICS_DISK_ROLES[r].kind)
				continue;
			ss_prints(&s, "snapraid_disk_error{disk=\"");
			ss_prints_prometheus_escaped(&s, disk->name);
			ss_printf(&s, "\",role=\"%s\",kind=\"io\"} %" PRIu64 "\n",
				METRICS_DISK_ROLES[r].role, disk->error_io);
			ss_prints(&s, "snapraid_disk_error{disk=\"");
			ss_prints_prometheus_escaped(&s, disk->name);
			ss_printf(&s, "\",role=\"%s\",kind=\"data\"} %" PRIu64 "\n",
				METRICS_DISK_ROLES[r].role, disk->error_data);
		}
	}
	ss_prints(&s, "\n");

	/* task queue depth */
	ss_prints(&s, "# HELP snapraid_task_queue_depth Number of tasks queued (pending)\n");
	ss_prints(&s, "# TYPE snapraid_task_queue_depth gauge\n");
	ss_printf(&s, "snapraid_task_queue_depth %zu\n", tommy_list_count(&runner->waiting_list));
	ss_prints(&s, "\n");

	/* active task (omitted when idle) */
	if (runner->latest && runner->latest->running) {
		struct snapraid_task* task = runner->latest;

		ss_prints(&s, "# HELP snapraid_task_active Currently active task (1 = running, omitted when idle)\n");
		ss_prints(&s, "# TYPE snapraid_task_active gauge\n");
		ss_printf(&s, "snapraid_task_active{command=\"%s\",high_command=\"%s\"} 1\n",
			command_name(task->cmd),
			task->high_cmd ? command_name(task->high_cmd) : "");
		ss_prints(&s, "\n");

		if (task->cmd == CMD_SYNC || task->cmd == CMD_SCRUB
			|| task->cmd == CMD_FIX || task->cmd == CMD_CHECK) {
			if (task->state == PROCESS_STATE_RUN) {
				ss_prints(&s, "# HELP snapraid_task_active_progress_percent Progress of the active task in percent\n");
				ss_prints(&s, "# TYPE snapraid_task_active_progress_percent gauge\n");
				ss_printf(&s, "snapraid_task_active_progress_percent %u\n", task->progress);
				ss_prints(&s, "\n");

				ss_prints(&s, "# HELP snapraid_task_active_eta_seconds Estimated seconds until the active task completes\n");
				ss_prints(&s, "# TYPE snapraid_task_active_eta_seconds gauge\n");
				ss_printf(&s, "snapraid_task_active_eta_seconds %u\n", task->eta_seconds);
				ss_prints(&s, "\n");
			}

			if (task->state == PROCESS_STATE_RUN
				|| task->state == PROCESS_STATE_TERM
				|| task->state == PROCESS_STATE_SIGNAL) {
				ss_prints(&s, "# HELP snapraid_task_active_speed_mbytes_per_second Speed of the active task in MiB/s\n");
				ss_prints(&s, "# TYPE snapraid_task_active_speed_mbytes_per_second gauge\n");
				ss_printf(&s, "snapraid_task_active_speed_mbytes_per_second %u\n", task->speed_mbs);
				ss_prints(&s, "\n");

				ss_prints(&s, "# HELP snapraid_task_active_elapsed_seconds Seconds elapsed since the active task started\n");
				ss_prints(&s, "# TYPE snapraid_task_active_elapsed_seconds gauge\n");
				ss_printf(&s, "snapraid_task_active_elapsed_seconds %u\n", task->elapsed_seconds);
				ss_prints(&s, "\n");
			}
		}
	}

	/* task history: accumulate (command, status, health) counts */
	struct metrics_task_tuple tuples[METRICS_TASK_TUPLES_MAX];
	int tuple_count = 0;

	struct metrics_latest_task latest_tasks[METRICS_LATEST_TASK_MAX];
	int latest_task_count = 0;

	for (tommy_node* i = tommy_list_head(&runner->history_list); i; i = i->next) {
		struct snapraid_task* task = i->data;
		const char* cmd_str = command_name(task->cmd);
		const char* status_str = metrics_task_status(task);
		const char* health_str = health_name(health_task(task));

		/* accumulate count for this (command, status, health) tuple */
		int found = 0;
		for (int j = 0; j < tuple_count; ++j) {
			if (tuples[j].command == cmd_str
				&& tuples[j].status == status_str
				&& tuples[j].health == health_str) {
				++tuples[j].count;
				found = 1;
				break;
			}
		}
		if (!found && tuple_count < METRICS_TASK_TUPLES_MAX) {
			tuples[tuple_count].command = cmd_str;
			tuples[tuple_count].status = status_str;
			tuples[tuple_count].health = health_str;
			tuples[tuple_count].count = 1;
			++tuple_count;
		}

		/* track latest terminated task per command */
		if (!task->running && task->state == PROCESS_STATE_TERM) {
			int found_latest = 0;
			for (int j = 0; j < latest_task_count; ++j) {
				if (latest_tasks[j].cmd == task->cmd) {
					latest_tasks[j].task = task;
					found_latest = 1;
					break;
				}
			}
			if (!found_latest && latest_task_count < METRICS_LATEST_TASK_MAX) {
				latest_tasks[latest_task_count].cmd = task->cmd;
				latest_tasks[latest_task_count].task = task;
				++latest_task_count;
			}
		}
	}

	if (tuple_count > 0) {
		ss_prints(&s, "# HELP snapraid_tasks_history_size Snapshot count of completed tasks in daemon history buffer\n");
		ss_prints(&s, "# TYPE snapraid_tasks_history_size gauge\n");
		for (int j = 0; j < tuple_count; ++j) {
			ss_printf(&s, "snapraid_tasks_history_size{command=\"%s\",status=\"%s\",health=\"%s\"} %d\n",
				tuples[j].command, tuples[j].status, tuples[j].health, tuples[j].count);
		}
		ss_prints(&s, "\n");
	}

	/* last terminated task per command */
	if (latest_task_count > 0) {
		ss_prints(&s, "# HELP snapraid_task_last_exit_code Exit code of the most recent terminated task per command\n");
		ss_prints(&s, "# TYPE snapraid_task_last_exit_code gauge\n");
		for (int j = 0; j < latest_task_count; ++j) {
			struct snapraid_task* task = latest_tasks[j].task;
			ss_printf(&s, "snapraid_task_last_exit_code{command=\"%s\"} %d\n",
				command_name(task->cmd), task->exit_code);
		}
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_task_last_duration_seconds Duration in seconds of the most recent terminated task per command\n");
		ss_prints(&s, "# TYPE snapraid_task_last_duration_seconds gauge\n");
		for (int j = 0; j < latest_task_count; ++j) {
			struct snapraid_task* task = latest_tasks[j].task;
			if (task->unix_start_time && task->unix_end_time) {
				ss_printf(&s, "snapraid_task_last_duration_seconds{command=\"%s\"} %" PRIi64 "\n",
					command_name(task->cmd),
					task->unix_end_time - task->unix_start_time);
			}
		}
		ss_prints(&s, "\n");

		ss_prints(&s, "# HELP snapraid_task_last_errors Error counts from the most recent terminated task per command and error kind\n");
		ss_prints(&s, "# TYPE snapraid_task_last_errors gauge\n");
		for (int j = 0; j < latest_task_count; ++j) {
			struct snapraid_task* task = latest_tasks[j].task;
			const char* cmd_str = command_name(task->cmd);
			switch (task->cmd) {
			case CMD_SYNC :
			case CMD_SCRUB :
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"soft\"} %" PRIu64 "\n",
					cmd_str, task->error_soft + task->hash_error_soft);
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"io\"} %" PRIu64 "\n",
					cmd_str, task->error_io);
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"data\"} %" PRIu64 "\n",
					cmd_str, task->error_data);
				break;
			case CMD_FIX :
			case CMD_CHECK :
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"unrecoverable\"} %" PRIu64 "\n",
					cmd_str, task->error_unrecoverable);
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"soft\"} %" PRIu64 "\n",
					cmd_str, task->error_soft + task->hash_error_soft);
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"io\"} %" PRIu64 "\n",
					cmd_str, task->error_io);
				ss_printf(&s, "snapraid_task_last_errors{command=\"%s\",kind=\"data\"} %" PRIu64 "\n",
					cmd_str, task->error_data);
				break;
			}
		}
		ss_prints(&s, "\n");
	}

	/* pulse counters */
	ss_prints(&s, "# HELP snapraid_exporter_last_pulse Pulse counter value per subsystem from the daemon\n");
	ss_prints(&s, "# TYPE snapraid_exporter_last_pulse gauge\n");
	ss_printf(&s, "snapraid_exporter_last_pulse{subsystem=\"array\"} %" PRIu64 "\n", pulse->array);
	ss_printf(&s, "snapraid_exporter_last_pulse{subsystem=\"config\"} %" PRIu64 "\n", pulse->config);
	ss_printf(&s, "snapraid_exporter_last_pulse{subsystem=\"disks\"} %" PRIu64 "\n", pulse->disks_attr + pulse->disks_ui);
	ss_printf(&s, "snapraid_exporter_last_pulse{subsystem=\"tasks\"} %" PRIu64 "\n", pulse->tasks);
	ss_printf(&s, "snapraid_exporter_last_pulse{subsystem=\"activity\"} %" PRIu64 "\n", pulse->activity);
	ss_prints(&s, "\n");

	/* daemon uptime */
	ss_prints(&s, "# HELP snapraid_daemon_uptime_seconds Seconds the daemon has been running\n");
	ss_prints(&s, "# TYPE snapraid_daemon_uptime_seconds gauge\n");
	ss_printf(&s, "snapraid_daemon_uptime_seconds %" PRIi64 "\n", (int64_t)(time(0) - state->daemon_start_time));
	ss_prints(&s, "\n");

	/* exporter up */
	ss_prints(&s, "# HELP snapraid_exporter_up 1 if the daemon is running and serving metrics\n");
	ss_prints(&s, "# TYPE snapraid_exporter_up gauge\n");
	ss_prints(&s, "snapraid_exporter_up 1\n");

	state_unlock();

	send_text_answer(conn, 200, &s);
	ss_done(&s);

	return 200;
}

int rest_init(struct snapraid_state* state)
{
	const char* options[20];
	char listening_port[CONFIG_MAX];
	int listening_port_default;
	int i;

	if (!state->config.net_enabled)
		return 0;

	i = 0;

	sncpy(listening_port, sizeof(listening_port), state->config.net_port);
	listening_port_default = 0;
	if (listening_port[0] == 0) {
		/* listen to both IPv4 and IPv6 */
		sncpy(listening_port, sizeof(listening_port), "[::1]:7627,127.0.0.1:7627");
		listening_port_default = 1;
	}
	options[i++] = "listening_ports";
	options[i++] = listening_port;
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
	if (!state->rest_context && listening_port_default) {
		/* retry with only IPv4 */
		log_msg(LVL_WARNING, "failed to start web server binding to both IPv4 and IPv6, going to retry with IPv4 only, errno=%s(%d)", strerror(errno), errno);
		sncpy(listening_port, sizeof(listening_port), "127.0.0.1:7627");
		state->rest_context = mg_start(&state->rest_callbacks, state, options);
	}
	if (!state->rest_context) {
		log_msg(LVL_ERROR, "failed to start web server, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	mg_set_request_handler(state->rest_context, "/snapraid/v1/maintenance", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/heal", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/undelete", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/suspend_idle", handler_action, state);
	mg_set_request_handler(state->rest_context, "/snapraid/v1/refresh", handler_action, state);
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
	mg_set_request_handler(state->rest_context, "/snapraid/v1/hold_off", handler_hold_off, state);
	mg_set_request_handler(state->rest_context, "/metrics", handler_metrics, state);
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

