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

/**
 * Max length of a JSON escaped string with json_esc()
 */
#define JSON_ESC_MAX 256

static char* json_esc(const char* src, char* dst)
{
	char* dst_begin = dst;
	char* dst_end = dst_begin + JSON_ESC_MAX;

	while (*src && dst_end - dst > 1) {
		switch (*src) {
		case '"' :
		case '\\' :
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = *src++;
			}
			break;
		case '\n' :
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 'n';
				++src;
			}
			break;
		case '\r' :
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 'r';
				++src;
			}
			break;
		case '\t' :
			if (dst_end - dst > 2) {
				*dst++ = '\\';
				*dst++ = 't';
				++src;
			}
			break;
		default :
			*dst++ = *src++;
			break;
		}
	}

	*dst = 0;

	return dst_begin;
}

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
/* data */

static const char* power_name(int power)
{
	switch (power) {
	case POWER_STANDBY : return "standby";
	case POWER_ACTIVE : return "active";
	case POWER_PENDING : return "pending";
	}

	return "-";
}

static const char* health_name(int health)
{
	switch (health) {
	case HEALTH_PASSED : return "passed";
	case HEALTH_FAILING : return "failing";
	case HEALTH_PENDING : return "pending";
	}

	return "-";
}

static int health_device_list(tommy_list* list)
{
	int health = HEALTH_PASSED;

	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* device = i->data;
		if (device->health == HEALTH_FAILING)
			return HEALTH_FAILING;
		if (device->health == HEALTH_PENDING)
			health = HEALTH_PENDING;
	}

	return health;
}

static int health_split_list(tommy_list* list)
{
	int health = HEALTH_PASSED;

	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_split* split = i->data;
		int device_health = health_device_list(&split->device_list);
		if (device_health == HEALTH_FAILING)
			return HEALTH_FAILING;
		if (device_health == HEALTH_PENDING)
			health = HEALTH_PENDING;
	}

	return health;
}

static int health_data(struct snapraid_data* data)
{
	if (data->error_data != 0 || data->error_io != 0)
		return HEALTH_FAILING;
	return health_device_list(&data->device_list);
}

static int health_parity(struct snapraid_parity* parity)
{
	if (parity->error_data != 0 || parity->error_io != 0)
		return HEALTH_FAILING;
	return health_split_list(&parity->split_list);
}

static int health_task(struct snapraid_task* task)
{
	if (task->error_data != 0 || task->error_io != 0 || task->block_bad != 0)
		return HEALTH_FAILING;
	switch (task->state) {
	case PROCESS_STATE_QUEUE :
		return HEALTH_PENDING;
	case PROCESS_STATE_TERM :
		if (task->exit_code != 0)
			return HEALTH_FAILING;
		break;
	case PROCESS_STATE_SIGNAL :
		return HEALTH_FAILING;
	}
	return HEALTH_PASSED;
}

static int health_array(struct snapraid_state* state)
{
	int health = HEALTH_PASSED;
	if (state->global.block_bad != 0)
		return HEALTH_FAILING;
	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_data* data = i->data;
		int data_health = health_data(data);
		if (data_health == HEALTH_FAILING)
			return HEALTH_FAILING;
		if (data_health == HEALTH_PENDING)
			health = HEALTH_PENDING;
	}
	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_parity* parity = i->data;
		int parity_health = health_parity(parity);
		if (parity_health == HEALTH_FAILING)
			return HEALTH_FAILING;
		if (parity_health == HEALTH_PENDING)
			parity_health = HEALTH_PENDING;
	}
	return health;
}

/****************************************************************************/
/* helper */

static void send_json_answer(struct mg_connection* conn, ss_t* s)
{
	mg_printf(conn, "HTTP/1.1 200 OK\r\n");
	mg_printf(conn, "Content-Type: application/json\r\n");
	mg_printf(conn, "Content-Length: %zd\r\n", ss_len(s));
	mg_printf(conn, "Connection: close\r\n");
	mg_printf(conn, "\r\n");

	mg_write(conn, ss_ptr(s), ss_len(s));
}

static int send_json_success(struct mg_connection* conn, int status)
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

static int send_json_error(struct mg_connection* conn, int status, const char* message)
{
	char body[256];

	int body_len = snprintf(body, sizeof(body), "{\n  \"success\": false,\n  \"message\": \"%s\"\n}\n", message);

	mg_printf(conn, "HTTP/1.1 %d %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n",
		status, mg_get_response_code_text(conn, status), body_len);

	mg_write(conn, body, body_len);

	return status;
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
			if (json_entry(js, &jv[j], json_const("scheduled_run")) == 0) {
				++j;
				if (json_string(js, &jv[j], buf, sizeof(buf)) == 0
					&& config_parse_scheduled_run(buf, &state->config) == 0) {
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
			} else if (json_entry(js, &jv[j], json_const("sync_suspend_on_deletes")) == 0) {
				++j;
				if (json_value(js, &jv[j], 0, 10000, &state->config.sync_suspend_on_deletes) == 0) {
				} else {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_suspend_on_deletes);
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
			} else if (json_entry(js, &jv[j], json_const("sync_report_differences")) == 0) {
				++j;
				if (json_boolean(js, &jv[j], &state->config.sync_report_differences) == 0) {
					config_set_int(&state->config, json_token(js, &jv[j - 1]), state->config.sync_report_differences);
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
			} else if (json_entry(js, &jv[j], json_const("script_pre_run")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.script_pre_run, sizeof(state->config.script_pre_run)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("script_post_run")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.script_post_run, sizeof(state->config.script_post_run)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("log_directory")) == 0) {
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
			} else if (json_entry(js, &jv[j], json_const("notify_heartbeat")) == 0) {
				++j;
				if (json_string(js, &jv[j], state->config.notify_heartbeat, sizeof(state->config.notify_heartbeat)) == 0) {
					config_set_string(&state->config, json_token(js, &jv[j - 1]), json_token(js, &jv[j]));
				} else {
					json_error_arg(msg, sizeof(msg), js, &jv[j - 1], &jv[j]);
					goto bad;
				}
				++j;
			} else if (json_entry(js, &jv[j], json_const("notify_result")) == 0) {
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
	char esc_buf[JSON_ESC_MAX];
	char schedule_buf[64];

	state_lock();

	ss_init(&s, JSON_INITIAL_SIZE);

	config_schedule_str(config, schedule_buf, sizeof(schedule_buf));

	ss_jsonf(&s, tab, "{\n");
	++tab;

	ss_jsonf(&s, tab, "\"scheduled_run\": \"%s\",\n", json_esc(schedule_buf, esc_buf));
	ss_jsonf(&s, tab, "\"sync_suspend_on_deletes\": %d,\n", config->sync_suspend_on_deletes);
	ss_jsonf(&s, tab, "\"sync_prehash\": %s,\n", config->sync_prehash ? "true" : "false");
	ss_jsonf(&s, tab, "\"sync_force_zero\": %s,\n", config->sync_force_zero ? "true" : "false");
	ss_jsonf(&s, tab, "\"sync_report_differences\": %s,\n", config->sync_report_differences ? "true" : "false");
	ss_jsonf(&s, tab, "\"scrub_percentage\": %d,\n", config->scrub_percentage);
	ss_jsonf(&s, tab, "\"scrub_older_than\": %d,\n", config->scrub_older_than);

	ss_jsonf(&s, tab, "\"probe_interval_minutes\": %d,\n", config->probe_interval_minutes);
	ss_jsonf(&s, tab, "\"spindown_idle_minutes\": %d,\n", config->spindown_idle_minutes);

	ss_jsonf(&s, tab, "\"script_pre_run\": \"%s\",\n", json_esc(config->script_pre_run, esc_buf));
	ss_jsonf(&s, tab, "\"script_post_run\": \"%s\",\n", json_esc(config->script_post_run, esc_buf));

	ss_jsonf(&s, tab, "\"log_directory\": \"%s\",\n", json_esc(config->log_directory, esc_buf));
	ss_jsonf(&s, tab, "\"log_retention_days\": %d,\n", config->log_retention_days);

	ss_jsonf(&s, tab, "\"notify_syslog_enabled\": %s,\n", config->notify_syslog_enabled ? "true" : "false");
	ss_jsonf(&s, tab, "\"notify_syslog_level\": \"%s\",\n", config_level_str(config->notify_syslog_level));

	ss_jsonf(&s, tab, "\"notify_heartbeat\": \"%s\",\n", json_esc(config->notify_heartbeat, esc_buf));
	ss_jsonf(&s, tab, "\"notify_result\": \"%s\",\n", json_esc(config->notify_result, esc_buf));
	ss_jsonf(&s, tab, "\"notify_result_level\": \"%s\",\n", config_level_str(config->notify_result_level));

	ss_jsonf(&s, tab, "\"notify_email_recipient\": \"%s\",\n", json_esc(config->notify_email_recipient, esc_buf));
	ss_jsonf(&s, tab, "\"notify_email_level\": \"%s\"\n", config_level_str(config->notify_email_level));

	--tab;
	ss_jsonf(&s, tab, "}\n");

	state_unlock();

	send_json_answer(conn, &s);

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
					char* arg;
					if (json_string_inplace(js, &jv[j], &arg) == 0) {
						sl_insert_str(&arg_list, arg);
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

	if (strcmp(path, "/api/v1/sync") == 0)
		runner(state, CMD_SYNC, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/scrub") == 0)
		runner(state, CMD_SCRUB, &arg_list, msg, sizeof(msg), &status);		
	else if (strcmp(path, "/api/v1/probe") == 0)
		runner(state, CMD_PROBE, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/up") == 0)
		runner(state, CMD_UP, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/down") == 0)
		runner(state, CMD_DOWN, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/smart") == 0)
		runner(state, CMD_SMART, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/diff") == 0)
		runner(state, CMD_DIFF, &arg_list, msg, sizeof(msg), &status);
	else if (strcmp(path, "/api/v1/status") == 0)
		runner(state, CMD_STATUS, &arg_list, msg, sizeof(msg), &status);
	else {
		sncpy(msg, sizeof(msg), "Resource not found");
		status = 404;
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
	int tab = 0;
	ss_t s;

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");

	if (runner_stop(state, msg, sizeof(msg), &status, &pid, &number) != 0)
		return send_json_error(conn, status, msg);

	ss_init(&s, JSON_INITIAL_SIZE);

	ss_jsonf(&s, tab, "{\n");
	++tab;
	ss_jsonf(&s, tab, "\"success\": true,\n");
	ss_jsonf(&s, tab, "\"message\": \"Signal sent\",\n");
	ss_jsonf(&s, tab, "\"number\": %d,\n", number);
	ss_jsonf(&s, tab, "\"pid\": %" PRIu64 "\n", (uint64_t)pid);
	--tab;
	ss_jsonf(&s, tab, "}\n");

	mg_printf(conn, "HTTP/1.1 %d %s\r\n", status, mg_get_response_code_text(conn, status));
	mg_printf(conn, "Content-Type: application/json\r\n");
	mg_printf(conn, "Content-Length: %zd\r\n", ss_len(&s));
	mg_printf(conn, "Connection: close\r\n");
	mg_printf(conn, "\r\n");

	mg_write(conn, ss_ptr(&s), ss_len(&s));

	ss_done(&s);

	return status;
}

static void json_device_list(ss_t* s, int tab, tommy_list* list)
{
	char esc_buf[JSON_ESC_MAX];

	++tab;
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* dev = i->data;
		ss_jsonf(s, tab, "{\n");
		++tab;
		ss_jsonf(s, tab, "\"health\": \"%s\",\n", health_name(dev->health));
		if (*dev->family)
			ss_jsonf(s, tab, "\"family\": \"%s\",\n", json_esc(dev->family, esc_buf));
		if (*dev->model)
			ss_jsonf(s, tab, "\"model\": \"%s\",\n", json_esc(dev->model, esc_buf));
		if (*dev->serial)
			ss_jsonf(s, tab, "\"serial\": \"%s\",\n", json_esc(dev->serial, esc_buf));
		ss_jsonf(s, tab, "\"power\": \"%s\",\n", power_name(dev->power));
		if (dev->size != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"size_bytes\": %" PRIu64 ",\n", dev->size);
		if (dev->rotational != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"rotational\": %" PRIu64 ",\n", dev->rotational);
		if (dev->error_protocol != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"error_protocol\": %" PRIu64 ",\n", dev->error_protocol);
		if (dev->error_medium != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"error_medium\": %" PRIu64 ",\n", dev->error_medium);
		if (dev->wear_level != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"wear_level\": %" PRIu64 ",\n", dev->wear_level);
		if (dev->smart[SMART_REALLOCATED_SECTOR_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"reallocated_sector_count\": %" PRIu64 ",\n", dev->smart[SMART_REALLOCATED_SECTOR_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"uncorrectable_error_cnt\": %" PRIu64 ",\n", dev->smart[SMART_UNCORRECTABLE_ERROR_CNT] & 0xFFFF);
		if (dev->smart[SMART_COMMAND_TIMEOUT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"command_timeout\": %" PRIu64 ",\n", dev->smart[SMART_COMMAND_TIMEOUT] & 0xFFFF);
		if (dev->smart[SMART_CURRENT_PENDING_SECTOR] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"current_pending_sector\": %" PRIu64 ",\n", dev->smart[SMART_CURRENT_PENDING_SECTOR] & 0xFFFFFFFF);
		if (dev->smart[SMART_OFFLINE_UNCORRECTABLE] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"offline_uncorrectable\": %" PRIu64 ",\n", dev->smart[SMART_OFFLINE_UNCORRECTABLE] & 0xFFFFFFFF);
		if (dev->smart[SMART_START_STOP_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"start_stop_count\": %" PRIu64 ",\n", dev->smart[SMART_START_STOP_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_LOAD_CYCLE_COUNT] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"power_on_hours\": %" PRIu64 ",\n", dev->smart[SMART_LOAD_CYCLE_COUNT] & 0xFFFFFFFF);
		if (dev->smart[SMART_POWER_ON_HOURS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"load_cycle_count\": %" PRIu64 ",\n", dev->smart[SMART_POWER_ON_HOURS] & 0xFFFFFFFF);
		if (dev->smart[SMART_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"temperature_celsius\": %" PRIu64 ",\n", dev->smart[SMART_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		else if (dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] != SMART_UNASSIGNED)
			ss_jsonf(s, tab, "\"temperature_celsius\": %" PRIu64 ",\n", dev->smart[SMART_AIRFLOW_TEMPERATURE_CELSIUS] & 0xFFFFFFFF);
		if (dev->afr != 0)
			ss_jsonf(s, tab, "\"annual_failure_rate\": %g,\n", dev->afr);
		if (dev->prob != 0)
			ss_jsonf(s, tab, "\"failure_probability\": %g,\n", dev->prob);
		ss_jsonf(s, tab, "\"device_node\": \"%s\"\n", json_esc(dev->file, esc_buf));
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
	int tab = 0;
	ss_t s;
	char esc_buf[JSON_ESC_MAX];

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_jsonf(&s, 0, "{\n");
	++tab;
	ss_jsonf(&s, 1, "\"data_disks\": [\n");
	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_data* data = i->data;

		++tab;
		ss_jsonf(&s, tab, "{\n");
		++tab;
		ss_jsonf(&s, tab, "\"name\": \"%s\",\n", json_esc(data->name, esc_buf));
		ss_jsonf(&s, tab, "\"health\": \"%s\",\n", health_name(health_data(data)));
		ss_jsonf(&s, tab, "\"mount_dir\": \"%s\",\n", json_esc(data->dir, esc_buf));
		if (*data->uuid)
			ss_jsonf(&s, tab, "\"uuid\": \"%s\",\n", json_esc(data->uuid, esc_buf));
		if (*data->content_uuid)
			ss_jsonf(&s, tab, "\"stored_uuid\": \"%s\",\n", json_esc(data->content_uuid, esc_buf));
		if (data->content_size != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"allocated_space_bytes\": %" PRIu64 ",\n", data->content_size);
		if (data->content_free != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"free_space_bytes\": %" PRIu64 ",\n", data->content_free);
		if (data->access_count != 0) {
			ss_jsonf(&s, tab, "\"access_count\": %" PRIi64 ",\n", data->access_count);
			ss_json_iso8601(&s, tab, "\"access_count_initial_time\": \"%s\",\n", data->access_count_initial_time);
			ss_jsonf(&s, tab, "\"access_count_idle_duration\": %" PRIi64 ",\n", data->access_count_latest_time - data->access_count_initial_time);
		}
		ss_jsonf(&s, tab, "\"error_io\": %" PRIi64 ",\n", data->error_io);
		ss_jsonf(&s, tab, "\"error_data\": %" PRIi64 ",\n", data->error_data);
		ss_jsonf(&s, tab, "\"devices\": [\n");
		json_device_list(&s, tab, &data->device_list);
		ss_jsonf(&s, tab, "]\n");
		--tab;
		ss_jsonf(&s, tab, "}%s\n", i->next ? "," : "");
		--tab;
	}
	ss_jsonf(&s, tab, "],\n");
	ss_jsonf(&s, tab, "\"parity_disks\": [\n");
	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_parity* parity = i->data;

		++tab;
		ss_jsonf(&s, tab, "{\n");
		++tab;
		ss_jsonf(&s, tab, "\"name\": \"%s\",\n", json_esc(parity->name, esc_buf));
		ss_jsonf(&s, tab, "\"health\": \"%s\",\n", health_name(health_parity(parity)));
		if (parity->content_size != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"allocated_space_bytes\": %" PRIu64 ",\n", parity->content_size);
		if (parity->content_free != SMART_UNASSIGNED)
			ss_jsonf(&s, tab, "\"free_space_bytes\": %" PRIu64 ",\n", parity->content_free);
		if (parity->access_count != 0) {
			ss_jsonf(&s, tab, "\"access_count\": %" PRIi64 ",\n", parity->access_count);
			ss_json_iso8601(&s, tab, "\"access_count_initial_time\": \"%s\",\n", parity->access_count_initial_time);
			ss_jsonf(&s, tab, "\"access_count_idle_duration\": %" PRIi64 ",\n", parity->access_count_latest_time - parity->access_count_initial_time);
		}
		ss_jsonf(&s, tab, "\"error_io\": %" PRIi64 ",\n", parity->error_io);
		ss_jsonf(&s, tab, "\"error_data\": %" PRIi64 ",\n", parity->error_data);

		ss_jsonf(&s, tab, "\"splits\": [\n");
		for (tommy_node* j = tommy_list_head(&parity->split_list); j; j = j->next) {
			struct snapraid_split* split = j->data;

			++tab;
			ss_jsonf(&s, tab, "{\n");
			++tab;
			ss_jsonf(&s, tab, "\"parity_path\": \"%s\",\n", json_esc(split->path, esc_buf));
			if (*split->uuid)
				ss_jsonf(&s, tab, "\"uuid\": \"%s\",\n", json_esc(split->uuid, esc_buf));
			if (*split->content_uuid)
				ss_jsonf(&s, tab, "\"stored_uuid\": \"%s\",\n", json_esc(split->content_uuid, esc_buf));
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

	send_json_answer(conn, &s);

	ss_done(&s);

	return 200;
}

static void json_task(ss_t* s, int tab, struct snapraid_task* task, const char* next)
{
	char esc_buf[JSON_ESC_MAX];

	ss_jsons(s, tab, "{\n");
	++tab;
	ss_jsonf(s, tab, "\"number\": %d,\n", task->number);
	ss_jsonf(s, tab, "\"command\": \"%s\",\n", command_name(task->cmd));
	ss_jsonf(s, tab, "\"health\": \"%s\",\n", health_name(health_task(task)));
	if (task->running) {
		switch (task->state) {
		case PROCESS_STATE_START : ss_jsonf(s, tab, "\"status\": \"starting\",\n"); break;
		case PROCESS_STATE_RUN : ss_jsonf(s, tab, "\"status\": \"processing\",\n"); break;
		case PROCESS_STATE_TERM : ss_jsonf(s, tab, "\"status\": \"finishing\",\n"); break;
		case PROCESS_STATE_SIGNAL : ss_jsonf(s, tab, "\"status\": \"stopping\",\n"); break;
		}
	} else {
		switch (task->state) {
		case PROCESS_STATE_QUEUE :
			ss_jsonf(s, tab, "\"status\": \"queued\",\n");
			break;
		case PROCESS_STATE_SIGNAL :
			ss_jsonf(s, tab, "\"status\": \"signaled\",\n");
			ss_jsonf(s, tab, "\"exit_sig\": %d,\n", task->exit_sig);
			break;
		case PROCESS_STATE_CANCEL :
			ss_jsonf(s, tab, "\"status\": \"canceled\",\n");
			break;
		case PROCESS_STATE_TERM :
			ss_jsonf(s, tab, "\"status\": \"terminated\",\n");
			ss_jsonf(s, tab, "\"exit_code\": %d,\n", task->exit_code);
			break;
		}
	}
	if (task->unix_queue_time)
		ss_json_iso8601(s, tab, "\"scheduled_at\": \"%s\",\n", task->unix_queue_time);
	if (task->unix_start_time != 0)
		ss_json_iso8601(s, tab, "\"started_at\": \"%s\",\n", task->unix_start_time);
	if (task->unix_end_time != 0)
		ss_json_iso8601(s, tab, "\"finished_at\": \"%s\",\n", task->unix_end_time);
	if (task->cmd == CMD_SYNC || task->cmd == CMD_SCRUB
		|| task->cmd == CMD_FIX || task->cmd == CMD_CHECK) {
		switch (task->state) {
		case PROCESS_STATE_RUN :
		case PROCESS_STATE_TERM :
		case PROCESS_STATE_SIGNAL :
			ss_jsonf(s, tab, "\"block_begin\": %u,\n", task->block_begin);
			ss_jsonf(s, tab, "\"block_end\": %u,\n", task->block_end);
			ss_jsonf(s, tab, "\"block_count\": %u,\n", task->block_count);
			ss_jsonf(s, tab, "\"progress\": %d,\n", task->progress);
			ss_jsonf(s, tab, "\"speed_mbs\": %u,\n", task->speed_mbs);
			ss_jsonf(s, tab, "\"eta_seconds\": %u,\n", task->eta_seconds);
			ss_jsonf(s, tab, "\"cpu_usage\": %u,\n", task->cpu_usage);
			ss_jsonf(s, tab, "\"elapsed_seconds\": %u,\n", task->elapsed_seconds);
			ss_jsonf(s, tab, "\"block_idx\": %u,\n", task->block_idx);
			ss_jsonf(s, tab, "\"block_done\": %u,\n", task->block_done);
			ss_jsonf(s, tab, "\"size_done_bytes\": %" PRIu64 ",\n", task->size_done);
			break;
		}
	}
	if (task->log_file[0])
		ss_jsonf(s, tab, "\"log_file\": \"%s\",\n", task->log_file);
	ss_jsonf(s, tab, "\"messages\": [\n");
	for (tommy_node* i = tommy_list_head(&task->message_list); i; i = i->next) {
		sn_t* message = i->data;
		++tab;
		ss_jsonf(s, tab, "\"%s\"%s\n", json_esc(message->str, esc_buf), i->next ? "," : "");
		--tab;
	}
	ss_jsonf(s, tab, "],\n");

	switch (task->cmd) {
	case CMD_SYNC :
	case CMD_SCRUB :
		ss_jsonf(s, tab, "\"error_io\": %" PRIi64 ",\n", task->error_io);
		ss_jsonf(s, tab, "\"error_data\": %" PRIi64 ",\n", task->error_data);
		break;
	case CMD_STATUS :
		ss_jsonf(s, tab, "\"block_bad\": %" PRIi64 ",\n", task->block_bad);
		break;
	}
	ss_jsonf(s, tab, "\"errors\": [\n");
	for (tommy_node* i = tommy_list_head(&task->error_list); i; i = i->next) {
		sn_t* error = i->data;
		++tab;
		ss_jsonf(s, tab, "\"%s\"%s\n", json_esc(error->str, esc_buf), i->next ? "," : "");
		--tab;
	}
	ss_jsonf(s, tab, "]\n");
	--tab;
	ss_jsonf(s, tab, "}%s\n", next);
}

/**
 * GET /api/v1/progress
 */
static int handler_progress(struct mg_connection* conn, void* cbdata)
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	int tab = 0;
	ss_t s;

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	struct snapraid_task* task = state->runner.latest;
	if (!task)
		return send_json_error(conn, 204, "No task");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	json_task(&s, tab, task, "");

	state_unlock();

	send_json_answer(conn, &s);

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
	int tab = 0;
	ss_t s;

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_jsonf(&s, tab, "[\n");
	for (tommy_node* i = tommy_list_head(&state->runner.waiting_list); i; i = i->next) {
		struct snapraid_task* task = i->data;
		++tab;
		json_task(&s, tab, task, i->next ? "," : "");
		--tab;
	}

	ss_jsonf(&s, tab, "]\n");

	state_unlock();

	send_json_answer(conn, &s);

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
	int tab = 0;
	ss_t s;

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_jsonf(&s, tab, "[\n");
	for (tommy_node* i = tommy_list_head(&state->runner.history_list); i; i = i->next) {
		struct snapraid_task* task = i->data;

		++tab;
		json_task(&s, tab, task, i->next ? "," : "");
		--tab;
	}

	ss_jsonf(&s, tab, "]\n");

	state_unlock();

	send_json_answer(conn, &s);

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
	int tab = 0;
	ss_t s;

	if (strcmp(ri->request_method, "GET") != 0)
		return send_json_error(conn, 405, "Only GET is allowed for this endpoint");

	ss_init(&s, JSON_INITIAL_SIZE);

	state_lock();

	ss_jsons(&s, tab, "{\n");
	++tab;
	ss_jsonf(&s, tab, "\"daemon_version\": \"%s\"\n", PACKAGE_VERSION);
	if (*global->version) {
		ss_jsonf(&s, tab, "\"engine_version\": \"%s\",\n", global->version);
		ss_jsonf(&s, tab, "\"health\": \"%s\",\n", health_name(health_array(state)));
		ss_jsonf(&s, tab, "\"conf\": \"%s\",\n", global->conf);
		ss_jsonf(&s, tab, "\"block_size_bytes\": %d,\n", global->blocksize);
		if (*global->content)
			ss_jsonf(&s, tab, "\"content\": \"%s\",\n", global->content);
		if (global->last_time)
			ss_json_iso8601(&s, tab, "\"last_command_at\": \"%s\",\n", global->last_time);
		if (*global->last_cmd)
			ss_jsonf(&s, tab, "\"last_cmd\": \"%s\",\n", global->last_cmd);
		if (global->diff_time)
			ss_json_iso8601(&s, tab, "\"last_diff_at\": \"%s\",\n", global->diff_time);
		if (global->status_time)
			ss_json_iso8601(&s, tab, "\"last_status_at\": \"%s\",\n", global->status_time);
		if (global->sync_time)
			ss_json_iso8601(&s, tab, "\"last_sync_at\": \"%s\",\n", global->sync_time);
		if (global->scrub_time)
			ss_json_iso8601(&s, tab, "\"last_scrub_at\": \"%s\",\n", global->scrub_time);
		if (global->afr != 0)
			ss_jsonf(&s, tab, "\"annual_failure_rate\": %g,\n", global->afr);
		if (global->prob != 0)
			ss_jsonf(&s, tab, "\"failure_probability\": %g,\n", global->prob);
		ss_jsonf(&s, tab, "\"file_total\": %" PRIu64 ",\n", global->file_total);
		ss_jsonf(&s, tab, "\"block_bad\": %" PRIu64 ",\n", global->block_bad);
		ss_jsonf(&s, tab, "\"block_rehash\": %" PRIu64 ",\n", global->block_rehash);
		ss_jsonf(&s, tab, "\"block_total\": %" PRIu64 ",\n", global->block_total);
		ss_jsonf(&s, tab, "\"diff_equal\": %" PRIu64 ",\n", global->diff_equal);
		ss_jsonf(&s, tab, "\"diff_added\": %" PRIu64 ",\n", global->diff_added);
		ss_jsonf(&s, tab, "\"diff_removed\": %" PRIu64 ",\n", global->diff_removed);
		ss_jsonf(&s, tab, "\"diff_updated\": %" PRIu64 ",\n", global->diff_updated);
		ss_jsonf(&s, tab, "\"diff_moved\": %" PRIu64 ",\n", global->diff_moved);
		ss_jsonf(&s, tab, "\"diff_copied\": %" PRIu64 ",\n", global->diff_copied);
		ss_jsonf(&s, tab, "\"diff_restored\": %" PRIu64 ",\n", global->diff_restored);
	} else {
		ss_jsonf(&s, tab, "\"health\": \"%s\",\n", health_name(HEALTH_PENDING));
	}
	--tab;
	ss_jsonf(&s, tab, "}\n");

	state_unlock();

	send_json_answer(conn, &s);

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
	mg_set_request_handler(state->rest_context, "/api/v1/stop", handler_stop, state);
	mg_set_request_handler(state->rest_context, "/api/v1/disks", handler_disks, state);
	mg_set_request_handler(state->rest_context, "/api/v1/progress", handler_progress, state);
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

