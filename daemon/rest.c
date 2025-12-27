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
#include "rest.h"

#define JSMN_STRICT
#include "../jsmn/jsmn.h"

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

int json_pair(const char* js, jsmntok_t* jt, const char* field, unsigned type)
{
	int len = strlen(field);

	if (jt[0].type != JSMN_STRING
		|| len != jt[0].end - jt[0].start
		|| strncmp(js + jt[0].start, field, len) != 0)
		return -1;

	if (jt[0].size != 1
		|| jt[1].type != type)
		return -1;

	return 0;
}

/**
 * POST /api/v1/sync, /api/v1/probe, /api/v1/up, /api/v1/down, /api/v1/smart 
 */
static int handler_action(struct mg_connection* conn, void* cbdata) 
{
	struct snapraid_state* state = cbdata;
	const struct mg_request_info* ri = mg_get_request_info(conn);
	const char* path = ri->local_uri;
	ssize_t content_length = ri->content_length;
	ssize_t jl;
	int ret;
	jsmntok_t jt[JSMN_TOKEN_MAX];
	jsmn_parser jp;
	char* js;
	int jc;
	char* argv[RUNNER_ARG_MAX];
	int argc;

	if (strcmp(ri->request_method, "POST") != 0)
		return send_json_error(conn, 405, "Only POST is allowed for this endpoint");
	if (content_length < 0) 
		return send_json_error(conn, 400, "Invalid content length");

	js = malloc_nofail(content_length);

	jl = 0;
	while (jl < content_length) {
		int r = mg_read(conn, js + jl, (size_t)(content_length - jl));
		if (r <= 0)
			break;
		jl += r;
	}

	argc = 0;
	jsmn_init(&jp);
	jc = jsmn_parse(&jp, js, jl, jt, JSMN_TOKEN_MAX);
	if (jc < 0)
		goto bad;
	if (jc != 0) { /* accept an empty request */
		int c0;
		int j = 0;
		if (jt[j].type != JSMN_OBJECT)
			goto bad;
		c0 = jt[j++].size;
		while (c0-- > 0) {
			if (json_pair(js, &jt[j], "args", JSMN_ARRAY) == 0) {
				int c1 = jt[++j].size;
				++j;
				while (c1-- > 0) {
					if (jt[j].type != JSMN_STRING)
						goto bad;
					js[jt[j].end] = 0;
					argv[argc++] = &js[jt[j].start];
					if (argc >= RUNNER_ARG_MAX)
						goto bad;
					++j;
				}
			} else 
				goto bad;
		}
	}
	argv[argc] = 0;

	if (strcmp(path, "/api/v1/sync") == 0)
		ret = runner(state, CMD_SYNC, argc, argv);
	else if (strcmp(path, "/api/v1/probe") == 0)
		ret = runner(state, CMD_PROBE, argc, argv);
	else if (strcmp(path, "/api/v1/up") == 0)
		ret = runner(state, CMD_UP, argc, argv);
	else if (strcmp(path, "/api/v1/down") == 0)
		ret = runner(state, CMD_DOWN, argc, argv);
	else if (strcmp(path, "/api/v1/smart") == 0)
		ret = runner(state, CMD_SMART, argc, argv);
	else
		ret = 404;

	free(js);

	switch (ret) {
	case 409 : return send_json_error(conn, 409, "A SnapRAID command is already running");
	case 503 : return send_json_error(conn, 503, "Impossible to start a SnapRAID command");
	case 404 : return send_json_error(conn, 404, "Resource not found");
	}

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

	ss_init(&s);

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

	ss_init(&s);

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
	for (i = 0; i < 1; i++) { // Dummy loop for TaskError items
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

void rest_init(struct snapraid_state* state, const char** options)
{
	memset(&state->rest_callbacks, 0, sizeof(state->rest_callbacks));
	
	state->rest_context = mg_start(&state->rest_callbacks, state, options);
	if (!state->rest_context) {
		exit(EXIT_FAILURE);
	}

	mg_set_request_handler(state->rest_context, "/api/v1/sync", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/probe", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/up", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/down", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/smart", handler_action, state);
	mg_set_request_handler(state->rest_context, "/api/v1/disks", handler_disks, state);
	mg_set_request_handler(state->rest_context, "/api/v1/progress", handler_progress, state);
	mg_set_request_handler(state->rest_context, "/api", handler_not_found, state);
}

void rest_run(struct snapraid_state* state)
{
	printf("Running...\n");

	while (state->daemon_running)
		sleep(1);
}

void rest_done(struct snapraid_state* state)
{
	mg_stop(state->rest_context);
}

/*
curl -X POST http://localhost:8080/api/v1/sync
curl -X POST http://localhost:8080/api/v1/probe
curl -X POST http://localhost:8080/api/v1/up
curl -X POST http://localhost:8080/api/v1/down
curl -X POST http://localhost:8080/api/v1/smart
curl -X GET http://localhost:8080/api/v1/disks
curl -X GET http://localhost:8080/api/v1/progress
*/
