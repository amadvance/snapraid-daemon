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
#include "log.h"
#include "daemon.h"
#include "runner.h"

/**
 * Check if the passed name is a parity
 * Split parities are NOT recognized.
 */
static int is_parity(const char* s)
{
	if (isdigit((unsigned char)s[0]) && s[1] == '-')
		s += 2;

	return strcmp(s, "parity") == 0;
}

/**
 * Check if the passed name is a parity, and extract the split index
 * The name is truncated to remove the split index.
 */
static int is_split_parity(char* s, int* index)
{
	if (isdigit((unsigned char)s[0]) && s[1] == '-')
		s += 2;

	if (strncmp(s, "parity", 6) != 0)
		return 0;

	s += 6;

	if (s[0] == 0) {
		*index = 0;
		return 1;
	}

	if (s[0] == '/') {
		*s = 0;
		if (strint(index, s + 1) == 0)
			return 1;
	}

	return 0;
}

static struct snapraid_data* find_data(tommy_list* list, const char* name)
{
	struct snapraid_data* data;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		data = i->data;
		if (strcmp(name, data->name) == 0)
			return data;
		i = i->next;
	}

	data = calloc_nofail(1, sizeof(struct snapraid_data));
	data->content_size = SMART_UNASSIGNED;
	data->content_free = SMART_UNASSIGNED;
	sncpy(data->name, sizeof(data->name), name);
	tommy_list_insert_tail(list, &data->node, data);

	return data;
}

static struct snapraid_parity* find_parity(tommy_list* list, const char* name)
{
	struct snapraid_parity* parity;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		parity = i->data;
		if (strcmp(name, parity->name) == 0)
			return parity;
		i = i->next;
	}

	parity = calloc_nofail(1, sizeof(struct snapraid_parity));
	parity->content_size = SMART_UNASSIGNED;
	parity->content_free = SMART_UNASSIGNED;
	sncpy(parity->name, sizeof(parity->name), name);
	tommy_list_insert_tail(list, &parity->node, parity);

	return parity;
}

static struct snapraid_split* find_split(tommy_list* list, int index)
{
	struct snapraid_split* split;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		split = i->data;
		if (index == split->index)
			return split;
		i = i->next;
	}

	split = calloc_nofail(1, sizeof(struct snapraid_split));
	split->index = index;
	tommy_list_insert_tail(list, &split->node, split);

	return split;
}

static struct snapraid_device* find_device_from_file(tommy_list* list, const char* file)
{
	struct snapraid_device* device;
	tommy_node* i;
	int j;

	i = tommy_list_head(list);
	while (i) {
		device = i->data;
		if (strcmp(file, device->file) == 0)
			return device;
		i = i->next;
	}

	device = calloc_nofail(1, sizeof(struct snapraid_device));
	for (j = 0; j < SMART_COUNT; ++j)
		device->smart[j] = SMART_UNASSIGNED;
	device->error = SMART_UNASSIGNED;
	device->size = SMART_UNASSIGNED;
	device->rotational = SMART_UNASSIGNED;
	device->error = SMART_UNASSIGNED;
	device->flags = SMART_UNASSIGNED;
	device->power = POWER_PENDING;
	device->health = HEALTH_PENDING;
	sncpy(device->file, sizeof(device->file), file);
	tommy_list_insert_tail(list, &device->node, device);

	return device;
}

static struct snapraid_device* find_device(struct snapraid_state* state, char* name, const char* file)
{
	int index;

	if (is_split_parity(name, &index)) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, name);
		struct snapraid_split* split = find_split(&parity->split_list, index);
		return find_device_from_file(&split->device_list, file);
	} else {
		struct snapraid_data* data = find_data(&state->data_list, name);
		return find_device_from_file(&data->device_list, file);
	}
}

static void process_stat(struct snapraid_state* state, char** map, size_t mac)
{
	uint64_t access_count;

	if (mac < 3)
		return;

	if (stru64(&access_count, map[2]) != 0)
		return;

	if (is_parity(map[1])) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (parity->access_count != access_count) {
			parity->access_count = access_count;
			parity->access_count_initial_time = state->global.last_time;
		}
		parity->access_count_latest_time = state->global.last_time;
	} else {
		struct snapraid_data* data = find_data(&state->data_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (data->access_count != access_count) {
			data->access_count = access_count;
			data->access_count_initial_time = state->global.last_time;
		}
		data->access_count_latest_time = state->global.last_time;
	}
}

static void process_data(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_data* data;

	if (mac < 4)
		return;

	data = find_data(&state->data_list, map[1]);

	sncpy(data->dir, sizeof(data->dir), map[2]);
	sncpy(data->uuid, sizeof(data->uuid), map[3]);
}

static void process_content_data(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_data* data;

	if (mac < 3)
		return;

	data = find_data(&state->data_list, map[1]);

	sncpy(data->content_uuid, sizeof(data->content_uuid), map[2]);
}

static void process_parity(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_parity* parity;
	struct snapraid_split* split;
	int index;

	if (mac < 3)
		return;
	if (!is_split_parity(map[0], &index))
		return;

	parity = find_parity(&state->parity_list, map[0]);
	split = find_split(&parity->split_list, index);

	sncpy(split->path, sizeof(split->path), map[1]);
	sncpy(split->uuid, sizeof(split->uuid), map[2]);
}

static void process_content_parity(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_parity* parity;
	struct snapraid_split* split;
	int index;

	if (mac < 4)
		return;
	if (!is_split_parity(map[0], &index))
		return;

	parity = find_parity(&state->parity_list, map[0]);
	split = find_split(&parity->split_list, index);

	sncpy(split->content_uuid, sizeof(split->content_uuid), map[1]);
	sncpy(split->content_path, sizeof(split->content_path), map[2]);
	stru64(&split->content_size, map[3]);
}

static void process_content_allocation(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	if (is_parity(map[0])) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[0]);
		stru64(&parity->content_size, map[1]);
		stru64(&parity->content_free, map[2]);
	} else {
		struct snapraid_data* data = find_data(&state->data_list, map[0]);
		stru64(&data->content_size, map[1]);
		stru64(&data->content_free, map[2]);
	}
}

static void process_attr(struct snapraid_state* state, char** map, size_t mac)
{
	const char* tag;
	const char* val;
	struct snapraid_device* device;

	if (mac < 5)
		return;
	if (map[2][0] == 0) /* ignore if no disk name is provided */
		return;

	device = find_device(state, map[2], map[1]);

	tag = map[3];
	val = map[4];

	if (strcmp(tag, "serial") == 0)
		sncpy(device->serial, sizeof(device->serial), val);
	else if (strcmp(tag, "model") == 0)
		sncpy(device->model, sizeof(device->model), val);
	else if (strcmp(tag, "family") == 0)
		sncpy(device->family, sizeof(device->family), val);
	else if (strcmp(tag, "size") == 0)
		stru64(&device->size, val);
	else if (strcmp(tag, "rotationrate") == 0)
		stru64(&device->rotational, val);
//	else if (strcmp(tag, "afr") == 0) // TODO
	//device->info[ROTATION_RATE] = si64(val);
	else if (strcmp(tag, "error") == 0)
		stru64(&device->error, val);
	else if (strcmp(tag, "power") == 0) {
		device->power = POWER_PENDING;
		if (strcmp(val, "standby") == 0 || strcmp(val, "down") == 0)
			device->power = POWER_STANDBY;
		else if (strcmp(val, "active") == 0 || strcmp(val, "up") == 0)
			device->power = POWER_ACTIVE;
	} else if (strcmp(tag, "flags") == 0) {
		device->health = HEALTH_PENDING;
		if (stru64(&device->flags, val) == 0) {
			if (device->flags & (SMARTCTL_FLAG_FAIL | SMARTCTL_FLAG_PREFAIL))
				device->health = HEALTH_FAILING;
			else
				device->health = HEALTH_PASSED;
		}
	} else {
		int index;
		if (strint(&index, tag) == 0) {
			if (index >= 0 && index < 256)
				stru64(&device->smart[index], val);
		}
	}
}

static void process_run(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 2)
		return;

	if (strcmp(map[1], "begin") == 0) {
		if (mac < 5)
			return;

		/* keep the state as starting */
		struint(&task->block_begin, map[2]);
		struint(&task->block_end, map[3]);
		struint(&task->block_count, map[4]);
	} else if (strcmp(map[1], "pos") == 0) {
		if (mac < 10)
			return;

		task->state = PROCESS_STATE_RUN;
		struint(&task->block_idx, map[2]);
		struint(&task->block_done, map[3]);
		stru64(&task->size_done, map[4]);
		struint(&task->progress, map[5]);
		struint(&task->eta_seconds, map[6]);
		struint(&task->speed_mbs, map[7]);
		struint(&task->cpu_usage, map[8]);
		struint(&task->elapsed_seconds, map[9]);
	} else if (strcmp(map[1], "end") == 0) {
		/* if interrupting, ignore the end, and it's reported anyway */
		if (task->state != PROCESS_STATE_SIGNAL) {
			task->state = PROCESS_STATE_TERM;
			task->progress = 100;
			task->eta_seconds = 0;
			task->speed_mbs = 0;
			task->cpu_usage = 0;
		}
	}
}

static void process_sigint(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 2)
		return;

	task->state = PROCESS_STATE_SIGNAL;
	struint(&task->block_idx, map[1]);
}

static void process_msg(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	if (strcmp(map[1], "progress") == 0 || strcmp(map[1], "status") == 0) {
		const char* msg = map[2];

		/* skip initial spaces */
		while (*msg != 0 && isspace((unsigned char)*msg))
			++msg;

		sl_insert_str(&task->message_list, msg);
	}
}

static void process_error(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 5) /* error:<block>:<disk_name>:<file>:<msg> */
		return;

	msg = map[4]; /* error message is the last field */

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	sl_insert_str(&task->error_list, msg);

	if (strcmp(map[0], "error_io") == 0) {
		struct snapraid_data* data = find_data(&state->data_list, map[2]);
		++data->error_io;
	} else if (strcmp(map[0], "error_data") == 0) {
		struct snapraid_data* data = find_data(&state->data_list, map[2]);
		++data->error_data;
	}
}

static void process_parity_error(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 4) /* parity_error:<block>:<level>:<msg> */
		return;

	msg = map[3]; /* error message is the last field */

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	sl_insert_str(&task->error_list, msg);

	if (strcmp(map[0], "parity_error_io") == 0) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[2]);
		++parity->error_io;
	} else if (strcmp(map[0], "parity_error_data") == 0) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[2]);
		++parity->error_data;
	}
}

static void process_hardlink_error(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 5) /* hardlink_error:<disk_name>:<link_path>:<target_path>:<msg> */
		return;

	msg = map[4]; /* error message is the last field */

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	sl_insert_str(&task->error_list, msg);
}

static void process_symlink_error(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 4) /* symlink_error:<disk_name>:<link_path>:<msg> */
		return;

	msg = map[3]; /* error message is the last field */

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	sl_insert_str(&task->error_list, msg);
}

static void process_dir_error(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 4) /* dir_error:<disk_name>:<dir_path>:<msg> */
		return;

	msg = map[3]; /* error message is the last field */

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	sl_insert_str(&task->error_list, msg);
}

static void process_outofparity(struct snapraid_state* state, char** map __attribute__((unused)), size_t mac __attribute__((unused)))
{
	struct snapraid_task* task = state->runner.latest;
	const char* msg;

	if (!task)
		return;
	if (mac < 3) /* outofparity:<disk_name>:<file_path> */
		return;

	/* For outofparity, we create a meaningful error message */
	msg = "File extends beyond available parity space";

	sl_insert_str(&task->error_list, msg);
}

static void process_conf(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	if (strcmp(map[1], "file") == 0)
		sncpy(state->global.conf, sizeof(state->global.conf), map[2]);
}

static void process_content(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	sncpy(state->global.content, sizeof(state->global.content), map[1]);
}

static void process_version(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int major;
	int minor;

	if (mac < 2)
		return;

	s = map[1];

	/* full version text */
	sncpy(state->global.version, sizeof(state->global.version), s);

	/* parse major */
	if (!isdigit((unsigned char)*s))
		return;

	major = strtol(s, &e, 10);
	if (e == s || *e != '.')
		return;

	s = e + 1;

	/* parse minor */
	if (!isdigit((unsigned char)*s))
		return;

	minor = strtol(s, &e, 10);

	/* anything after minor is ignored */
	state->global.version_major = major;
	state->global.version_minor = minor;
}

static void process_blocksize(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int blocksize;

	if (mac < 2)
		return;

	s = map[1];

	if (!isdigit((unsigned char)*s))
		return;

	blocksize = strtol(s, &e, 10);
	if (e == s || *e != 0)
		return;

	state->global.blocksize = blocksize;
}

static void process_unixtime(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int64_t last_time;

	if (mac < 2)
		return;

	s = map[1];

	if (!isdigit((unsigned char)*s))
		return;

	last_time = strtoll(s, &e, 10);
	if (e == s || *e != 0)
		return;

	state->global.last_time = last_time;
}

static void process_command(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	sncpy(state->global.last_cmd, sizeof(state->global.last_cmd), map[1]);
}

static void process_hash_summary(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	if (strcmp(map[1], "error_file") == 0) {
		stru64(&task->hash_error_alert, map[2]);
	}
}

static void process_summary(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	if (strcmp(map[1], "equal") == 0)
		stru64(&state->global.diff_equal, map[2]);
	else if (strcmp(map[1], "added") == 0)
		stru64(&state->global.diff_added, map[2]);
	else if (strcmp(map[1], "removed") == 0)
		stru64(&state->global.diff_removed, map[2]);
	else if (strcmp(map[1], "updated") == 0)
		stru64(&state->global.diff_updated, map[2]);
	else if (strcmp(map[1], "moved") == 0)
		stru64(&state->global.diff_moved, map[2]);
	else if (strcmp(map[1], "copied") == 0)
		stru64(&state->global.diff_copied, map[2]);
	else if (strcmp(map[1], "restored") == 0)
		stru64(&state->global.diff_restored, map[2]);
	else if (strcmp(map[1], "error_file") == 0)
		stru64(&task->error_alert, map[2]);
	else if (strcmp(map[1], "error_io") == 0)
		stru64(&task->error_io, map[2]);
	else if (strcmp(map[1], "error_data") == 0)
		stru64(&task->error_data, map[2]);
	else if (strcmp(map[1], "exit") == 0) {
		/* copy exit status */
		if (mac >= 3)
			sncpy(task->exit, sizeof(task->exit), map[2]);
		/* set the time, only if we complete the command */
		if (strcmp(state->global.last_cmd, "sync") == 0)
			state->global.sync_time = state->global.last_time;
		if (strcmp(state->global.last_cmd, "scrub") == 0)
			state->global.scrub_time = state->global.last_time;
		if (strcmp(state->global.last_cmd, "diff") == 0)
			state->global.diff_time = state->global.last_time;
	}
}

static void process_line(struct snapraid_state* state, char** map, size_t mac)
{
	const char* cmd;

	if (mac == 0)
		return;

	cmd = map[0];

	if (strcmp(cmd, "data") == 0) {
		state_lock();
		process_data(state, map, mac);
		state_unlock();
	} else if (is_parity(cmd)) {
		state_lock();
		process_parity(state, map, mac);
		state_unlock();
//	} else if (strcmp(cmd, "device") == 0) { // TODO
		//process_device(state, map, mac);
	} else if (strcmp(cmd, "attr") == 0) {
		state_lock();
		process_attr(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "run") == 0) {
		state_lock();
		process_run(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "sigint") == 0) {
		state_lock();
		process_sigint(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "msg") == 0) {
		state_lock();
		process_msg(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "stat") == 0) {
		state_lock();
		process_stat(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "command") == 0) {
		state_lock();
		process_command(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "conf") == 0) {
		state_lock();
		process_conf(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content") == 0) {
		state_lock();
		process_content(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "version") == 0) {
		state_lock();
		process_version(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "blocksize") == 0) {
		state_lock();
		process_blocksize(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "unixtime") == 0) {
		state_lock();
		process_unixtime(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content_disk") == 0) {
		state_lock();
		process_content_data(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content_parity") == 0) {
		state_lock();
		process_content_parity(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content_allocation") == 0) {
		state_lock();
		process_content_allocation(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "hash_summary") == 0) {
		state_lock();
		process_hash_summary(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "summary") == 0) {
		state_lock();
		process_summary(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "error") == 0 || strcmp(cmd, "error_io") == 0 || strcmp(cmd, "error_data") == 0) {
		state_lock();
		process_error(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "parity_error") == 0 || strcmp(cmd, "parity_error_io") == 0 || strcmp(cmd, "parity_error_data") == 0) {
		state_lock();
		process_parity_error(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "hardlink_error") == 0) {
		state_lock();
		process_hardlink_error(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "symlink_error") == 0) {
		state_lock();
		process_symlink_error(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "dir_error") == 0) {
		state_lock();
		process_dir_error(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "outofparity") == 0) {
		state_lock();
		process_outofparity(state, map, mac);
		state_unlock();
	}
}

#define RUN_INPUT_MAX 4096
#define RUN_FIELD_MAX 64

void parse_log(struct snapraid_state* state, int f, const char* cat_log_path)
{
	char buf[RUN_INPUT_MAX];
	char line[RUN_INPUT_MAX];
	char* map[RUN_FIELD_MAX];
	size_t len = 0;
	size_t mac = 0;
	int escape = 0;
	FILE* log_f = 0;

	if (cat_log_path[0] != 0) {
		log_f = fopen(cat_log_path, "wte");
		if (log_f == 0) {
			log_msg(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", cat_log_path, strerror(errno), errno);
		}
	}

	map[mac++] = line;

	while (1) {
		ssize_t n = read(f, buf, sizeof(buf));
		if (n > 0) {
			ssize_t i;

			if (log_f) {
				if (fwrite(buf, n, 1, log_f) != 1) {
					log_msg(LVL_WARNING, "failed to write log file %s, errno=%s(%d)", cat_log_path, strerror(errno), errno);
				}
			}

			for (i = 0; i < n; i++) {
				char c = buf[i];

				if (escape) {
					if (len + 1 < RUN_INPUT_MAX) { /* ignore if too long */
						switch (c) {
						case '\\' : line[len++] = '\\'; break;
						case 'n' :  line[len++] = '\n'; break;
						case 'd' : line[len++] = ':'; break;
						default : /* ignore if unknown */
						}
					}
					escape = 0;
					continue;
				}

				if (c == '\\') {
					escape = 1;
					continue;
				}

				if (c == ':') {
					if (mac + 1 < RUN_FIELD_MAX) {
						line[len++] = '\0';
						map[mac++] = &line[len];
						continue;
					}
					/* do not split if too many fields */
				}

				if (c == '\n') {
					line[len] = '\0';
					map[mac] = 0;

					process_line(state, map, mac);

					len = 0;
					mac = 0;
					escape = 0;
					map[mac++] = line;
					continue;
				}

				if (len + 1 < RUN_INPUT_MAX) /* ignore if too long */
					line[len++] = c;
			}
		} else if (n == 0) {
			/* EOF, discard partial read not ending with \n */
			break;
		} else { /* n < 0 */
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}
	}


	if (log_f) {
		if (fclose(log_f) != 0) {
			log_msg(LVL_WARNING, "failed to close log file %s, errno=%s(%d)", cat_log_path, strerror(errno), errno);
		}
	}
}
