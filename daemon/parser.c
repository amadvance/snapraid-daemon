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
#include "elem.h"
#include "parser.h"

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

static struct snapraid_disk* find_disk(tommy_list* list, const char* name)
{
	struct snapraid_disk* disk;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		disk = i->data;
		if (strcmp(name, disk->name) == 0)
			return disk;
		i = i->next;
	}

	disk = calloc_nofail(1, sizeof(struct snapraid_disk));
	disk->content_size = SMART_UNASSIGNED;
	disk->content_free = SMART_UNASSIGNED;
	sncpy(disk->name, sizeof(disk->name), name);
	tommy_list_insert_tail(list, &disk->node, disk);

	return disk;
}

int split_compare(const void* void_a, const void* void_b)
{
	const struct snapraid_split* split_a = void_a;
	const struct snapraid_split* split_b = void_b;
	if (split_a->index < split_b->index)
		return -1;
	if (split_a->index > split_b->index)
		return 1;
	return 0;
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

	/* the list must be sorted by index for the JSON output that references the array position */
	tommy_list_sort(list, split_compare);

	return split;
}

static struct snapraid_device* find_device_from_file(tommy_list* list, const char* file, int split_index)
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
	device->error_protocol = SMART_UNASSIGNED;
	device->error_medium = SMART_UNASSIGNED;
	device->wear_level = SMART_UNASSIGNED;
	device->size = SMART_UNASSIGNED;
	device->rotational = SMART_UNASSIGNED;
	device->flags = SMART_UNASSIGNED;
	device->power = POWER_PENDING;
	device->health = HEALTH_PENDING;
	device->split_index = split_index;
	sncpy(device->file, sizeof(device->file), file);
	tommy_list_insert_tail(list, &device->node, device);

	return device;
}

static struct snapraid_device* find_device(struct snapraid_state* state, char* name, const char* file)
{
	int index;

	if (is_split_parity(name, &index)) {
		struct snapraid_disk* parity = find_disk(&state->parity_list, name);
		return find_device_from_file(&parity->device_list, file, index);
	} else {
		struct snapraid_disk* data = find_disk(&state->data_list, name);
		return find_device_from_file(&data->device_list, file, 0); /* at present data disks don't have the split index */
	}
}

/**
 * Clear the error accumulators of all the disks.
 */
static void clear_disk_accumulator(struct snapraid_state* state)
{
	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* data = i->data;
		data->error_io = 0;
		data->error_data = 0;
	}
	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_disk* parity = i->data;
		parity->error_io = 0;
		parity->error_data = 0;
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
		struct snapraid_disk* parity = find_disk(&state->parity_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (parity->access_count != access_count) {
			parity->access_count = access_count;
			parity->access_count_initial_time = state->global.last_time;
		}
		parity->access_count_latest_time = state->global.last_time;
	} else {
		struct snapraid_disk* data = find_disk(&state->data_list, map[1]);
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
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* dir = map[2];
	const char* uuid = map[3];

	struct snapraid_disk* disk = find_disk(&state->data_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, 0); /* at present data disks don't have the split index */

	sncpy(split->path, sizeof(split->path), dir);
	sncpy(split->uuid, sizeof(split->uuid), uuid);
}

static void process_content_data(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	const char* name = map[1];
	const char* uuid = map[2];

	struct snapraid_disk* disk = find_disk(&state->data_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, 0); /* at present data disks don't have the split index */

	sncpy(split->content_uuid, sizeof(split->content_uuid), uuid);
}

static void process_parity(struct snapraid_state* state, char** map, size_t mac)
{
	int index;

	if (mac < 3)
		return;

	char* name = map[0];
	const char* path = map[1];
	const char* uuid = map[2];

	if (!is_split_parity(name, &index))
		return;

	struct snapraid_disk* disk = find_disk(&state->parity_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, index);

	sncpy(split->path, sizeof(split->path), path);
	sncpy(split->uuid, sizeof(split->uuid), uuid);
}

static void process_content_parity(struct snapraid_state* state, char** map, size_t mac)
{
	int index;

	if (mac < 5)
		return;

	char* name = map[1];
	const char* uuid = map[2];
	const char* path = map[3];
	const char* size_alloc = map[4];

	if (!is_split_parity(name, &index))
		return;

	struct snapraid_disk* disk = find_disk(&state->parity_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, index);

	sncpy(split->content_uuid, sizeof(split->content_uuid), uuid);
	sncpy(split->content_path, sizeof(split->content_path), path);
	stru64(&split->content_size, size_alloc);
}

static void process_content_allocation(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];

	if (is_parity(name)) {
		struct snapraid_disk* parity = find_disk(&state->parity_list, name);
		stru64(&parity->content_size, size_alloc);
		stru64(&parity->content_free, size_free);
	} else {
		struct snapraid_disk* data = find_disk(&state->data_list, name);
		stru64(&data->content_size, size_alloc);
		stru64(&data->content_free, size_free);
	}
}

static void process_content_info(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	const char* tag = map[1];
	const char* val = map[2];

	if (strcmp(tag, "file") == 0) {
		stru64(&state->global.file_total, val);
	} else if (strcmp(tag, "block_bad") == 0) {
		uint64_t block_bad;
		if (stru64(&block_bad, val) == 0) {
			if (block_bad == 0) {
				/* if status report has no stored error, clear the disk error accumulators */
				clear_disk_accumulator(state);
			} else {
				task->block_bad = block_bad;
			}
			state->global.block_bad = block_bad;
		}
	} else if (strcmp(tag, "block_rehash") == 0) {
		stru64(&state->global.block_rehash, val);
	} else if (strcmp(tag, "block") == 0) {
		stru64(&state->global.block_total, val);
	}
}

static void process_attr(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 5)
		return;
	if (map[2][0] == 0) /* ignore if no disk name is provided */
		return;

	struct snapraid_device* device = find_device(state, map[2], map[1]);

	const char* tag = map[3];
	const char* val = map[4];

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
	else if (strcmp(tag, "afr") == 0) {
		strdouble(&device->afr, val);
		if (mac >= 6)
			strdouble(&device->prob, map[5]);
	} else if (strcmp(tag, "error_protocol") == 0)
		stru64(&device->error_protocol, val);
	else if (strcmp(tag, "error_medium") == 0)
		stru64(&device->error_medium, val);
	else if (strcmp(tag, "wear_level") == 0)
		stru64(&device->wear_level, val);
	else if (strcmp(tag, "power") == 0) {
		device->power = POWER_PENDING;
		if (strcmp(val, "standby") == 0 || strcmp(val, "down") == 0)
			device->power = POWER_STANDBY;
		else if (strcmp(val, "active") == 0 || strcmp(val, "up") == 0)
			device->power = POWER_ACTIVE;
	} else if (strcmp(tag, "flags") == 0) {
		device->health = HEALTH_PENDING;
		if (stru64(&device->flags, val) == 0) {
			if (device->flags & SMARTCTL_FLAG_FAIL)
				device->health = HEALTH_FAILING;
			else if (device->flags & SMARTCTL_FLAG_PREFAIL)
				device->health = HEALTH_PREFAIL;
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

static void process_scan(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* tag = map[1];
	const char* disk = map[2];
	const char* path = map[3];

	if (strcmp(tag, "add") == 0) {
		struct snapraid_diff* diff = diff_alloc(DIFF_CHANGE_ADD, disk, path);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
	} else if (strcmp(tag, "remove") == 0) {
		struct snapraid_diff* diff = diff_alloc(DIFF_CHANGE_REMOVE, disk, path);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
	} else if (strcmp(tag, "update") == 0) {
		struct snapraid_diff* diff = diff_alloc(DIFF_CHANGE_UPDATE, disk, path);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
	} else if (strcmp(tag, "move") == 0 && mac >= 5) {
		struct snapraid_diff* diff = diff_alloc_source(DIFF_CHANGE_MOVE, disk, path, disk, map[4]);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
	} else if (strcmp(tag, "copy") == 0 && mac >= 6) {
		struct snapraid_diff* diff = diff_alloc_source(DIFF_CHANGE_COPY, disk, path, map[4], map[5]);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
	} else if (strcmp(tag, "restore") == 0) {
		struct snapraid_diff* diff = diff_alloc(DIFF_CHANGE_RESTORE, disk, path);
		tommy_list_insert_tail(&state->global.diff_current.diff_list, &diff->node, diff);
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
		/* if stopping, ignore the end, and it's reported anyway */
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

	/* the task error_io and error_data will be gathered by the final summary tag */

	if (strstr(map[0], "error_io:") != 0) { /* match all [hardlink/symlink/dir/empty]_error_io */
		struct snapraid_disk* data = find_disk(&state->data_list, map[2]);
		++data->error_io;
	} else if (strcmp(map[0], "error_data") == 0) {
		struct snapraid_disk* data = find_disk(&state->data_list, map[2]);
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
		struct snapraid_disk* parity = find_disk(&state->parity_list, map[2]);
		++parity->error_io;
	} else if (strcmp(map[0], "parity_error_data") == 0) {
		struct snapraid_disk* parity = find_disk(&state->parity_list, map[2]);
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
		sncpy(state->global.conf_engine, sizeof(state->global.conf_engine), map[2]);
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
	if (mac < 2)
		return;

	struint(&state->global.blocksize, map[1]);
}

static void process_unixtime(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	if (stri64(&state->global.last_time, map[1]) != 0)
		return;
}

static void process_command(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	sncpy(state->global.last_cmd, sizeof(state->global.last_cmd), map[1]);
}

static void process_daemon(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	const char* tag = map[1];
	const char* val = map[2];

	if (strcmp(tag, "start") == 0) {
		stri64(&task->unix_start_time, val);
	} else if (strcmp(tag, "end") == 0) {
		stri64(&task->unix_end_time, val);
	} else if (strcmp(tag, "scheduled") == 0) {
		stri64(&task->unix_queue_time, val);
	} else if (strcmp(tag, "command") == 0) {
		task->cmd = command_parse(val);
	} else if (strcmp(tag, "term") == 0) {
		task->state = PROCESS_STATE_TERM;
		strint(&task->exit_code, val);
	} else if (strcmp(tag, "signal") == 0) {
		task->state = PROCESS_STATE_SIGNAL;
		strint(&task->exit_sig, val);
	}
}

static void process_hash_summary(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	if (strcmp(map[1], "error_file") == 0) {
		stru64(&task->hash_error_soft, map[2]);
	}
}

static void process_summary(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	const char* tag = map[1];
	const char* val = map[2];

	/* diff */
	if (task->cmd == CMD_DIFF) {
		if (strcmp(tag, "equal") == 0)
			stri64(&state->global.diff_current.diff_equal, val);
		else if (strcmp(tag, "added") == 0)
			stri64(&state->global.diff_current.diff_added, val);
		else if (strcmp(tag, "removed") == 0)
			stri64(&state->global.diff_current.diff_removed, val);
		else if (strcmp(tag, "updated") == 0)
			stri64(&state->global.diff_current.diff_updated, val);
		else if (strcmp(tag, "moved") == 0)
			stri64(&state->global.diff_current.diff_moved, val);
		else if (strcmp(tag, "copied") == 0)
			stri64(&state->global.diff_current.diff_copied, val);
		else if (strcmp(tag, "restored") == 0)
			stri64(&state->global.diff_current.diff_restored, val);
	}

	if (strcmp(tag, "error_file") == 0)
		stru64(&task->error_soft, val);
	else if (strcmp(tag, "error_io") == 0)
		stru64(&task->error_io, val);
	else if (strcmp(tag, "error_data") == 0)
		stru64(&task->error_data, val);
	else if (strcmp(tag, "exit") == 0) {
		/* set the time, only if we complete the command */
		switch (task->cmd) {
		case CMD_SYNC :
			state->global.sync_time = state->global.last_time;
			break;
		case CMD_SCRUB :
			state->global.scrub_time = state->global.last_time;
			break;
		case CMD_DIFF :
			state->global.diff_time = state->global.last_time;
			break;
		case CMD_STATUS :
			state->global.status_time = state->global.last_time;
			break;
		}
	} else if (strcmp(tag, "array_failure") == 0) {
		strdouble(&state->global.afr, val);
		if (mac >= 4)
			strdouble(&state->global.prob, map[3]);
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
	} else if (strcmp(cmd, "scan") == 0) {
		state_lock();
		process_scan(state, map, mac);
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
	} else if (strcmp(cmd, "content_data") == 0) {
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
	} else if (strcmp(cmd, "content_info") == 0) {
		state_lock();
		process_content_info(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "hash_summary") == 0) {
		state_lock();
		process_hash_summary(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "summary") == 0) {
		state_lock();
		process_summary(state, map, mac);
		state_unlock();
	} else if (
		strcmp(cmd, "error") == 0 || strcmp(cmd, "error_io") == 0 || strcmp(cmd, "error_data") == 0
		|| strcmp(cmd, "hardlink_error") == 0 || strcmp(cmd, "hardlink_error_io") == 0
		|| strcmp(cmd, "symlink_error") == 0 || strcmp(cmd, "symlink_error_io") == 0
		|| strcmp(cmd, "dir_error") == 0 || strcmp(cmd, "dir_error_io") == 0
		|| strcmp(cmd, "empty_error") == 0 || strcmp(cmd, "empty_error_io") == 0
	) {
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
	} else if (strcmp(cmd, "daemon") == 0) {
		state_lock();
		process_daemon(state, map, mac);
		state_unlock();
	}
}

#define RUN_INPUT_MAX 4096
#define RUN_FIELD_MAX 64

void parse_log(struct snapraid_state* state, int f, FILE* log_f, const char* log_path)
{
	char buf[RUN_INPUT_MAX];
	char line[RUN_INPUT_MAX];
	char* map[RUN_FIELD_MAX];
	size_t len = 0;
	size_t mac = 0;
	int escape = 0;

	map[mac++] = line;

	while (1) {
		ssize_t n = read(f, buf, sizeof(buf));
		if (n > 0) {
			ssize_t i;

			if (log_f) {
				if (fwrite(buf, n, 1, log_f) != 1) {
					log_msg(LVL_WARNING, "failed to write log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
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
}

int parse_timestamp(const char *name, int64_t* out)
{
	int Y, M, D, h, m, s;
	char dash;

	/* expect: YYYYMMDD-HHMMSS-* */
	if (sscanf(name, "%4d%2d%2d-%2d%2d%2d%c", &Y, &M, &D, &h, &m, &s, &dash) != 7)
		return -1;

	if (dash != '-')
		return -1;

	/* basic range checks */
	if (Y < 1970
		|| M < 1 || M > 12
		|| D < 1 || D > 31
		|| h < 0 || h > 23
		|| m < 0 || m > 59
		|| s < 0 || s > 59) /* in POSIX and Windows s is never 60, even for leap seconds */
		return -1;

	struct tm tm = { 0 };
	tm.tm_year = Y - 1900;
	tm.tm_mon = M - 1;
	tm.tm_mday = D;
	tm.tm_hour = h;
	tm.tm_min = m;
	tm.tm_sec = s;

	/* force local time interpretation, let libc resolve DST */
	tm.tm_isdst = -1;

	*out = mktime(&tm);

	if (*out == -1)
		return -1;

	return 0;
}

int parse_past_log(struct snapraid_state* state)
{
	char* log_directory = state->config.log_directory;
	int64_t log_retention_days = state->config.log_retention_days;
	sl_t log_list;

	if (*log_directory == 0)
		return 0;

	DIR* dir = opendir(log_directory);
	if (!dir) {
		log_msg(LVL_WARNING, "failed to open log directory %s, errno=%s(%d)", log_directory, strerror(errno), errno);
		return -1;
	}

	/* read only no more than 30 days of logs */
	if (log_retention_days == 0)
		log_retention_days = HISTORY_PAST_DAYS;
	else if (log_retention_days > HISTORY_PAST_DAYS)
		log_retention_days = HISTORY_PAST_DAYS;

	int count = 0;
	int64_t now = time(0);
	int64_t cutoff_seconds = now - log_retention_days * SECONDS_IN_A_DAY;

	sl_init(&log_list);
	struct dirent *ent;
	while ((ent = readdir(dir)) != 0) {
		if (ent->d_name[0] == '.')
			continue;
		if (ent->d_type != DT_REG)
			continue;

		/* only files matching the pattern */
		int64_t ntime;
		if (parse_timestamp(ent->d_name, &ntime) != 0)
			continue;

		/* only files that are recent enough */
		if (ntime < cutoff_seconds)
			continue;

		sl_insert_str(&log_list, ent->d_name);
	}

	closedir(dir);

	/* sort alphabetically */
	tommy_list_sort(&log_list, sl_compare);

	/* read them all */
	for (tommy_node* i = tommy_list_head(&log_list); i; i = i->next) {
		char path[PATH_MAX];
		sn_t* sn = i->data;

		snprintf(path, sizeof(path), "%s/%s", log_directory, sn->str);

		int f = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (f == -1) {
			log_msg(LVL_WARNING, "failed to open log file %s, errno=%s(%d)", log_directory, strerror(errno), errno);
			continue;
		}

		/* setup a task */
		struct snapraid_task* task = task_alloc();
		task->number = ++state->runner.number_allocator;
		state->runner.latest = task;

		parse_log(state, f, 0, 0);
		++count;

		if (task->state != PROCESS_STATE_SIGNAL && task->state != PROCESS_STATE_TERM)
			task->state = PROCESS_STATE_TERM;

		/* move it to the history */
		tommy_list_insert_tail(&state->runner.history_list, &task->node, task);
		state->runner.latest = 0;

		close(f);
	}

	sl_free(&log_list);

	int64_t stop = time(0);

	log_msg(LVL_INFO, "loaded %d logs in %" PRIi64 " seconds", count, stop - now);

	return 0;
}

