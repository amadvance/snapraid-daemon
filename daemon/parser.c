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
#include "smart.h"
#include "parser.h"

/**
 * Clear the error accumulators of all the disks.
 */
static void clear_disk_accumulator(struct snapraid_state* state)
{
	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* data = i->data;
		if (data->error_io != 0 || data->error_data != 0) {
			pulse(state, PULSE_DISKS);
			data->error_io = 0;
			data->error_data = 0;
		}
	}
	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_disk* parity = i->data;
		if (parity->error_io != 0 || parity->error_data != 0) {
			pulse(state, PULSE_DISKS);
			parity->error_io = 0;
			parity->error_data = 0;
		}
	}
}

/**
 * Clear the access accumulators of all the disks.
 */
static void clear_access_accumulator(struct snapraid_state* state)
{
	pulse(state, PULSE_DISKS);
	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* data = i->data;
		data->access_count_initial_time = state->global.last_time;
		data->access_count_latest_time = state->global.last_time;
	}
	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_disk* parity = i->data;
		parity->access_count_initial_time = state->global.last_time;
		parity->access_count_latest_time = state->global.last_time;
	}
}

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
	disk->total_space_bytes = 0;
	disk->free_space_bytes = 0;
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
	for (j = 0; j < SMART_COUNT; ++j) {
		tracked_init(&device->smart[j].raw);
		device->smart[j].norm = 0;
		device->smart[j].worst = 0;
		device->smart[j].thresh = 0;
		device->smart[j].flags = 0;
	}
	tracked_init(&device->error_protocol);
	tracked_init(&device->error_medium);
	device->wear_level = SMART_UNASSIGNED;
	device->size = SMART_UNASSIGNED;
	device->rotational = SMART_UNASSIGNED;
	device->flags = SMART_UNASSIGNED;
	device->power = POWER_PENDING;
	device->health = HEALTH_PENDING;
	sncpy(device->health_reason, sizeof(device->health_reason), "SMART telemetry not yet obtained because the device is in stand-by");
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
			pulse(state, PULSE_DISKS);
			parity->access_count = access_count;
			parity->access_count_initial_time = state->global.last_time;
		}

		/* this is the current time, no need to pulse */
		parity->access_count_latest_time = state->global.last_time;
	} else {
		struct snapraid_disk* data = find_disk(&state->data_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (data->access_count != access_count) {
			pulse(state, PULSE_DISKS);
			data->access_count = access_count;
			data->access_count_initial_time = state->global.last_time;
		}

		/* this is the current time, no need to pulse */
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

	pulse_str(state, PULSE_DISKS, split->path, sizeof(split->path), dir);
	pulse_str(state, PULSE_DISKS, split->uuid, sizeof(split->uuid), uuid);
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

	pulse_str(state, PULSE_DISKS, split->path, sizeof(split->path), path);
	pulse_str(state, PULSE_DISKS, split->uuid, sizeof(split->uuid), uuid);
}

static void process_content_data(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];

	struct snapraid_disk* data = find_disk(&state->data_list, name);

	/* PULSE_ARRAY reports the sum of alloc and free space */
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &data->total_space_bytes, size_alloc);
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &data->free_space_bytes, size_free);
}

static void process_content_parity(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];

	struct snapraid_disk* parity = find_disk(&state->parity_list, name);

	/* PULSE_ARRAY reports the sum of alloc and free space */
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &parity->total_space_bytes, size_alloc);
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &parity->free_space_bytes, size_free);
}

static void process_content_data_split(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	const char* name = map[1];
	const char* uuid = map[2];

	struct snapraid_disk* data = find_disk(&state->data_list, name);
	struct snapraid_split* split = find_split(&data->split_list, 0); /* at present data disks don't have the split index */

	pulse_str(state, PULSE_DISKS, split->content_uuid, sizeof(split->content_uuid), uuid);
}

static void process_content_parity_split(struct snapraid_state* state, char** map, size_t mac)
{
	int index;

	if (mac < 5)
		return;

	char* name = map[1];
	const char* uuid = map[2];
	const char* path = map[3];
	const char* size = map[4];

	if (!is_split_parity(name, &index))
		return;

	struct snapraid_disk* disk = find_disk(&state->parity_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, index);

	pulse_str(state, PULSE_DISKS, split->path, sizeof(split->path), path);
	pulse_str(state, PULSE_DISKS, split->content_uuid, sizeof(split->uuid), uuid);
	pulse_stru64(state, PULSE_DISKS, &split->content_size, size);
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
		pulse_stru64(state, PULSE_ARRAY, &state->global.file_total, val);
	} else if (strcmp(tag, "block_bad") == 0) {
		pulse_stru64(state, PULSE_ARRAY, &state->global.block_bad, val);
		if (state->global.block_bad == 0) {
			/* if content has no stored error, clear the disk error accumulators */
			clear_disk_accumulator(state);
		}
	} else if (strcmp(tag, "block_rehash") == 0) {
		pulse_stru64(state, PULSE_ARRAY, &state->global.block_rehash, val);
	} else if (strcmp(tag, "block_unscrubbed") == 0) {
		pulse_stru64(state, PULSE_ARRAY, &state->global.block_unscrubbed, val);
	} else if (strcmp(tag, "block_unsynced") == 0) {
		pulse_stru64(state, PULSE_ARRAY, &state->global.block_unsynced, val);
	} else if (strcmp(tag, "block") == 0) {
		pulse_stru64(state, PULSE_ARRAY, &state->global.block_total, val);
	}
}

static void process_fsinfo_data(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];

	struct snapraid_disk* data = find_disk(&state->data_list, name);

	/* PULSE_ARRAY reports the sum of alloc and free space */
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &data->total_space_bytes, size_alloc);
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &data->free_space_bytes, size_free);
}

static void process_fsinfo_parity(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];

	struct snapraid_disk* parity = find_disk(&state->parity_list, name);

	/* PULSE_ARRAY reports the sum of alloc and free space */
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &parity->total_space_bytes, size_alloc);
	pulse_stru64(state, PULSE_DISKS | PULSE_ARRAY, &parity->free_space_bytes, size_free);
}

static void process_fsinfo_data_split(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 6)
		return;

	const char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];
	const char* type = map[4];
	const char* label = map[5];

	struct snapraid_disk* data = find_disk(&state->data_list, name);
	struct snapraid_split* split = find_split(&data->split_list, 0); /* at present data disks don't have the split index */

	pulse_stru64(state, PULSE_DISKS, &split->fssize, size_alloc);
	pulse_stru64(state, PULSE_DISKS, &split->fsfree, size_free);
	pulse_str(state, PULSE_DISKS, split->fstype, sizeof(split->fstype), type);
	pulse_str(state, PULSE_DISKS, split->fslabel, sizeof(split->fslabel), label);
}

static void process_fsinfo_parity_split(struct snapraid_state* state, char** map, size_t mac)
{
	int index;

	if (mac < 6)
		return;

	char* name = map[1];
	const char* size_alloc = map[2];
	const char* size_free = map[3];
	const char* type = map[4];
	const char* label = map[5];

	if (!is_split_parity(name, &index))
		return;

	struct snapraid_disk* disk = find_disk(&state->parity_list, name);
	struct snapraid_split* split = find_split(&disk->split_list, index);

	pulse_stru64(state, PULSE_DISKS, &split->fssize, size_alloc);
	pulse_stru64(state, PULSE_DISKS, &split->fsfree, size_free);
	pulse_str(state, PULSE_DISKS, split->fstype, sizeof(split->fstype), type);
	pulse_str(state, PULSE_DISKS, split->fslabel, sizeof(split->fslabel), label);
}

static void process_attr(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 5)
		return;
	if (map[2][0] == 0) /* ignore if no disk name is provided */
		return;

	struct snapraid_device* device = find_device(state, map[2], map[1]);

	const char* disk = map[2];
	const char* tag = map[3];
	const char* val = map[4];

	if (strcmp(tag, "serial") == 0)
		pulse_str(state, PULSE_DISKS, device->serial, sizeof(device->serial), val);
	else if (strcmp(tag, "model") == 0)
		pulse_str(state, PULSE_DISKS, device->model, sizeof(device->model), val);
	else if (strcmp(tag, "family") == 0)
		pulse_str(state, PULSE_DISKS, device->family, sizeof(device->family), val);
	else if (strcmp(tag, "interface") == 0)
		pulse_str(state, PULSE_DISKS, device->interf, sizeof(device->interf), val);
	else if (strcmp(tag, "size") == 0)
		pulse_stru64(state, PULSE_DISKS, &device->size, val);
	else if (strcmp(tag, "rotationrate") == 0)
		/* do not pulse because if the disk is in stand-by it gets 1 instead of the rate */
		stru64(&device->rotational, val);
	else if (strcmp(tag, "afr") == 0) {
		pulse_double(state, PULSE_DISKS, &device->afr, val);
		if (mac >= 6)
			pulse_double(state, PULSE_DISKS, &device->prob, map[5]);
	} else if (strcmp(tag, "temperature") == 0) {
		if (pulse_strint(state, PULSE_DISKS, &device->temperature, val) == 0) {
			struct snapraid_temp* temp = temperature_alloc(device->temperature, state->global.last_time);
			temperature_insert(device, temp);
		}
	} else if (strcmp(tag, "error_protocol") == 0) {
		uint64_t old = device->error_protocol.value;
		if (pulse_stru64(state, PULSE_DISKS, &device->error_protocol.value, val) == 0) {
			tracked_update(&device->error_protocol, old, 0, state->global.last_time);
		}
	} else if (strcmp(tag, "error_medium") == 0) {
		uint64_t old = device->error_medium.value;
		if (pulse_stru64(state, PULSE_DISKS, &device->error_medium.value, val) == 0) {
			tracked_update(&device->error_medium, old, 0, state->global.last_time);
		}
	} else if (strcmp(tag, "wear_level") == 0)
		pulse_stru64(state, PULSE_DISKS, &device->wear_level, val);
	else if (strcmp(tag, "power") == 0) {
		int power = POWER_PENDING;
		if (strcmp(val, "standby") == 0 || strcmp(val, "down") == 0) {
			power = POWER_STANDBY;
		} else if (strcmp(val, "active") == 0 || strcmp(val, "up") == 0) {
			power = POWER_ACTIVE;
		}
		if (device->power != power) {
			pulse(state, PULSE_DISKS);
			device->power = power;
		}
	} else if (strcmp(tag, "flags") == 0) {
		uint64_t flags;
		if (stru64(&flags, val) == 0) {
			int health = HEALTH_PENDING;
			char health_reason[HEALTH_REASON_MAX];

			/* update the time, but do not pulse on this */
			device->smart_time = state->global.last_time;

			if (flags & SMARTCTL_FLAG_FAIL) {
				snprintf(health_reason, sizeof(health_reason), "SMART reports a FAILING condition for disk %s", disk);
				health = HEALTH_FAILING;
			} else if (flags & SMARTCTL_FLAG_PREFAIL) {
				snprintf(health_reason, sizeof(health_reason), "SMART reports a PREFAIL condition for disk %s", disk);
				health = HEALTH_PREFAIL;
			} else {
				health_reason[0] = 0;
				health = HEALTH_PASSED;
			}

			if (device->health != health || device->flags != flags) {
				pulse(state, PULSE_DISKS);
				device->health = health;
				sncpy(device->health_reason, sizeof(device->health_reason), health_reason);
				device->flags = flags;
			}
		}
	} else {
		if (mac < 13)
			return;

		int index;
		const char* raw = map[4];
		const char* norm = map[6];
		const char* worst = map[7];
		const char* thresh = map[8];
		const char* name = map[9];
		const char* type = map[10];
		const char* updated = map[11];
		const char* when_failed = map[12];

		int flags = 0;
		if (strcmp(type, "prefail") == 0)
			flags |= SMART_ATTR_TYPE_PREFAIL;
		else if (strcmp(type, "oldage") == 0)
			flags |= SMART_ATTR_TYPE_OLDAGE;
		if (strcmp(updated, "always") == 0)
			flags |= SMART_ATTR_UPDATE_ALWAYS;
		else if (strcmp(updated, "offline") == 0)
			flags |= SMART_ATTR_UPDATE_OFFLINE;
		if (strcmp(when_failed, "now") == 0)
			flags |= SMART_ATTR_WHEN_FAILED_NOW;
		else if (strcmp(when_failed, "past") == 0)
			flags |= SMART_ATTR_WHEN_FAILED_PAST;
		else if (strcmp(when_failed, "never") == 0)
			flags |= SMART_ATTR_WHEN_FAILED_NEVER;

		if (strint(&index, tag) == 0 && index >= 0 && index < 256) {
			int kind = smart_kind(index, name);
			uint64_t old_raw = device->smart[index].raw.value;
			int got_raw;

			if ((kind & SMART_KIND_PULSE) != 0) {
				got_raw = pulse_stru64(state, PULSE_DISKS, &device->smart[index].raw.value, raw);
				pulse_stru64(state, PULSE_DISKS, &device->smart[index].norm, norm);
				pulse_stru64(state, PULSE_DISKS, &device->smart[index].worst, worst);
				pulse_stru64(state, PULSE_DISKS, &device->smart[index].thresh, thresh);
				sncpy(device->smart[index].name, sizeof(device->smart[index].name), name);
				device->smart[index].flags = flags;
			} else {
				/* these values are not reported with pulse */
				got_raw = stru64(&device->smart[index].raw.value, raw);
				stru64(&device->smart[index].norm, norm);
				stru64(&device->smart[index].worst, worst);
				stru64(&device->smart[index].thresh, thresh);
				sncpy(device->smart[index].name, sizeof(device->smart[index].name), name);
				device->smart[index].flags = flags;
			}

			if (got_raw == 0 && (kind & SMART_KIND_PREFAIL) != 0)
				tracked_update(&device->smart[index].raw, old_raw, kind, state->global.last_time);
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
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc(FILE_CHANGE_DIFF_ADD, disk, path);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	} else if (strcmp(tag, "remove") == 0) {
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc(FILE_CHANGE_DIFF_REMOVE, disk, path);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	} else if (strcmp(tag, "update") == 0) {
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc(FILE_CHANGE_DIFF_UPDATE, disk, path);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	} else if (strcmp(tag, "move") == 0 && mac >= 5) {
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc_source(FILE_CHANGE_DIFF_MOVE, disk, path, disk, map[4]);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	} else if (strcmp(tag, "copy") == 0 && mac >= 6) {
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc_source(FILE_CHANGE_DIFF_COPY, disk, path, map[4], map[5]);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	} else if (strcmp(tag, "restore") == 0) {
		/* do not pulse because this is temporary storage for parsing */
		struct snapraid_file* file = file_alloc(FILE_CHANGE_DIFF_RESTORE, disk, path);
		tommy_list_insert_tail(&state->global.diff_parse.file_list, &file->node, file);
	}
}

static void process_bucket(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	const char* tag = map[1];
	const char* val = map[2];

	if (strcmp(tag, "entry") == 0) {
		if (mac < 5)
			return;

		const char* count1 = map[3];
		const char* count2 = map[4];
		uint64_t time_at;
		uint64_t count_scrubbed;
		uint64_t count_justsynced;

		if (stru64(&time_at, val) == 0
			&& stru64(&count_scrubbed, count1) == 0
			&& stru64(&count_justsynced, count2) == 0) {
			/* do not pulse because this is temporary storage for parsing */
			struct snapraid_bucket* bucket = bucket_alloc(time_at, count_scrubbed, count_justsynced);
			tommy_list_insert_tail(&state->global.bucket_parse_list, &bucket->node, bucket);
		}
	} else if (strcmp(tag, "count") == 0) {
		/* unused */
	} else if (strcmp(tag, "block_count") == 0) {
		/* unused */
	}
}

static void process_list(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 2)
		return;

	const char* tag = map[1];

	if (strcmp(tag, "scan_begin") == 0) {
		/* a new diff list is coming, so cleanup it */
		/* do not pulse because this is temporary storage for parsing */
		diff_cleanup(&state->global.diff_parse, 0);
	} else if (strcmp(tag, "scan_end") == 0) {
		/* now we pulse because we move the temporary parsing data to the real data */
		pulse(state, PULSE_ARRAY);

		/* move the parsing to the current state */
		diff_move(&state->global.diff_parse, &state->global.diff_current);
	} else if (strcmp(tag, "bucket_begin") == 0) {
		/* for any command that load content */

		/* generate a new bucket list, so cleanup it */
		/* do not pulse because this is temporary storage for parsing */
		bucket_cleanup(&state->global.bucket_parse_list);
	} else if (strcmp(tag, "bucket_end") == 0) {
		/* for any command that load content */

		/* now we pulse because we move the temporary parsing data to the real data */
		pulse(state, PULSE_ARRAY);

		/* move the parsing bucket to the current state */
		bucket_move(&state->global.bucket_parse_list, &state->global.bucket_list);
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
		pulse(state, PULSE_ACTIVITY);
		struint(&task->block_begin, map[2]);
		struint(&task->block_end, map[3]);
		struint(&task->block_count, map[4]);
	} else if (strcmp(map[1], "pos") == 0) {
		if (mac < 10)
			return;

		pulse(state, PULSE_ACTIVITY);
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
			pulse(state, PULSE_ACTIVITY);
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

	pulse(state, PULSE_ACTIVITY);

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

	pulse(state, PULSE_ACTIVITY);

	const char* msg = map[2];

	/* skip initial spaces */
	while (*msg != 0 && isspace((unsigned char)*msg))
		++msg;

	if (strcmp(map[1], "progress") == 0 || strcmp(map[1], "status") == 0) {
		/* don't limit the number of these messages */
		struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_INFO, MESSAGE_TYPE_NONE, msg);
		tommy_list_insert_tail(&task->message_list, &message->node, message);
		++task->message_list_count;
	} else if (strcmp(map[1], "verbose") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_INFO, MESSAGE_TYPE_NONE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	} else if (strcmp(map[1], "error") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_ERROR, MESSAGE_TYPE_SOFTWARE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	} else if (strcmp(map[1], "expected") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_INFO, MESSAGE_TYPE_SOFTWARE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	} else if (strcmp(map[1], "fatal") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	} else if (strcmp(map[1], "error_hardware") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_ERROR, MESSAGE_TYPE_HARDWARE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	} else if (strcmp(map[1], "fatal_hardware") == 0) {
		if (task->message_list_count <= MESSAGES_MAX) {
			struct snapraid_message* message = message_alloc(MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_HARDWARE, msg);
			tommy_list_insert_tail(&task->message_list, &message->node, message);
		}
		++task->message_list_count;
	}
}

static void process_status(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 4)
		return;

	const char* ope = map[1];
	const char* disk = map[2];
	const char* sub = map[3];

	if (strcmp(ope, "recovered") == 0 || strcmp(ope, "recoverable") == 0) {
		pulse(state, PULSE_ACTIVITY);
		struct snapraid_file* file = file_alloc(FILE_CHANGE_RECOVERED, disk, sub);
		tommy_list_insert_tail(&task->fix_list, &file->node, file);
	} else if (strcmp(ope, "unrecoverable") == 0) {
		pulse(state, PULSE_ACTIVITY);
		struct snapraid_file* file = file_alloc(FILE_CHANGE_UNRECOVERABLE, disk, sub);
		tommy_list_insert_tail(&task->fix_list, &file->node, file);
	}
}

static void process_error(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 5) /* error:<block>:<disk_name>:<file>:<msg> */
		return;

	/* the task error_io and error_data will be gathered by the final summary tag */

	if (strstr(map[0], "error_io") != 0) { /* match all [hardlink/symlink/dir/empty]_error_io */
		struct snapraid_disk* data = find_disk(&state->data_list, map[2]);
		pulse(state, PULSE_DISKS);
		++data->error_io;
	} else if (strcmp(map[0], "error_data") == 0) {
		struct snapraid_disk* data = find_disk(&state->data_list, map[2]);
		pulse(state, PULSE_DISKS);
		++data->error_data;
	}
}

static void process_parity_error(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 4) /* parity_error:<block>:<level>:<msg> */
		return;

	/* the task error_io and error_data will be gathered by the final summary tag */

	if (strcmp(map[0], "parity_error_io") == 0) {
		struct snapraid_disk* parity = find_disk(&state->parity_list, map[2]);
		pulse(state, PULSE_DISKS);
		++parity->error_io;
	} else if (strcmp(map[0], "parity_error_data") == 0) {
		struct snapraid_disk* parity = find_disk(&state->parity_list, map[2]);
		pulse(state, PULSE_DISKS);
		++parity->error_data;
	}
}

static void process_conf(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	if (strcmp(map[1], "file") == 0) {
		pulse_str(state, PULSE_ARRAY, state->global.conf_engine, sizeof(state->global.conf_engine), map[2]);
	}
}

static void process_content(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	pulse_str(state, PULSE_ARRAY, state->global.content, sizeof(state->global.content), map[1]);
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
	pulse_str(state, PULSE_ARRAY, state->global.version, sizeof(state->global.version), s);

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

	pulse_struint(state, PULSE_ARRAY, &state->global.blocksize, map[1]);
}

static void process_unixtime(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	/* this is the current time, no need to pulse */
	stri64(&state->global.last_time, map[1]);

	/* at any time update, remove too old temperature measurements */
	if (temperature_cleanup_devices(state, state->global.last_time))
		pulse(state, PULSE_DISKS);
}

static void process_command(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	const char* val = map[1];

	pulse_str(state, PULSE_ARRAY, state->global.last_cmd, sizeof(state->global.last_cmd), val);

	int cmd = command_parse(val);

	switch (cmd) {
	case CMD_UP :
		clear_access_accumulator(state);
		break;
	}
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

	/* these are always unique and always changing something */
	pulse(state, PULSE_ACTIVITY);

	if (strcmp(tag, "start") == 0) {
		stri64(&task->unix_start_time, val);
	} else if (strcmp(tag, "end") == 0) {
		stri64(&task->unix_end_time, val);
	} else if (strcmp(tag, "scheduled") == 0) {
		stri64(&task->unix_queue_time, val);
	} else if (strcmp(tag, "command") == 0) {
		task->cmd = command_parse(val);
	} else if (strcmp(tag, "high_command") == 0) {
		task->high_cmd = command_parse(val);
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

	if (strcmp(map[1], "error_soft") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->hash_error_soft, map[2]);
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
	if (task->cmd == CMD_DIFF || task->cmd == CMD_SYNC) {
		/* do not pulse because this is temporary storage for parsing */
		if (strcmp(tag, "equal") == 0)
			stri64(&state->global.diff_parse.diff_equal, val);
		else if (strcmp(tag, "added") == 0)
			stri64(&state->global.diff_parse.diff_added, val);
		else if (strcmp(tag, "removed") == 0)
			stri64(&state->global.diff_parse.diff_removed, val);
		else if (strcmp(tag, "updated") == 0)
			stri64(&state->global.diff_parse.diff_updated, val);
		else if (strcmp(tag, "moved") == 0)
			stri64(&state->global.diff_parse.diff_moved, val);
		else if (strcmp(tag, "copied") == 0)
			stri64(&state->global.diff_parse.diff_copied, val);
		else if (strcmp(tag, "restored") == 0)
			stri64(&state->global.diff_parse.diff_restored, val);
	}

	if (strcmp(tag, "error_soft") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->error_soft, val);
	} else if (strcmp(tag, "error_io") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->error_io, val);
	} else if (strcmp(tag, "error_data") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->error_data, val);
	} else if (strcmp(tag, "error_recovered") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->error_recovered, val);
	} else if (strcmp(tag, "error_unrecoverable") == 0) {
		pulse_stru64(state, PULSE_ACTIVITY, &task->error_unrecoverable, val);
	} else if (strcmp(tag, "exit") == 0) {
		/* set the time, only if we complete the command */
		switch (task->cmd) {
		case CMD_SYNC :
			/* now we pulse because we move the diff */
			pulse(state, PULSE_ARRAY);
			state->global.sync_time = task->unix_start_time;

			/* after a sync the latest diff is the sync itself */
			state->global.diff_time = task->unix_start_time;
			state->global.fix_time = 0;

			/* move the current to the previous state */
			diff_move(&state->global.diff_current, &state->global.diff_prev);

			/* clear the parsing fix as now they are integrated in the parity */
			fix_cleanup(&state->global.fix_current);
			break;
		case CMD_SCRUB :
			pulse(state, PULSE_ARRAY);
			state->global.scrub_time = task->unix_start_time;
			break;
		case CMD_DIFF :
			pulse(state, PULSE_ARRAY);
			state->global.diff_time = task->unix_start_time;
			break;
		case CMD_FIX :
			pulse(state, PULSE_ARRAY);
			state->global.fix_time = task->unix_start_time;

			/* accumulate the parsing fix to the current state */
			fix_accumulate(&task->fix_list, &state->global.fix_current);
			break;
		}
	}
}

static int process_line(struct snapraid_state* state, char** map, size_t mac)
{
	const char* cmd;
	int ignore_this_line = 0;

	if (mac == 0)
		return ignore_this_line;

	cmd = map[0];

	if (strcmp(cmd, "smartctl") == 0) {
		ignore_this_line = 1;
	} else if (strcmp(cmd, "data") == 0) {
		state_lock();
		process_data(state, map, mac);
		state_unlock();
	} else if (is_parity(cmd)) {
		state_lock();
		process_parity(state, map, mac);
		state_unlock();
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
	} else if (strcmp(cmd, "status") == 0) {
		state_lock();
		process_status(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "stat") == 0) {
		state_lock();
		process_stat(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "command") == 0) {
		state_lock();
		process_command(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "list") == 0) {
		state_lock();
		process_list(state, map, mac);
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
	} else if (strcmp(cmd, "content_data_split") == 0) {
		state_lock();
		process_content_data_split(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content_parity_split") == 0) {
		state_lock();
		process_content_parity_split(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "content_info") == 0) {
		state_lock();
		process_content_info(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "bucket") == 0) {
		state_lock();
		process_bucket(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "fsinfo_data") == 0) {
		state_lock();
		process_fsinfo_data(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "fsinfo_parity") == 0) {
		state_lock();
		process_fsinfo_parity(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "fsinfo_data_split") == 0) {
		state_lock();
		process_fsinfo_data_split(state, map, mac);
		state_unlock();
	} else if (strcmp(cmd, "fsinfo_parity_split") == 0) {
		state_lock();
		process_fsinfo_parity_split(state, map, mac);
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
	} else if (strcmp(cmd, "daemon") == 0) {
		state_lock();
		process_daemon(state, map, mac);
		state_unlock();
	}

	return ignore_this_line;
}

#define RUN_INPUT_MAX 4096
#define RUN_FIELD_MAX 64

void parse_log(struct snapraid_state* state, int f, FILE* log_f, const char* log_path)
{
	char buf[RUN_INPUT_MAX];
	char plain[RUN_INPUT_MAX];
	char dup[RUN_INPUT_MAX];
	char* map[RUN_FIELD_MAX];
	size_t plain_len = 0;
	size_t dup_len = 0;
	size_t mac = 0;
	size_t mac_limit = 0; /* no limit */
	int escape = 0;
	int disable = 0;

	map[mac++] = plain;

	/* clear the engine version */
	state->global.version_major = 0;
	state->global.version_minor = 0;

	while (1) {
		ssize_t n = read(f, buf, sizeof(buf));
		if (n > 0) {
			ssize_t i;

			for (i = 0; i < n; i++) {
				char c = buf[i];

				/* insert in the duplicate plain */
				if (dup_len + 1 < RUN_INPUT_MAX) { /* ignore if too long */
					dup[dup_len++] = c;
				}

				/* insert in the de-escaped plain */
				if (escape) {
					if (plain_len + 1 < RUN_INPUT_MAX) { /* ignore if too long */
						switch (c) {
						case '\\' : plain[plain_len++] = '\\'; break;
						case 'n' :  plain[plain_len++] = '\n'; break;
						case 'd' : plain[plain_len++] = ':'; break;
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

				if (c == ':' && (mac_limit == 0 || mac <= mac_limit)) {
					if (mac + 1 < RUN_FIELD_MAX) {
						plain[plain_len++] = '\0';
						if (mac == 1) {
							if (strcmp(map[0], "msg") == 0)
								mac_limit = 2; /* the command has two tags, no more */
						}
						map[mac++] = &plain[plain_len];
						continue;
					}
					/* do not split if too many fields */
				}

				if (c == '\r') {
					continue; /* ignore Windows CR */
				}

				if (c == '\n') {
					int ignore_this_line = 0;

					plain[plain_len] = '\0';
					map[mac] = 0;

					if (!disable) {
						ignore_this_line = process_line(state, map, mac);

						/* version 14 is the minimal supported one */
						if (state->global.version_major != 0 && state->global.version_major < 14) {
							/* don't log error in syslog if it's a past log */
							if (log_f)
								log_msg(LVL_ERROR, "requires SnapRAID 14.0 or newer");
							if (state->runner.latest)
								message_insert(&state->runner.latest->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, "Requires SnapRAID 14.0 or newer");
							disable = 1;
						}
					}

					dup[dup_len] = 0; /* it contains the \n */

					/* write dup to the log */
					if (!ignore_this_line && log_f) {
						if (fwrite(dup, dup_len, 1, log_f) != 1) {
							log_msg(LVL_WARNING, "failed to write log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
						}
					}

					plain_len = 0;
					dup_len = 0;
					mac = 0;
					mac_limit = 0;
					escape = 0;
					map[mac++] = plain;
					continue;
				}

				if (plain_len + 1 < RUN_INPUT_MAX) /* ignore if too long */
					plain[plain_len++] = c;
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

int parse_timestamp(const char* name, int64_t* out)
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
	struct dirent* ent;
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
		sncpy(task->log_file, sizeof(task->log_file), path);

		parse_log(state, f, 0, 0);
		++count;

		/* compute the task health */
		task->health = health_task(task);

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

