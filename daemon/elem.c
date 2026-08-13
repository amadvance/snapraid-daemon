// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#include "app.h"
#include "state.h"
#include "support.h"
#include "log.h"
#include "parser.h"
#include "runner.h"
#include "smart.h"
#include "elem.h"

/****************************************************************************/
/* command */

struct {
	int cmd;
	const char* str;
} COMMANDS[] = {
	{ CMD_PROBE, "probe" },
	{ CMD_UP, "up" },
	{ CMD_DOWN, "down" },
	{ CMD_SMART, "smart" },
	{ CMD_LIST, "list" },
	{ CMD_DIFF, "diff" },
	{ CMD_DUP, "dup" },
	{ CMD_SYNC, "sync" },
	{ CMD_SCRUB, "scrub" },
	{ CMD_FIX, "fix" },
	{ CMD_CHECK, "check" },
	{ CMD_STATUS, "status" },
	{ CMD_READ, "read" },
	{ CMD_REPORT, "report" },
	{ CMD_DOWN_IDLE, "down_idle" },
	{ CMD_SHUTDOWN, "shutdown" },
	{ CMD_START, "start" },
	{ CMD_MAINTENANCE, "maintenance" },
	{ CMD_HEAL, "heal" },
	{ CMD_UNDELETE, "undelete" },
	{ CMD_SUSPEND_IDLE, "suspend_idle" },
	{ CMD_REFRESH, "refresh" },
	{ CMD_STARTUP, "startup" },
	{ 0 }
};

int command_parse(const char* str)
{
	for (int i = 0; COMMANDS[i].cmd; ++i) {
		if (strcmp(str, COMMANDS[i].str) == 0)
			return COMMANDS[i].cmd;
	}

	return 0;
}

const char* command_name(int cmd)
{
	for (int i = 0; COMMANDS[i].cmd; ++i) {
		if (cmd == COMMANDS[i].cmd)
			return COMMANDS[i].str;
	}

	return "-";
}

/****************************************************************************/
/* disk/split/device */

int disk_count(tommy_list* list, int kind)
{
	int count = 0;
	for (tommy_node* i = tommy_list_head(list); i != 0; i = i->next) {
		struct snapraid_disk* disk = i->data;
		if (disk->kind == kind)
			++count;
	}
	return count;
}

struct snapraid_disk* disk_alloc(const char* name, int kind, int64_t last_time)
{
	struct snapraid_disk* disk = calloc_nofail(1, sizeof(struct snapraid_disk));
	disk->kind = kind;
	disk->total_space_bytes = SMART_UNASSIGNED;
	disk->free_space_bytes = SMART_UNASSIGNED;
	disk->access_count = SMART_UNASSIGNED;
	tracked_set(&disk->error_io, 0, last_time);
	tracked_set(&disk->error_data, 0, last_time);
	sncpy(disk->name, sizeof(disk->name), name);

	return disk;
}

void disk_free(void* void_disk)
{
	struct snapraid_disk* disk = void_disk;
	if (!disk)
		return;
	tommy_list_foreach(&disk->device_list, device_free);
	tommy_list_foreach(&disk->split_list, split_free);
	free(disk);
}

void device_free(void* void_device)
{
	struct snapraid_device* device = void_device;
	if (!device)
		return;
	tommy_list_foreach(&device->temp_list, temperature_free);
	sl_free(&device->id_list);
	free(device);
}

void split_free(void* void_split)
{
	free(void_split);
}

/****************************************************************************/
/* message */

struct snapraid_message* message_alloc(int level, int type, const char* msg)
{
	size_t len = strlen(msg);
	struct snapraid_message* message = malloc_nofail(sizeof(struct snapraid_message) + len + 1);
	message->level = level;
	message->type = type;
	memcpy(message->msg, msg, len + 1);
	return message;
}

void message_free(void* void_message)
{
	free(void_message);
}

void message_insert(tommy_list* list, int level, int type, const char* msg)
{
	struct snapraid_message* message = message_alloc(level, type, msg);
	tommy_list_insert_tail(list, &message->node, message);
}

/****************************************************************************/
/* run */

struct snapraid_run* run_alloc(int day_of_week, int hour, int minute)
{
	struct snapraid_run* run = calloc_nofail(1, sizeof(struct snapraid_run));
	run->day_of_week = day_of_week;
	run->hour = hour;
	run->minute = minute;
	return run;
}

struct snapraid_run* run_dup(struct snapraid_run* run)
{
	return run_alloc(run->day_of_week, run->hour, run->minute);
}

void run_free(void* void_run)
{
	free(void_run);
}

/****************************************************************************/
/* smartignore */

/**
 * Allocate and initialize a new smartignore.
 * @return Pointer to newly allocated smartignore
 */
struct snapraid_smartignore* smartignore_alloc(const char* disk_name, const char* attr_name)
{
	struct snapraid_smartignore* smartignore = calloc_nofail(1, sizeof(struct snapraid_smartignore));
	sncpy(smartignore->disk_name, sizeof(smartignore->disk_name), disk_name);
	sncpy(smartignore->attr_name, sizeof(smartignore->attr_name), attr_name);
	if (strint(&smartignore->attr_index, attr_name) != 0) {
		smartignore->attr_index = 0;
	}
	return smartignore;
}

/**
 * Duplicate a smartignore
 */
struct snapraid_smartignore* smartignore_dup(struct snapraid_smartignore* smartignore)
{
	return smartignore_alloc(smartignore->disk_name, smartignore->attr_name);
}

/**
 * Free a smartignore.
 * @param void_smartignore Pointer to the smartignore entry
 */
void smartignore_free(void* void_smartignore)
{
	free(void_smartignore);
}

int smartignore_match(const char* disk_name, int attr_index, const char* attr_name, tommy_list* smartignore_list)
{
	if (tommy_list_empty(smartignore_list)) {
		return 0;
	}

	for (tommy_node* i = tommy_list_head(smartignore_list); i != 0; i = i->next) {
		struct snapraid_smartignore* smartignore = i->data;
		if ((smartignore->disk_name[0] == '*' && smartignore->disk_name[1] == 0)
			|| strcmp(smartignore->disk_name, disk_name) == 0) {
			if (smartignore->attr_index != 0) {
				if (attr_index != 0 && smartignore->attr_index == attr_index) {
					return 1;
				}
			} else {
				if (strcasecmp(smartignore->attr_name, attr_name) == 0) {
					return 1;
				}
			}
		}
	}

	/* retry with UI interfaces names */
	if (strcmp(attr_name, "error_io") == 0)
		return smartignore_match(disk_name, attr_index, "input_output_errors", smartignore_list);
	if (strcmp(attr_name, "error_data") == 0)
		return smartignore_match(disk_name, attr_index, "silent_errors", smartignore_list);
	if (strcmp(attr_name, "error_protocol") == 0)
		return smartignore_match(disk_name, attr_index, "protocol_errors", smartignore_list);
	if (strcmp(attr_name, "error_medium") == 0)
		return smartignore_match(disk_name, attr_index, "medium_errors", smartignore_list);

	return 0;
}

/****************************************************************************/
/* association */

struct snapraid_association* association_alloc(const char* file, const char* id)
{
	struct snapraid_association* association = calloc_nofail(1, sizeof(struct snapraid_association));
	sncpy(association->file, sizeof(association->file), file);
	sncpy(association->id, sizeof(association->id), id);
	return association;
}

void association_free(void* void_association)
{
	free(void_association);
}

/****************************************************************************/
/* task */

struct snapraid_task* task_alloc(void)
{
	struct snapraid_task* task = calloc_nofail(1, sizeof(struct snapraid_task));
	sl_init(&task->arg_list);
	tommy_list_init(&task->message_list);
	task->message_list_count = 0;
	sl_init(&task->fix_list);
	task->fix_counter = 0;
	task->health = HEALTH_PENDING;
	return task;
}

void task_free(void* void_task)
{
	struct snapraid_task* task = void_task;
	if (!task)
		return;
	sl_free(&task->arg_list);
	tommy_list_foreach(&task->message_list, message_free);
	tommy_list_foreach(&task->fix_list, file_free);
	free(task->text_report);
	free(task);
}

int task_success(struct snapraid_task* task)
{
	if (task->state != PROCESS_STATE_TERM)
		return 0;

	if (task->cmd == CMD_DIFF)
		return task->exit_code == 0 || task->exit_code == EXIT_NEED_SYNC; /* detecting differences are not a failure */

	return task->exit_code == 0;
}

int task_same_group(const struct snapraid_task* task1, const struct snapraid_task* task2)
{
	return task1->group == task2->group;
}

static void task_cancel(struct snapraid_state* state, struct snapraid_task* task, const char* msg, time_t now)
{
	pulse(state, PULSE_TASKS);

	/* remove from the waiting list */
	tommy_list_remove_existing(&state->runner.waiting_list, &task->node);
	sncpy(task->exit_msg, sizeof(task->exit_msg), msg);
	message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, msg);
	task->state = PROCESS_STATE_CANCEL;
	task->unix_start_time = now;
	task->unix_end_time = now;
	log_msg(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));

	/* insert in the history */
	tommy_list_insert_tail(&state->runner.history_list, &task->node, task);
}

void task_list_cancel_in_group(struct snapraid_state* state, struct snapraid_task* failed_task, const char* msg)
{
	time_t now = time(0);
	tommy_node* i = tommy_list_head(&state->runner.waiting_list);
	while (i != 0) {
		tommy_node* i_next = i->next;
		struct snapraid_task* task = i->data;

		/* stop at the first task not part of the group */
		if (!task_same_group(task, failed_task))
			break;

		/* do not cancel report, down, or shutdown commands so cleanup and notifications execute */
		if (task->cmd == CMD_REPORT || task->cmd == CMD_DOWN || task->cmd == CMD_SHUTDOWN) {
			i = i_next;
			continue;
		}

		task_cancel(state, task, msg, now);

		i = i_next;
	}
}

void task_list_cancel_down(struct snapraid_state* state, const char* msg)
{
	time_t now = time(0);
	tommy_node* i = tommy_list_head(&state->runner.waiting_list);
	while (i != 0) {
		tommy_node* i_next = i->next;
		struct snapraid_task* task = i->data;

		if (task->cmd == CMD_DOWN) {
			task_cancel(state, task, msg, now);
		}

		i = i_next;
	}
}

int task_level(struct snapraid_task* task)
{
	int level = LVL_INFO;

	/* check exit code */
	if (task->state == PROCESS_STATE_TERM) {
		if (task->exit_code == EXIT_SYNC_NEEDED)
			level = level_mix(level, LVL_WARNING);
		else if (task->exit_code != 0)
			level = level_mix(level, LVL_ERROR);
	} else if (task->state == PROCESS_STATE_SIGNAL) {
		if (task->exit_sig == SIGINT /* user interrupt with Ctrl+C */
			|| task->exit_sig == SIGTERM) /* user interrupt with "Stop" button */
			level = level_mix(level, LVL_WARNING);
		else
			level = level_mix(level, LVL_CRITICAL); /* crash ? */
	} else if (task->state == PROCESS_STATE_CANCEL) {
		level = level_mix(level, LVL_WARNING);
	}

	/* check all messages */
	for (tommy_node* i = tommy_list_head(&task->message_list); i; i = i->next) {
		struct snapraid_message* message = i->data;

		switch (message->level) {
		case MESSAGE_LEVEL_FATAL :
			if (message->type == MESSAGE_TYPE_HARDWARE)
				level = level_mix(level, LVL_CRITICAL);
			else
				level = level_mix(level, LVL_ERROR);
			break;
		case MESSAGE_LEVEL_ERROR :
			if (message->type == MESSAGE_TYPE_HARDWARE)
				level = level_mix(level, LVL_CRITICAL);
			else
				level = level_mix(level, LVL_WARNING);
			break;
		}
	}

	return level;
}

void task_set_unique_start_time_locked(struct snapraid_state* state, struct snapraid_task* task, time_t now)
{
	if (now <= state->runner.last_start_time)
		now = state->runner.last_start_time + 1;
	task->unix_start_time = now;
	state->runner.last_start_time = now;
}

/****************************************************************************/
/* schedule */

struct snapraid_schedule* schedule_alloc(void)
{
	struct snapraid_schedule* sched = malloc_nofail(sizeof(struct snapraid_schedule));
	sched->cmd = 0;
	sl_init(&sched->args);
	return sched;
}

void schedule_free(void* void_sched)
{
	struct snapraid_schedule* sched = void_sched;
	sl_free(&sched->args);
	free(sched);
}

/****************************************************************************/
/* file */

struct {
	int change;
	const char* str;
} CHANGES[] = {
	{ FILE_CHANGE_DIFF_ADD, "added" },
	{ FILE_CHANGE_DIFF_REMOVE, "removed" },
	{ FILE_CHANGE_DIFF_UPDATE, "updated" },
	{ FILE_CHANGE_DIFF_MOVE, "moved" },
	{ FILE_CHANGE_DIFF_COPY, "copied" },
	{ FILE_CHANGE_DIFF_RELOCATE, "relocated" },
	{ FILE_CHANGE_DIFF_RESTORE, "restored" },
	{ FILE_CHANGE_FIX_RECOVERED, "recovered" },
	{ FILE_CHANGE_FIX_UNRECOVERABLE, "unrecoverable" },
	{ 0 }
};

const char* change_name(int change)
{
	for (int i = 0; CHANGES[i].change; ++i) {
		if (change == CHANGES[i].change)
			return CHANGES[i].str;
	}

	return "-";
}

struct snapraid_file* file_alloc(int change, const char* disk, const char* path)
{
	return file_alloc_source(change, disk, path, 0, 0);
}

struct snapraid_file* file_dup(struct snapraid_file* dup)
{
	return file_alloc_source(dup->change, dup->disk, dup->path, dup->source_disk, dup->source_path);
}

struct snapraid_file* file_alloc_source(int change, const char* disk, const char* path, const char* source_disk, const char* source_path)
{
	ssize_t disk_len = strlen(disk);
	ssize_t path_len = strlen(path);
	ssize_t source_disk_len = source_disk ? strlen(source_disk) : 0;
	ssize_t source_path_len = source_path ? strlen(source_path) : 0;

	struct snapraid_file* file = malloc_nofail(sizeof(struct snapraid_file) + disk_len + path_len + source_disk_len + source_path_len + 4);
	file->change = change;
	file->disk = file->str;
	file->path = file->disk + disk_len + 1;
	file->source_disk = file->path + path_len + 1;
	file->source_path = file->source_disk + source_disk_len + 1;

	memcpy(file->disk, disk, disk_len + 1);
	memcpy(file->path, path, path_len + 1);
	if (source_disk)
		memcpy(file->source_disk, source_disk, source_disk_len + 1);
	else
		file->source_disk[0] = 0;
	if (source_path)
		memcpy(file->source_path, source_path, source_path_len + 1);
	else
		file->source_path[0] = 0;

	return file;
}

void file_free(void* void_file)
{
	struct snapraid_file* file = void_file;
	free(file);
}

/****************************************************************************/
/* diff */

void diff_cleanup(struct snapraid_diff_stat* diff, int64_t equal)
{
	diff->diff_equal = equal;
	diff->diff_added = 0;
	diff->diff_removed = 0;
	diff->diff_updated = 0;
	diff->diff_moved = 0;
	diff->diff_copied = 0;
	diff->diff_relocated = 0;
	diff->diff_restored = 0;

	tommy_list_foreach(&diff->file_list, file_free);
	tommy_list_init(&diff->file_list);
	diff->file_counter = 0;
}

void diff_move(struct snapraid_diff_stat* diff_src, struct snapraid_diff_stat* diff_dest)
{
	/* clear the destination list */
	tommy_list_foreach(&diff_dest->file_list, file_free);

	*diff_dest = *diff_src;

	/* reset the list */
	tommy_list_init(&diff_src->file_list);
	diff_src->file_counter = 0;

	diff_src->diff_equal = diff_dest->diff_equal;
	diff_src->diff_equal += diff_dest->diff_added;
	diff_src->diff_equal += diff_dest->diff_updated;
	diff_src->diff_equal += diff_dest->diff_moved;
	diff_src->diff_equal += diff_dest->diff_copied;
	/* don't add relocated as they match one copied and one removed */
	diff_src->diff_equal += diff_dest->diff_restored;
	diff_src->diff_added = 0;
	diff_src->diff_removed = 0;
	diff_src->diff_updated = 0;
	diff_src->diff_moved = 0;
	diff_src->diff_copied = 0;
	diff_src->diff_relocated = 0;
	diff_src->diff_restored = 0;
}

static int file_compare_disk_path(const void* void_a, const void* void_b)
{
	const struct snapraid_file* a = void_a;
	const struct snapraid_file* b = void_b;
	int ret = strcmp(a->disk, b->disk);
	if (ret != 0)
		return ret;
	return strcmp(a->path, b->path);
}

static int file_compare_importance(const void* void_a, const void* void_b)
{
	const struct snapraid_file* a = void_a;
	const struct snapraid_file* b = void_b;
	if (a->change < b->change)
		return -1;
	if (a->change > b->change)
		return 1;
	return file_compare_disk_path(void_a, void_b);
}

void diff_sort(struct snapraid_diff_stat* diff)
{
	tommy_list_sort(&diff->file_list, file_compare_importance);
}

/****************************************************************************/
/* fix */

void fix_cleanup(struct snapraid_fix_stat* fix)
{
	fix->fix_recovered = 0;
	fix->fix_unrecoverable = 0;

	tommy_list_foreach(&fix->file_list, file_free);
	tommy_list_init(&fix->file_list);
}

void fix_accumulate(tommy_list* fix_src, struct snapraid_fix_stat* fix_dest)
{
	/* assume dest is already sorted */
	tommy_list_sort(fix_src, file_compare_importance);

	/* merge all elements from src to dest avoiding duplicates */
	tommy_node* i = tommy_list_head(fix_src);
	tommy_node* j = tommy_list_head(&fix_dest->file_list);
	while (i) {
		struct snapraid_file* src = i->data;

		/* end of the destination list */
		if (j == 0) {
			/* insert at the end of the dest */
			struct snapraid_file* dup = file_dup(src);
			tommy_list_insert_tail(&fix_dest->file_list, &dup->node, dup);
			i = i->next;
			continue;
		}

		int cmd = file_compare_importance(i->data, j->data);
		if (cmd > 0) {
			/* next dest */
			j = j->next;
			continue;
		}

		if (cmd < 0) {
			/* file is missing in dest */
			struct snapraid_file* dup = file_dup(src);
			tommy_list_insert_before(&fix_dest->file_list, j, &dup->node, dup);
			i = i->next;
			continue;
		}

		/* file is already present in dest with the same change state */
		i = i->next;
		j = j->next;
	}

	/* second pass: remove UNRECOVERABLE files that are now RECOVERED */
	i = tommy_list_head(&fix_dest->file_list);
	j = i;

	/* move j to the start of RECOVERED files */
	while (j) {
		struct snapraid_file* f2 = j->data;
		if (f2->change == FILE_CHANGE_FIX_RECOVERED)
			break;
		j = j->next;
	}

	while (i && j) {
		struct snapraid_file* unr = i->data;
		struct snapraid_file* rec = j->data;

		if (unr->change != FILE_CHANGE_FIX_UNRECOVERABLE)
			break; /* end of UNRECOVERABLE section */

		int cmd = file_compare_disk_path(unr, rec);
		if (cmd < 0) {
			i = i->next;
		} else if (cmd > 0) {
			j = j->next;
		} else {
			/* same file is both UNRECOVERABLE and RECOVERED, remove the UNRECOVERABLE one */
			tommy_node* i_next = i->next;
			tommy_list_remove_existing(&fix_dest->file_list, i);
			file_free(unr);
			i = i_next;
			j = j->next;
		}
	}

	/* recompute counters */
	fix_dest->fix_recovered = 0;
	fix_dest->fix_unrecoverable = 0;

	i = tommy_list_head(&fix_dest->file_list);
	while (i) {
		struct snapraid_file* dst = i->data;
		if (dst->change == FILE_CHANGE_FIX_RECOVERED)
			++fix_dest->fix_recovered;
		if (dst->change == FILE_CHANGE_FIX_UNRECOVERABLE)
			++fix_dest->fix_unrecoverable;
		i = i->next;
	}
}

/****************************************************************************/
/* bucket */

struct snapraid_bucket* bucket_alloc(uint64_t time_at, uint64_t count_scrubbed, uint64_t count_justsynced)
{
	struct snapraid_bucket* bucket = malloc_nofail(sizeof(struct snapraid_bucket));
	bucket->time_at = time_at;
	bucket->count_scrubbed = count_scrubbed;
	bucket->count_justsynced = count_justsynced;
	return bucket;
}

void bucket_free(void* void_bucket)
{
	struct snapraid_bucket* bucket = void_bucket;
	free(bucket);
}

void bucket_cleanup(tommy_list* bucket)
{
	tommy_list_foreach(bucket, bucket_free);
	tommy_list_init(bucket);
}

void bucket_move(tommy_list* bucket_src, tommy_list* bucket_dest)
{
	/* clear the destination list */
	tommy_list_foreach(bucket_dest, bucket_free);

	*bucket_dest = *bucket_src;

	/* reset the list */
	tommy_list_init(bucket_src);
}

/****************************************************************************/
/* health */

const char* power_name(int power)
{
	switch (power) {
	case POWER_STANDBY : return "standby";
	case POWER_ACTIVE : return "active";
	case POWER_PENDING : return "pending";
	}

	return "-";
}

const char* health_name(int health)
{
	switch (health) {
	case HEALTH_PASSED : return "passed";
	case HEALTH_FAILING : return "failing";
	case HEALTH_PREFAIL : return "prefail";
	case HEALTH_CORRUPT : return "corrupt";
	case HEALTH_PENDING : return "pending";
	}

	return "-";
}

static int health_worse(int current, int value, char* reason, size_t reason_size, const char* msg)
{
	if (current <= value)
		return current;

	if (reason)
		sncpy(reason, reason_size, msg);

	return value;
}

static int health_device_list(tommy_list* list, char* reason, size_t reason_size)
{
	int health = HEALTH_PASSED;

	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* device = i->data;
		health = health_worse(health, device->health, reason, reason_size, device->health_reason);
	}

	return health;
}

static int health_split_list(const char* disk, tommy_list* list, char* reason, size_t reason_size)
{
	char msg[HEALTH_REASON_MAX + KEYWORD_MAX];
	int health = HEALTH_PASSED;

	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_split* split = i->data;

		/*
		 * If the UUID was present and it's now different (but not empty) it's a FAIL condition
		 *
		 * Accept an empty UUID in case probe is disabled and it's just not retrieved.
		 */
		if (split->content_uuid[0] != 0 && split->uuid[0] != 0 && strcmp(split->uuid, split->content_uuid) != 0) {
			snprintf(msg, sizeof(msg), "Disk %s has split %d with UUID changed from %s to %s", disk, split->index, split->content_uuid, split->uuid);
			health = health_worse(health, HEALTH_FAILING, reason, reason_size, msg);
		}
	}

	return health;
}

int health_disk(struct snapraid_disk* disk, char* reason, size_t reason_size)
{
	char msg[HEALTH_REASON_MAX + KEYWORD_MAX];
	int health = HEALTH_PASSED;

	if (disk->transient_error_data != 0) {
		snprintf(msg, sizeof(msg), "Disk %s has %" PRIu64 " new silent data %s since the last clean sync/scrub (run a manual scrub reporting 0 bad blocks to reset health status)", disk->name, disk->transient_error_data, disk->transient_error_data == 1 ? "error" : "errors");
		health = health_worse(health, HEALTH_CORRUPT, reason, reason_size, msg);
	}

	if (disk->transient_error_io != 0) {
		snprintf(msg, sizeof(msg), "Disk %s has %" PRIu64 " new input/output %s since the last clean sync/scrub (run a manual scrub reporting 0 bad blocks to reset health status)", disk->name, disk->transient_error_io, disk->transient_error_io == 1 ? "error" : "errors");
		health = health_worse(health, HEALTH_PREFAIL, reason, reason_size, msg);
	}

	int device_health = health_device_list(&disk->device_list, msg, sizeof(msg));
	health = health_worse(health, device_health, reason, reason_size, msg);

	int split_health = health_split_list(disk->name, &disk->split_list, msg, sizeof(msg));
	health = health_worse(health, split_health, reason, reason_size, msg);

	return health;
}

int health_task(struct snapraid_task* task, char* reason, size_t reason_size)
{
	char msg[HEALTH_REASON_MAX + KEYWORD_MAX];
	int health = HEALTH_PASSED;

	if (task->error_data != 0) {
		snprintf(msg, sizeof(msg), "Task found %" PRIu64 " silent data errors", task->error_data);
		health = health_worse(health, HEALTH_CORRUPT, reason, reason_size, msg);
	}

	if (task->error_io != 0) {
		snprintf(msg, sizeof(msg), "Task found %" PRIu64 " input/output errors", task->error_io);
		health = health_worse(health, HEALTH_PREFAIL, reason, reason_size, msg);
	}

	if (task->error_unrecoverable != 0) {
		snprintf(msg, sizeof(msg), "Task found %" PRIu64 " unrecoverable errors", task->error_unrecoverable);
		health = health_worse(health, HEALTH_CORRUPT, reason, reason_size, msg);
	}

	switch (task->state) {
	case PROCESS_STATE_QUEUE :
		snprintf(msg, sizeof(msg), "Task is waiting to be executed");
		health = health_worse(health, HEALTH_PENDING, reason, reason_size, msg);
		break;
	}

	return health;
}

int health_array_locked(struct snapraid_state* state, char* reason, size_t reason_size)
{
	char msg[HEALTH_REASON_MAX];
	int health = HEALTH_PASSED;

	if (reason)
		reason[0] = 0;

	if (state->engine_version[0] == 0 || app_find_engine(state->config.sys_engine) == 0) { /* never run or uninstalled */
		health = HEALTH_PENDING;
		if (reason)
			snprintf(reason, reason_size, "The snapraid binary was not found in the expected location. Please install SnapRAID and restart the daemon.");
	} else if (tommy_list_empty(&state->array.disk_list)) {
		health = HEALTH_PENDING;
		if (reason) {
#ifdef _WIN32
			snprintf(reason, reason_size, "The array is not configured. Copy snapraid.conf.example to snapraid.conf in the installation directory (where snapraid.exe and snapraidd.exe reside) and define your disks to begin.");
#else
			snprintf(reason, reason_size, "The array is not configured. The /etc/snapraid.conf is missing or empty. Copy the snapraid.conf.example to /etc/snapraid.conf and define your disks to begin.");
#endif
		}
	}

	if (state->array.block_bad != 0) {
		snprintf(msg, sizeof(msg), "The array has %" PRIu64 " bad blocks (silent data errors)", state->array.block_bad);
		health = health_worse(health, HEALTH_CORRUPT, reason, reason_size, msg);
	}

	for (tommy_node* i = tommy_list_head(&state->array.disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		int low_health = health_disk(disk, msg, sizeof(msg));
		health = health_worse(health, low_health, reason, reason_size, msg);
	}

	return health;
}

double afr_array_locked(struct snapraid_state* state)
{
	double afr = 0;

	for (tommy_node* i = tommy_list_head(&state->array.disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			afr += device->afr;
		}
	}

	return afr;
}

/**
 * Calculates the probability of at least one failure occurring
 * within a year using a Poisson distribution.
 *
 * @param afr The aggregate Annual Failure Rate (lambda).
 * @return The probability as a double between 0 and 1.
 */
static double poisson_prob_at_least_one_failure(double rate)
{
	return 1.0 - exp(-rate);
}

double fp_array_locked(struct snapraid_state* state)
{
	double afr = afr_array_locked(state);
	if (afr == 0)
		return 0;
	return poisson_prob_at_least_one_failure(afr);
}

/****************************************************************************/
/* temperature */

struct snapraid_temp* temperature_alloc(int temperature, time_t time_at)
{
	struct snapraid_temp* temp = malloc_nofail(sizeof(struct snapraid_temp));
	temp->temp = temperature;
	temp->time_at = time_at;
	return temp;
}

void temperature_free(void* void_temp)
{
	struct snapraid_temp* temp = void_temp;
	free(temp);
}

int temperature_cleanup(struct snapraid_device* device, time_t last_time)
{
	int ret = 0;
	time_t cutoff = last_time - SECONDS_IN_A_DAY;

	/* clear too old entries */
	tommy_node* i = tommy_list_head(&device->temp_list);
	while (i) {
		tommy_node* i_next = i->next;

		struct snapraid_temp* entry = i->data;

		if (entry->time_at < cutoff) {
			tommy_list_remove_existing(&device->temp_list, &entry->node);
			temperature_free(entry);
			ret = 1;
		}

		i = i_next;
	}

	return ret;
}

int temperature_cleanup_devices(struct snapraid_state* state, time_t last_time)
{
	int ret = 0;

	for (tommy_node* i = tommy_list_head(&state->array.disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			if (temperature_cleanup(device, last_time))
				ret = 1;
		}
	}

	return ret;
}

void temperature_insert(struct snapraid_device* device, struct snapraid_temp* temp)
{
	temperature_cleanup(device, temp->time_at);

	tommy_list_insert_tail(&device->temp_list, &temp->node, temp);
}

/****************************************************************************/
/* tracked */

void tracked_init(struct snapraid_tracked* tracked)
{
	tracked->value = SMART_UNASSIGNED;
	tracked->prev = SMART_UNASSIGNED;
	tracked->lowest = SMART_UNASSIGNED;
	tracked->highest = SMART_UNASSIGNED;
	tracked->prev_last = 0;
	tracked->lowest_last = 0;
	tracked->highest_last = 0;
}

void tracked_set(struct snapraid_tracked* tracked, uint64_t value, int64_t last_time)
{
	tracked->value = value;
	tracked->prev = SMART_UNASSIGNED;
	tracked->lowest = value;
	tracked->highest = value;
	tracked->prev_last = 0;
	tracked->lowest_last = last_time;
	tracked->highest_last = last_time;
}

void tracked_update(struct snapraid_tracked* tracked, uint64_t old, int kind, int64_t last_time)
{
	if (tracked->value == SMART_UNASSIGNED)
		return;

	if (tracked->lowest == SMART_UNASSIGNED
		|| smart_conv(tracked->value, kind) < smart_conv(tracked->lowest, kind)) {
		tracked->lowest = tracked->value;
		tracked->lowest_last = last_time;
	} else if (smart_conv(tracked->lowest, kind) == smart_conv(tracked->value, kind)) {
		tracked->lowest_last = last_time;
	}

	if (tracked->highest == SMART_UNASSIGNED
		|| smart_conv(tracked->value, kind) > smart_conv(tracked->highest, kind)) {
		tracked->highest = tracked->value;
		tracked->highest_last = last_time;
	} else if (smart_conv(tracked->highest, kind) == smart_conv(tracked->value, kind)) {
		tracked->highest_last = last_time;
	}

	if (old != SMART_UNASSIGNED
		&& smart_conv(old, kind) != smart_conv(tracked->value, kind)) {
		tracked->prev = old;
		tracked->prev_last = last_time;
	}
}

/****************************************************************************/
/* page */

struct snapraid_page* page_alloc(const char* path, size_t content_size)
{
	ssize_t path_len = strlen(path);

	struct snapraid_page* page = malloc_nofail(sizeof(struct snapraid_page) + path_len + 1 + content_size);
	page->path = page->str;
	page->size = content_size;
	page->content = page->path + path_len + 1;
	page->mime_type = 0;
	page->is_static = 0;

	memcpy(page->path, path, path_len + 1);

	return page;
}

struct snapraid_page* page_dup(const struct snapraid_page* src)
{
	struct snapraid_page* dup = page_alloc(src->path, src->size);
	dup->mime_type = src->mime_type;
	dup->is_static = src->is_static;

	memcpy(dup->content, src->content, src->size);

	return dup;
}

void page_free(void* void_page)
{
	free(void_page);
}

