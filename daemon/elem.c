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
#include "parser.h"
#include "daemon.h"
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
	{ CMD_STATUS, "status" },
	{ CMD_LIST, "list" },
	{ CMD_DIFF, "diff" },
	{ CMD_DUP, "dup" },
	{ CMD_DEVICES, "devices" },
	{ CMD_SYNC, "sync" },
	{ CMD_SCRUB, "scrub" },
	{ CMD_FIX, "fix" },
	{ CMD_CHECK, "check" },
	{ CMD_REPORT, "report" },
	{ CMD_DOWN_IDLE, "down_idle" },
	{ CMD_MAINTENANCE, "maintenance" },
	{ CMD_HEAL, "heal" },
	{ CMD_UNDELETE, "undelete" },
	{ CMD_SUSPEND_IDLE, "suspend_idle" },
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
	free(void_device);
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
/* task */

struct snapraid_task* task_alloc(void)
{
	struct snapraid_task* task = calloc_nofail(1, sizeof(struct snapraid_task));
	sl_init(&task->arg_list);
	tommy_list_init(&task->message_list);
	task->message_list_count = 0;
	sl_init(&task->fix_list);
	task->health = HEALTH_PASSED;
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

void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list, const char* msg)
{
	time_t now = time(0);
	tommy_node* i = tommy_list_head(waiting_list);
	while (i != 0) {
		tommy_node* i_next = i->next;
		struct snapraid_task* task = i->data;

		/* stop at the first report */
		if (task->cmd == CMD_REPORT)
			break;

		/* remove from the waiting list */
		tommy_list_remove_existing(waiting_list, i);
		sncpy(task->exit_msg, sizeof(task->exit_msg), msg);
		task->state = PROCESS_STATE_CANCEL;
		task->unix_start_time = now;
		task->unix_end_time = now;
		log_msg_locked(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));

		/* insert in the history */
		tommy_list_insert_tail(history_list, &task->node, task);

		i = i_next;
	}
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
	{ FILE_CHANGE_DIFF_RESTORE, "restored" },
	{ FILE_CHANGE_RECOVERED, "recovered" },
	{ FILE_CHANGE_UNRECOVERABLE, "unrecoverable" },
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
	struct snapraid_filef* file = void_file;
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
	diff->diff_restored = 0;

	tommy_list_foreach(&diff->file_list, file_free);
	tommy_list_init(&diff->file_list);
}

void diff_move(struct snapraid_diff_stat* diff_src, struct snapraid_diff_stat* diff_dest)
{
	/* clear the destination list */
	tommy_list_foreach(&diff_dest->file_list, file_free);

	*diff_dest = *diff_src;

	/* reset the list */
	tommy_list_init(&diff_src->file_list);

	diff_src->diff_equal = diff_dest->diff_equal;
	diff_src->diff_equal += diff_dest->diff_added;
	diff_src->diff_equal += diff_dest->diff_updated;
	diff_src->diff_equal += diff_dest->diff_moved;
	diff_src->diff_equal += diff_dest->diff_copied;
	diff_src->diff_equal += diff_dest->diff_restored;
	diff_src->diff_added = 0;
	diff_src->diff_removed = 0;
	diff_src->diff_updated = 0;
	diff_src->diff_moved = 0;
	diff_src->diff_copied = 0;
	diff_src->diff_restored = 0;
}

/****************************************************************************/
/* diff */

static int fix_compare(const void* void_a, const void* void_b)
{
	const struct snapraid_file* a = void_a;
	const struct snapraid_file* b = void_b;
	int ret = strcmp(a->disk, b->disk);
	if (ret != 0)
		return ret;
	return strcmp(a->path, b->path);
}

void fix_cleanup(struct snapraid_fix_stat* fix)
{
	fix->fix_recovered = 0;
	fix->fix_unrecoverable = 0;

	tommy_list_foreach(&fix->file_list, file_free);
	tommy_list_init(&fix->file_list);
}

void fix_accumulate(tommy_list* fix_src, struct snapraid_fix_stat* fix_dest)
{
	/* assume dest is alreay sorted */
	tommy_list_sort(fix_src, fix_compare);

	fix_dest->fix_recovered = 0;
	fix_dest->fix_unrecoverable = 0;

	tommy_node* i = tommy_list_head(fix_src);
	tommy_node* j = tommy_list_head(&fix_dest->file_list);
	while (i) {
		struct snapraid_file* src = i->data;

		/* end of the destination list */
		if (j == 0) {
			/* insert at the end of the dest */
			struct snapraid_file* dup = file_dup(src);
			if (dup->change == FILE_CHANGE_RECOVERED)
				++fix_dest->fix_recovered;
			if (dup->change == FILE_CHANGE_UNRECOVERABLE)
				++fix_dest->fix_unrecoverable;
			tommy_list_insert_tail(&fix_dest->file_list, &dup->node, dup);
			i = i->next;
			continue;
		}

		struct snapraid_file* dst = j->data;

		int cmd = fix_compare(i->data, j->data);
		if (cmd > 0) {
			if (dst->change == FILE_CHANGE_RECOVERED)
				++fix_dest->fix_recovered;
			if (dst->change == FILE_CHANGE_UNRECOVERABLE)
				++fix_dest->fix_unrecoverable;

			/* next dest */
			j = j->next;
			continue;
		}

		if (cmd < 0) {
			/* file is missing in dest */
			struct snapraid_file* dup = file_dup(src);
			if (dup->change == FILE_CHANGE_RECOVERED)
				++fix_dest->fix_recovered;
			if (dup->change == FILE_CHANGE_UNRECOVERABLE)
				++fix_dest->fix_unrecoverable;
			tommy_list_insert_before(&fix_dest->file_list, j, &dup->node, dup);
			i = i->next;
			continue;
		}

		/* file is already present in dest */
		if (src->change == FILE_CHANGE_RECOVERED && dst->change == FILE_CHANGE_UNRECOVERABLE)
			dst->change = FILE_CHANGE_RECOVERED; /* now it's recovered */
		if (dst->change == FILE_CHANGE_RECOVERED)
			++fix_dest->fix_recovered;
		if (dst->change == FILE_CHANGE_UNRECOVERABLE)
			++fix_dest->fix_unrecoverable;

		i = i->next;
		j = j->next;
	}
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
	case HEALTH_PENDING : return "pending";
	}

	return "-";
}

static int health_worse(int a, int b)
{
	if (a < b)
		return a;
	else
		return b;
}

static int health_device_list(tommy_list* list)
{
	int health = HEALTH_PASSED;

	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_device* device = i->data;
		if (device->error_medium != 0 && device->error_medium != SMART_UNASSIGNED)
			health = health_worse(health, HEALTH_FAILING);
		if (device->error_protocol != 0 && device->error_protocol != SMART_UNASSIGNED)
			health = health_worse(health, HEALTH_PREFAIL);
		health = health_worse(health, device->health);
	}

	return health;
}

int health_disk(struct snapraid_disk* data)
{
	int health = HEALTH_PASSED;

	if (data->error_data != 0)
		health = health_worse(health, HEALTH_PREFAIL);

	if (data->error_io != 0)
		health = health_worse(health, HEALTH_FAILING);

	health = health_worse(health, health_device_list(&data->device_list));

	return health;
}

int health_task(struct snapraid_task* task)
{
	int health = task->health;

	if (task->error_data != 0)
		health = health_worse(health, HEALTH_PREFAIL);

	if (task->error_io != 0)
		health = health_worse(health, HEALTH_FAILING);

	if (task->error_unrecoverable != 0)
		health = health_worse(health, HEALTH_FAILING);

	if (task->block_bad != 0)
		health = health_worse(health, HEALTH_PREFAIL);

	switch (task->state) {
	case PROCESS_STATE_QUEUE :
		health = health_worse(health, HEALTH_PENDING);
		break;
	}

	return health;
}

int health_array(struct snapraid_state* state)
{
	int health = HEALTH_PASSED;

	if (state->global.block_bad != 0)
		health = health_worse(health, HEALTH_PREFAIL);

	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		health = health_worse(health, health_disk(disk));
	}

	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		health = health_worse(health, health_disk(disk));
	}

	return health;
}

double afr_array(struct snapraid_state* state)
{
	double afr = 0;

	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			afr += device->afr;
		}
	}

	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
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

double fp_array(struct snapraid_state* state)
{
	return poisson_prob_at_least_one_failure(afr_array(state));
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

	memcpy(page->path, path, path_len + 1);

	return page;
}

void page_free(void* void_page)
{
	struct snapraid_page* page = void_page;
	free(page);
}

