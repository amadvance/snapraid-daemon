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
/* task */

struct snapraid_task* task_alloc(void)
{
	struct snapraid_task* task = calloc_nofail(1, sizeof(struct snapraid_task));
	sl_init(&task->arg_list);
	sl_init(&task->message_list);
	task->health = HEALTH_PASSED;
	return task;
}

void task_free(void* void_task)
{
	struct snapraid_task* task = void_task;
	if (!task)
		return;
	sl_free(&task->arg_list);
	sl_free(&task->message_list);
	sl_free(&task->error_list);
	free(task->text_report);
	free(task);
}

void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list, const char* msg)
{
	time_t now = time(0);
	for (tommy_node* i = tommy_list_head(waiting_list); i != 0; i = i->next) {
		struct snapraid_task* task = i->data;
		sncpy(task->exit_msg, sizeof(task->exit_msg), msg);
		task->state = PROCESS_STATE_CANCEL;
		task->unix_start_time = now;
		task->unix_end_time = now;
		log_msg_lock(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));
		tommy_list_insert_tail(history_list, &task->node, task);
	}
	tommy_list_init(waiting_list);
}

/****************************************************************************/
/* diff */

struct {
	int change;
	const char* str;
} CHANGES[] = {
	{ DIFF_CHANGE_ADD, "added" },
	{ DIFF_CHANGE_REMOVE, "removed" },
	{ DIFF_CHANGE_UPDATE, "updated" },
	{ DIFF_CHANGE_MOVE, "moved" },
	{ DIFF_CHANGE_COPY, "copied" },
	{ DIFF_CHANGE_RESTORE, "restored" },
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

struct snapraid_diff* diff_alloc(int change, const char* disk, const char* path)
{
	return diff_alloc_source(change, disk, path, 0, 0);
}

struct snapraid_diff* diff_alloc_source(int change, const char* disk, const char* path, const char* source_disk, const char* source_path)
{
	ssize_t disk_len = strlen(disk);
	ssize_t path_len = strlen(path);
	ssize_t source_disk_len = source_disk ? strlen(source_disk) : 0;
	ssize_t source_path_len = source_path ? strlen(source_path) : 0;

	struct snapraid_diff* diff = malloc_nofail(sizeof(struct snapraid_diff) + disk_len + path_len + source_disk_len + source_path_len + 4);
	diff->change = change;
	diff->disk = diff->str;
	diff->path = diff->disk + disk_len + 1;
	diff->source_disk = diff->path + path_len + 1;
	diff->source_path = diff->source_disk + source_disk_len + 1;

	memcpy(diff->disk, disk, disk_len + 1);
	memcpy(diff->path, path, path_len + 1);
	if (source_disk)
		memcpy(diff->source_disk, source_disk, source_disk_len + 1);
	else
		diff->source_disk[0] = 0;
	if (source_path)
		memcpy(diff->source_path, source_path, source_path_len + 1);
	else
		diff->source_path[0] = 0;

	return diff;
}

void diff_free(void* void_diff)
{
	struct snapraid_diff* diff = void_diff;
	free(diff);
}

void diff_cleanup(struct snapraid_diff_stat* diff)
{
	diff->diff_equal = 0;
	diff->diff_added = 0;
	diff->diff_removed = 0;
	diff->diff_updated = 0;
	diff->diff_moved = 0;
	diff->diff_copied = 0;
	diff->diff_restored = 0;

	tommy_list_foreach(&diff->diff_list, diff_free);
}

void diff_push(struct snapraid_diff_stat* diff_current, struct snapraid_diff_stat* diff_pre)
{
	/* clear the previous list */
	tommy_list_foreach(&diff_pre->diff_list, diff_free);

	*diff_pre = *diff_current;

	/* reset the list */
	tommy_list_init(&diff_current->diff_list);

	diff_current->diff_equal = diff_pre->diff_equal;
	diff_current->diff_equal += diff_pre->diff_added;
	diff_current->diff_equal -= diff_pre->diff_removed;
	diff_current->diff_equal += diff_pre->diff_updated;
	diff_current->diff_equal += diff_pre->diff_moved;
	diff_current->diff_equal += diff_pre->diff_copied;
	diff_current->diff_equal += diff_pre->diff_restored;
	diff_current->diff_added = 0;
	diff_current->diff_removed = 0;
	diff_current->diff_updated = 0;
	diff_current->diff_moved = 0;
	diff_current->diff_copied = 0;
	diff_current->diff_restored = 0;
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

