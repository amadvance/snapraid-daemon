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
	struct snapraid_diff* diff = malloc_nofail(sizeof(struct snapraid_diff));
	diff->change = change;
	sncpy(diff->disk, sizeof(diff->disk), disk);
	sncpy(diff->path, sizeof(diff->path), path);
	diff->source_disk[0] = 0;
	diff->source_path[0] = 0;
	return diff;
}

struct snapraid_diff* diff_alloc_source(int change, const char* disk, const char* path, const char* source_disk, const char* source_path)
{
	struct snapraid_diff* diff = diff_alloc(change, disk, path);
	if (source_disk)
		sncpy(diff->source_disk, sizeof(diff->source_disk), source_disk);
	if (source_path)
		sncpy(diff->source_path, sizeof(diff->source_path), source_path);
	return diff;
}

void diff_free(void* void_diff)
{
	struct snapraid_diff* diff = void_diff;
	free(diff);
}


