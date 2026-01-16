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
	switch (cmd) {
	case CMD_PROBE : return "probe";
	case CMD_UP : return "up";
	case CMD_DOWN : return "down";
	case CMD_SMART : return "smart";
	case CMD_STATUS : return "status";
	case CMD_LIST : return "list";
	case CMD_DIFF : return "diff";
	case CMD_SYNC : return "sync";
	case CMD_SCRUB : return "scrub";
	case CMD_FIX : return "fix";
	case CMD_CHECK : return "check";
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

void task_free(struct snapraid_task* task)
{
	if (!task)
		return;
	sl_free(&task->arg_list);
	sl_free(&task->message_list);
	sl_free(&task->error_list);
	free(task);
}

void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list)
{
	for (tommy_node* i = tommy_list_head(waiting_list); i != 0; i = i->next) {
		struct snapraid_task* task = i->data;
		task->state = PROCESS_STATE_CANCEL;
		log_msg_lock(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));
		tommy_list_insert_tail(history_list, &task->node, task);
	}
	tommy_list_init(waiting_list);
}
