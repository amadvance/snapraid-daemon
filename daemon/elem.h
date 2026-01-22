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

#ifndef __ELEM_H
#define __ELEM_H

#include "state.h"

/****************************************************************************/
/* command */

/**
 * Parse a command str
 * @return One of CMD_* or 0 if not found
 */
int command_parse(const char* str);

const char* command_name(int cmd);

/****************************************************************************/
/* task */

struct snapraid_task* task_alloc(void);
void task_free(void* void_task);

/**
 * Move all the tasks in the history list
 */
void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list, const char* msg);

/****************************************************************************/
/* diff */

const char* change_name(int change);

struct snapraid_diff* diff_alloc(int reason, const char* disk, const char* path);
struct snapraid_diff* diff_alloc_source(int reason, const char* disk, const char* path, const char* source_disk, const char* source_path);
void diff_free(void* void_diff);

/****************************************************************************/
/* health */

const char* power_name(int power);
const char* health_name(int health);
int health_disk(struct snapraid_disk* disk);
int health_task(struct snapraid_task* task);
int health_array(struct snapraid_state* state);

#endif

