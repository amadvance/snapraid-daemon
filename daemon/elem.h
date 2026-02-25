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
/* disk/split/device */

void disk_free(void* void_disk);
void device_free(void* void_device);
void split_free(void* void_split);

/****************************************************************************/
/* message */

struct snapraid_message* message_alloc(int level, int type, const char* msg);
void message_free(void* void_message);
void message_insert(tommy_list* list, int level, int type, const char* msg);

/****************************************************************************/
/* task */

struct snapraid_task* task_alloc(void);
void task_free(void* void_task);

/**
 * Check if the task failed.
 */
int task_success(struct snapraid_task* task);

/**
 * Cancel tasks and move in the history list. Stop at the first REPORT tasks
 */
void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list, const char* msg);

/**
 * Get the info level of the task from it's result
 * @return One of LVL_* defines.
 */
int task_level(struct snapraid_task* task);

/****************************************************************************/
/* schedule */

struct snapraid_schedule* schedule_alloc(void);
void schedule_free(void* void_sched);

/****************************************************************************/
/* file */

const char* change_name(int change);

struct snapraid_file* file_alloc(int reason, const char* disk, const char* path);
struct snapraid_file* file_dup(struct snapraid_file* dup);
struct snapraid_file* file_alloc_source(int reason, const char* disk, const char* path, const char* source_disk, const char* source_path);
void file_free(void* void_file);

/****************************************************************************/
/* diff */

void diff_cleanup(struct snapraid_diff_stat* diff, int64_t equal);
void diff_move(struct snapraid_diff_stat* diff_src, struct snapraid_diff_stat* diff_dest);

/****************************************************************************/
/* fix */

void fix_cleanup(struct snapraid_fix_stat* fix);
void fix_accumulate(tommy_list* fix_src, struct snapraid_fix_stat* fix_dest);

/****************************************************************************/
/* bucket */

struct snapraid_bucket* bucket_alloc(uint64_t time_at, uint64_t count_scrubbed, uint64_t count_justsynced);
void bucket_free(void* void_bucket);

void bucket_cleanup(tommy_list* bucket);
void bucket_move(tommy_list* bucket_src, tommy_list* bucket_dest);

/****************************************************************************/
/* health */

const char* power_name(int power);
const char* health_name(int health);
int health_task(struct snapraid_task* task);
int health_disk(struct snapraid_disk* disk, char* reason, size_t reason_size);
int health_array(struct snapraid_state* state, char* reason, size_t reason_size);
double afr_array(struct snapraid_state* state);
double fp_array(struct snapraid_state* state);

/****************************************************************************/
/* temperature */

struct snapraid_temp* temperature_alloc(int temperature, time_t time_at);
void temperature_free(void* void_temp);

/**
 * Insert a new temperature entry for the specific device
 */
void temperature_insert(struct snapraid_device* device, struct snapraid_temp* temp);

/**
 * Cleanup temperature that are too old for the specific device
 */
int temperature_cleanup(struct snapraid_device* device, time_t last_time);

/**
 * * Cleanup temperature that are too old all devices
 */
int temperature_cleanup_devices(struct snapraid_state* state, time_t last_time);

/****************************************************************************/
/* tracked */

void tracked_init(struct snapraid_tracked* tracked);
void tracked_update(struct snapraid_tracked* tracked, uint64_t old, uint64_t mask, int64_t last_time);

/****************************************************************************/
/* page */

struct snapraid_page {
	tommy_node node;
	char* path; /**< The URL path (e.g., /index.html) */
	char* content; /**< File buffer */
	ssize_t size; /**< File size */
	const char* mime_type; /**< MIME type */
	char str[];
};

struct snapraid_page* page_alloc(const char* path, size_t content_size);
void page_free(void* void_page);

#endif

