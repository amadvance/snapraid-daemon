// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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

/**
 * Get the string representation of a command.
 * @param cmd Command ID (one of CMD_*)
 * @return Command name string
 */
const char* command_name(int cmd);

/****************************************************************************/
/* disk/split/device */

/**
 * Allocate a disk entry
 */
struct snapraid_disk* disk_alloc(const char* name, int kind);

/**
 * Free a disk entry and its associated device and split lists.
 * @param void_disk Pointer to the disk entry
 */
void disk_free(void* void_disk);

/**
 * Count the number of disks of the specified kind.
 */
int disk_count(tommy_list* list, int kind);

/**
 * Free a device entry.
 * @param void_device Pointer to the device entry
 */
void device_free(void* void_device);

/**
 * Free a split entry.
 * @param void_split Pointer to the split entry
 */
void split_free(void* void_split);

/****************************************************************************/
/* message */

/**
 * Allocate and initialize a new message.
 * @param level Logging level
 * @param type Message type
 * @param msg Message text
 * @return Pointer to newly allocated message
 */
struct snapraid_message* message_alloc(int level, int type, const char* msg);

/**
 * Free a message entry.
 * @param void_message Pointer to the message entry
 */
void message_free(void* void_message);

/**
 * Insert a message into a message list.
 * @param list Destination message list
 * @param level Logging level
 * @param type Message type
 * @param msg Message text
 */
void message_insert(tommy_list* list, int level, int type, const char* msg);

/****************************************************************************/
/* run */

/**
 * Allocate and initialize a new run.
 * @return Pointer to newly allocated run
 */
struct snapraid_run* run_alloc(int day_of_week, int hour, int minute);

/**
 * Duplicate a run
 */
struct snapraid_run* run_dup(struct snapraid_run* run);

/**
 * Free a run.
 * @param void_run Pointer to the run entry
 */
void run_free(void* void_run);

/****************************************************************************/
/* association */

/**
 * Allocate and initialize a new association.
 * @return Pointer to newly allocated association
 */
struct snapraid_association* association_alloc(const char* file, const char* id);

/**
 * Free a association.
 * @param void_association Pointer to the association entry
 */
void association_free(void* void_association);

/****************************************************************************/
/* task */

/**
 * Allocate and initialize a new task.
 * @return Pointer to newly allocated task
 */
struct snapraid_task* task_alloc(void);

/**
 * Free a task and its associated message and fix lists.
 * @param void_task Pointer to the task entry
 */
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

/**
 * Set the start time ensuring uniquiness.
 */
void task_set_unique_start_time(struct snapraid_state* state, struct snapraid_task* task, time_t now);

/****************************************************************************/
/* schedule */

/**
 * Allocate a new schedule entry.
 * @return Pointer to newly allocated schedule
 */
struct snapraid_schedule* schedule_alloc(void);

/**
 * Free a schedule entry and its associated arguments.
 * @param void_sched Pointer to the schedule entry
 */
void schedule_free(void* void_sched);

/****************************************************************************/
/* file */

/**
 * Get the string representation of a file change type.
 * @param change Change type ID (one of FILE_CHANGE_*)
 * @return String representation of change type
 */
const char* change_name(int change);

/**
 * Allocate a new file entry for tracking changes.
 * @param reason Change type ID
 * @param disk Name of the disk
 * @param path File path
 * @return Pointer to newly allocated file entry
 */
struct snapraid_file* file_alloc(int reason, const char* disk, const char* path);

/**
 * Duplicate a file entry.
 * @param dup File entry to duplicate
 * @return Pointer to newly allocated copy of the file entry
 */
struct snapraid_file* file_dup(struct snapraid_file* dup);

/**
 * Allocate a new file entry with source information (for moves/copies).
 * @param reason Change type ID
 * @param disk Destination disk name
 * @param path Destination file path
 * @param source_disk Source disk name
 * @param source_path Source file path
 * @return Pointer to newly allocated file entry
 */
struct snapraid_file* file_alloc_source(int reason, const char* disk, const char* path, const char* source_disk, const char* source_path);

/**
 * Free a file entry.
 * @param void_file Pointer to the file entry
 */
void file_free(void* void_file);

/****************************************************************************/
/* diff */

/**
 * Clean up a difference statistics structure, freeing its file list.
 * @param diff Pointer to difference statistics structure
 * @param equal New value for equal files counter
 */
void diff_cleanup(struct snapraid_diff_stat* diff, int64_t equal);

/**
 * Move difference statistics from source to destination.
 * @param diff_src Source difference statistics
 * @param diff_dest Destination difference statistics
 */
void diff_move(struct snapraid_diff_stat* diff_src, struct snapraid_diff_stat* diff_dest);

/****************************************************************************/
/* fix */

/**
 * Clean up a fix statistics structure, freeing its file list.
 * @param fix Pointer to fix statistics structure
 */
void fix_cleanup(struct snapraid_fix_stat* fix);

/**
 * Accumulate fix results from a list into a fix statistics structure.
 * @param fix_src Source list of file entries
 * @param fix_dest Destination fix statistics structure
 */
void fix_accumulate(tommy_list* fix_src, struct snapraid_fix_stat* fix_dest);

/****************************************************************************/
/* bucket */

/**
 * Allocate a new bucket entry for scrub statistics.
 * @param time_at Timestamp
 * @param count_scrubbed Number of blocks scrubbed
 * @param count_justsynced Number of blocks just synced
 * @return Pointer to newly allocated bucket
 */
struct snapraid_bucket* bucket_alloc(uint64_t time_at, uint64_t count_scrubbed, uint64_t count_justsynced);

/**
 * Free a bucket entry.
 * @param void_bucket Pointer to the bucket entry
 */
void bucket_free(void* void_bucket);

/**
 * Clean up a list of buckets.
 * @param bucket List of buckets to clean up
 */
void bucket_cleanup(tommy_list* bucket);

/**
 * Move buckets from source to destination.
 * @param bucket_src Source list
 * @param bucket_dest Destination list
 */
void bucket_move(tommy_list* bucket_src, tommy_list* bucket_dest);

/****************************************************************************/
/* health */

/**
 * Get the string representation of a power state.
 * @param power Power state ID
 * @return String representation
 */
const char* power_name(int power);

/**
 * Get the string representation of a health status.
 * @param health Health status ID
 * @return String representation
 */
const char* health_name(int health);

/**
 * Determine health status for a task result.
 * @param task Completed task
 * @return Health status ID
 */
int health_task(struct snapraid_task* task);

/**
 * Analyze disk health and return health status.
 * @param disk Disk to analyze
 * @param reason Buffer to store health reason
 * @param reason_size Size of reason buffer
 * @return Health status ID
 */
int health_disk(struct snapraid_disk* disk, char* reason, size_t reason_size);

/**
 * Analyze overall array health.
 * @param state Current snapraid state
 * @param reason Buffer to store health reason
 * @param reason_size Size of reason buffer
 * @return Health status ID
 */
int health_array(struct snapraid_state* state, char* reason, size_t reason_size);

/**
 * Calculate Annual Failure Rate (AFR) for the array.
 * @param state Current snapraid state
 * @return AFR value
 */
double afr_array(struct snapraid_state* state);

/**
 * Calculate failure probability for the array.
 * @param state Current snapraid state
 * @return Failure probability (0.0 to 1.0)
 */
double fp_array(struct snapraid_state* state);

/****************************************************************************/
/* temperature */

/**
 * Allocate a new temperature record.
 * @param temperature Temperature in Celsius
 * @param time_at Timestamp
 * @return Pointer to newly allocated record
 */
struct snapraid_temp* temperature_alloc(int temperature, time_t time_at);

/**
 * Free a temperature record.
 * @param void_temp Pointer to the record
 */
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

/**
 * Initialize a tracked metric.
 * @param tracked Metric to initialize
 */
void tracked_init(struct snapraid_tracked* tracked);

/**
 * Update a tracked metric with new value.
 * @param tracked Metric to update
 * @param old Previous value
 * @param kind Metric kind
 * @param last_time Current timestamp
 */
void tracked_update(struct snapraid_tracked* tracked, uint64_t old, int kind, int64_t last_time);

/****************************************************************************/
/* page */

struct snapraid_page {
	tommy_node node;
	char* path; /**< The URL path (e.g., /index.html) */
	char* content; /**< File buffer */
	ssize_t size; /**< File size */
	const char* mime_type; /**< MIME type */
	int is_static; /**< Page is static and will have relaxed headers */
	char str[];
};

/**
 * Allocate and initialize a new web page entry.
 * @param path URL path
 * @param content_size Size of file content
 * @return Pointer to newly allocated page
 */
struct snapraid_page* page_alloc(const char* path, size_t content_size);

/**
 * Free a web page entry.
 * @param void_page Pointer to the page entry
 */
void page_free(void* void_page);

#endif

