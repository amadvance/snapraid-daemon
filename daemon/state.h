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

#ifndef __STATE_H
#define __STATE_H

#include "../tommyds/tommylist.h"
#include "../civetweb/civetweb.h"

/* string list typedef for string lists */
typedef tommy_list sl_t;

/**
 * Max disk name length
 */
#define DISK_MAX 128

/**
 * Max UUID length.
 */
#define UUID_MAX 128

/**
 * Standard SMART attributes.
 */
#define SMART_REALLOCATED_SECTOR_COUNT 5
#define SMART_UNCORRECTABLE_ERROR_CNT 187
#define SMART_COMMAND_TIMEOUT 188
#define SMART_CURRENT_PENDING_SECTOR 197
#define SMART_OFFLINE_UNCORRECTABLE 198
#define SMART_START_STOP_COUNT 4
#define SMART_POWER_ON_HOURS 9
#define SMART_AIRFLOW_TEMPERATURE_CELSIUS 190
#define SMART_LOAD_CYCLE_COUNT 193
#define SMART_TEMPERATURE_CELSIUS 194

/**
 * SMART attributes count.
 */
#define SMART_COUNT 256

/**
 * Flags returned by smartctl.
 */
#define SMARTCTL_FLAG_UNSUPPORTED (1 << 0) /**< Device not recognized, requiring the -d option. */
#define SMARTCTL_FLAG_OPEN (1 << 1) /**< Device open or identification failed. */
#define SMARTCTL_FLAG_COMMAND (1 << 2) /**< Some SMART or ATA commands failed. This is a common error, also happening with full info gathering. */
#define SMARTCTL_FLAG_FAIL (1 << 3) /**< SMART status check returned "DISK FAILING". */
#define SMARTCTL_FLAG_PREFAIL (1 << 4) /**< We found prefail Attributes <= threshold. */
#define SMARTCTL_FLAG_PREFAIL_LOGGED (1 << 5) /**< SMART status check returned "DISK OK" but we found that some (usage or prefail) Attributes have been <= threshold at some time in the past. */
#define SMARTCTL_FLAG_ERROR (1 << 6) /**< The device error log contains records of errors. */
#define SMARTCTL_FLAG_ERROR_LOGGED (1 << 7) /**< The device self-test log contains records of errors. */

/**
 * SMART max attribute length.
 */
#define SMART_MAX 64

/**
 * Value for unassigned SMART attribute.
 */
#define SMART_UNASSIGNED 0xFFFFFFFFFFFFFFFFULL

/**
 * Power mode
 */
#define POWER_PENDING 0
#define POWER_STANDBY -1
#define POWER_ACTIVE 1

/**
 * Health
 */
#define HEALTH_PENDING 0
#define HEALTH_PASSED 1
#define HEALTH_FAILING -1

/**
 * Device info entry.
 */
struct snapraid_device {
	char file[PATH_MAX]; /**< File device. */
	char serial[SMART_MAX]; /**< Serial number. */
	char family[SMART_MAX]; /**< Vendor and model family. */
	char model[SMART_MAX]; /**< Model. */
	uint64_t smart[SMART_COUNT]; /**< SMART attributes. */
	uint64_t size;
	uint64_t rotational;
	uint64_t error_protocol;
	uint64_t error_medium;
	uint64_t wear_level;
	uint64_t flags; /**< Smartctl flags */
	double afr; /**< Estimated annual failure rate (the average number of failures you expect in a year) */
	double prob; /**< Estimated probability of failure (the probability of at least one failure in the next year) */
	int power; /**< POWER mode. */
	int health; /**< HEALTH code. */
	tommy_node node;
};

struct snapraid_data {
	char name[DISK_MAX]; /**< Name of the disk. */
	char dir[PATH_MAX]; /**< Mount point */
	char uuid[UUID_MAX]; /**< Current UUID. */
	char content_uuid[UUID_MAX]; /**< UUID stored in the content file. */
	tommy_list device_list; /**< List of snapraid_device */
	uint64_t content_size; /**< Size of the disk stored in the content file. */
	uint64_t content_free; /**< Free size of the disk stored in the content file. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	uint64_t error_io; /**< Accumulator of all I/O errors encountered. */
	uint64_t error_data; /**< Accumulator of all silent data errors encountered. */
	tommy_node node;
};

struct snapraid_split {
	int index; /**< Index of the split */
	char path[PATH_MAX]; /**< Parity file */
	char uuid[UUID_MAX]; /**< Current UUID. */
	char content_path[PATH_MAX]; /**< Parity file stored in the content file. */
	char content_uuid[UUID_MAX]; /**< UUID stored in the content file. */
	tommy_list device_list; /**< List of snapraid_device */
	uint64_t content_size; /**< Size of the parity file stored in the content file. */
	tommy_node node;
};

struct snapraid_parity {
	char name[DISK_MAX]; /**< Name of the parity. */
	tommy_list split_list; /**< List of snapraid_split */
	uint64_t content_size; /**< Size of the disk stored in the content file. */
	uint64_t content_free; /**< Free size of the disk stored in the content file. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	uint64_t error_io; /**< Accumulator of all I/O errors encountered. */
	uint64_t error_data; /**< Accumulator of all silent data errors encountered. */
	tommy_node node;
};

#define CMD_PROBE 1
#define CMD_UP 2
#define CMD_DOWN 3
#define CMD_SMART 4
#define CMD_STATUS 5
#define CMD_LIST 6
#define CMD_DIFF 7
#define CMD_DUP 8
#define CMD_DEVICES 9
#define CMD_SYNC 10
#define CMD_SCRUB 11
#define CMD_FIX 12
#define CMD_CHECK 13
#define CMD_REPORT 100 /**< Generate a notification report */

#define PROCESS_STATE_QUEUE 0 /**< The process is queued */
#define PROCESS_STATE_START 1 /**< The process is starting */
#define PROCESS_STATE_RUN 2 /**< The task sent a "begin"/"pos" log telling its progress */
#define PROCESS_STATE_SIGNAL 3 /**< The task sent a "signal" log (running!=0) or it's signaled (running==0) and exit_sig has the signal */
#define PROCESS_STATE_TERM 4 /**< The task set a "end" log (running!=0) or it's terminated (running==0) and exit_code has the status code */
#define PROCESS_STATE_CANCEL 5 /**< The task is canceled */

#define HISTORY_PAST_DAYS 30 /**< Number of days the history is kept */
#define SECONDS_IN_A_DAY (24 * 3600)

struct snapraid_task {
	char log_file[PATH_MAX]; /**< Log file of the task. */
	int cmd; /**< The command running */
	int number; /**< Number of the task. It's an increasing number. */
	int running; /**< If the command is running or finished */
	int state; /**< one of PROCESS_STATE_* */
	int64_t unix_queue_time; /**< Unix time of when the task was queued */
	int64_t unix_start_time; /**< Unix time of when the task was started */
	int64_t unix_end_time; /**< Unix time of when the task terminated */
	unsigned progress; /**< Completion percentage, 0 <= progress <= 100 */
	unsigned eta_seconds; /**< Estimate seconds for the end */
	unsigned speed_mbs; /**< Processing speed in MBytes/s */
	unsigned cpu_usage; /**< CPU occupation in percentage, 0 <= cpu_usage <= 100. */
	unsigned elapsed_seconds; /**< Number of seconds elapsed from the begin of the process. */
	unsigned block_begin; /**< First block to be processed */
	unsigned block_end; /**< Latest block +1 to be processed */
	unsigned block_count; /**< Number of blocks to be processed, it may be less than end - begin */
	unsigned block_idx; /**< Block currently processed. block_begin <= processed_block < block_end */
	unsigned block_done; /**< Incremental number of block processed. 0 <= block_done < block_count */
	uint64_t size_done; /**< Number of bytes processed until now */
	pid_t pid; /**< Process ID of the running task */
	int exit_code; /**< Exit code. Valid only for PROCESS_STATE_TERM */
	int exit_sig; /**< Signal code. Valid only for PROCESS_STATE_SIGNAL */
	char exit_msg[128]; /** Exit message. Valid only for PROCESS_STATE_CANCEL */
	sl_t arg_list; /**< List of arguments */
	sl_t message_list; /**< List of messages */
	sl_t error_list; /**< List of error messages */
	tommy_node node;

	/* error stats */
	uint64_t hash_error_soft; /**< Total software errors during hashing phase (sync only). */
	uint64_t error_soft; /**< Total software errors encountered. */
	uint64_t error_io; /**< Total I/O errors encountered. */
	uint64_t error_data; /**< Total silent data errors encountered (sync/scrub only). */
	uint64_t block_bad; /**< Total blocks marked as bad (status only). */
	char exit_status[32]; /**< Exit status: ok/warning/error. */
};

struct snapraid_runner {
	thread_cond_t cond;
	thread_id_t thread_id;
	int number_allocator; /**< Allocator of number of tasks */
	struct snapraid_task* latest; /**< Task running, or latest one finished */
	tommy_list waiting_list; /**< List of snapraid_task waiting to be executed */
	tommy_list history_list; /**< List of snapraid_task already executed */
};

struct snapraid_scheduler {
	thread_cond_t cond;
	thread_id_t thread_id;
};

#define DIFF_CHANGE_ADD 1 /**< A new file or link was found that is not in the content file. */
#define DIFF_CHANGE_REMOVE 2 /**< A file or link has been removed from the filesystem since the last sync. */
#define DIFF_CHANGE_UPDATE 3 /**< A file or link has been updated (size, timestamp, or link target changed). */
#define DIFF_CHANGE_MOVE 4 /**< A file was moved on the same disk. */
#define DIFF_CHANGE_COPY 5 /**< A new file was found to be a copy of a file from another disk. */
#define DIFF_CHANGE_RESTORE 6 /**< A file's inode has changed but not its date-time and size, which suggests the file may be restored from backup. */

struct snapraid_diff {
	char path[PATH_MAX]; /**< Path of the file */
	char source_path[PATH_MAX]; /**< Path of the source/old file, valid only if reason == DIFF_REASON_MOVE or DIFF_REASON_COPY */
	char disk[DISK_MAX]; /**< Name of the disk */
	char source_disk[DISK_MAX]; /**< Name of the source disk, valid only if reason == DIFF_REASON_MOVE or DIFF_REASON_COPY */
	int change; /**< One of the DIFF_CHANGE_* */
	tommy_node node;
};

struct snapraid_global {
	char version[64]; /**< SnapRAID version. */
	int version_major;
	int version_minor;
	char conf_engine[PATH_MAX]; /**< Configuration file of the SnapRAID engine. */
	char content[PATH_MAX]; /**< Content file. */
	unsigned blocksize; /**< Block size */
	int64_t last_time; /**< Time of the latest command */
	char last_cmd[64]; /**< Last command started */

	double afr; /**< Estimated annual failure rate (the average number of failures you expect in a year) */
	double prob; /**< Estimated probability of failure (the probability of at least one failure in the next year) */

	int64_t sync_time; /**< Time of the last sync run. If 0 never run. */
	int64_t scrub_time; /**< Time of the last scrub run. If 0 never run. */
	int64_t diff_time; /**< Time of the last diff run. If 0 never run. */
	int64_t status_time; /**< Time of the last status run. If 0 never run. */

	/* info counters. Updated in sync/scrub */
	uint64_t file_total; /**< Total file count in the array as stored in the content file */
	uint64_t block_bad; /**< Total blocks marked as bad */
	uint64_t block_rehash; /**< Total blocks marked as bad */
	uint64_t block_total; /**< Total blocks */

	/* diff counters. Updated in diff and sync */
	int64_t diff_equal; /**< Comparison of the content state with the real state of the array */
	int64_t diff_added;
	int64_t diff_removed;
	int64_t diff_updated;
	int64_t diff_moved;
	int64_t diff_copied;
	int64_t diff_restored;

	tommy_list diff_list; /**< List of snapraid_diff entries */ 
};

#define CONFIG_MAX 512 /**< Max length of a configuration option */

#define RUN_DISABLED 0
#define RUN_DAILY 1
#define RUN_WEEKLY 7

#define LVL_CRITICAL 0
#define LVL_ERROR 1
#define LVL_WARNING 2
#define LVL_INFO 3

#define CONFIG_LINE_MAX 1024

struct snapraid_config_line {
	char text[CONFIG_LINE_MAX];
	tommy_node node;
};

struct snapraid_config {
	char conf[PATH_MAX]; /**< Configuration file of the daemon. */
	tommy_list line_list; /**< List of snapraid_config_line */
	/* empty string or 0 value means value not set and/or disabled */
	int net_enabled;
	char net_port[CONFIG_MAX];
	char net_acl[CONFIG_MAX];
	int schedule_run;
	int schedule_hour;
	int schedule_minute;
	int schedule_day_of_week;
	int sync_threshold_deletes;
	int sync_threshold_updates;
	int sync_prehash;
	int sync_force_zero;
	int scrub_percentage;
	int scrub_older_than;
	int probe_interval_minutes;
	int spindown_idle_minutes;
	char script_pre_run[CONFIG_MAX];
	char script_post_run[CONFIG_MAX];
	char script_run_as_user[CONFIG_MAX];
	char log_directory[CONFIG_MAX];
	int log_retention_days;
	int notify_syslog_enabled;
	int notify_syslog_level;
	char notify_heartbeat[CONFIG_MAX];
	char notify_result[CONFIG_MAX];
	int notify_result_level;
	char notify_email_recipient[CONFIG_MAX];
	int notify_email_level;
	char notify_run_as_user[CONFIG_MAX];
	int notify_differences;
};

#define DAEMON_QUIT 0
#define DAEMON_RUNNING 1
#define DAEMON_RELOAD 2

struct snapraid_state {
	volatile int daemon_running; /**< If the daemon is running or terminating */
	volatile int daemon_sig; /**< Signal received by the daemon that made it stopping */
	thread_mutex_t lock; /**< Main lock for accessing the state */
	struct mg_context* rest_context; /**< The context of the rest support */
	struct mg_callbacks rest_callbacks;
	struct snapraid_runner runner;
	struct snapraid_scheduler scheduler;
	struct snapraid_global global;
	struct snapraid_config config;
	tommy_list data_list;
	tommy_list parity_list;
};

/**
 * Initialize the global state system.
 */
void state_init(void);

/**
 * Cleanup the global state system.
 */
void state_done(void);

/**
 * Get pointer to the global snapraid state.
 * @return Pointer to global state structure
 */
struct snapraid_state* state_ptr(void);

/**
 * Acquire lock for accessing the state.
 */
void state_lock(void);

/**
 * Release lock for accessing the state.
 */
void state_unlock(void);

#endif

