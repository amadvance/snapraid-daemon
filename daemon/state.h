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
 * Exit code of the engine if differences are detected
 **/
#define EXIT_NEED_SYNC 2

/**
 * Max disk name length
 */
#define DISK_MAX 128

/**
 * Max UUID length.
 */
#define UUID_MAX 128

/**
 * Max filesystem type/label length
 */

#define FSINFO_MAX 64

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
#define SMARTCTL_FLAG_ERROR_LOGGED (1 << 6) /**< The device error log contains records of errors. */
#define SMARTCTL_FLAG_SELFERROR_LOGGED (1 << 7) /**< The device self-test log contains records of errors. */

/**
 * SMART max attribute length.
 */
#define SMART_MAX 64

/**
 * Value for unassigned SMART attribute.
 */
#define SMART_UNASSIGNED 0xFFFFFFFFFFFFFFFFULL


/**
 * Check if a SMART attribute needs the pulse.
 */
int is_smart_pulse(int index, const char* name);

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
#define HEALTH_PREFAIL -1
#define HEALTH_FAILING -2

/**
 * Pulse masks
 */
#define PULSE_ARRAY 1
#define PULSE_CONFIG 2
#define PULSE_DISKS 4
#define PULSE_TASKS 8
#define PULSE_ACTIVITY 16
#define PULSE_ALL (PULSE_ARRAY | PULSE_CONFIG | PULSE_DISKS | PULSE_TASKS | PULSE_ACTIVITY)

/**
 * Pulse
 */
struct snapraid_pulse {
	uint64_t array; /**< State counter for the "array" entry point */
	uint64_t config; /**< State counter for the "config" entry point */
	uint64_t disks; /**< State counter for the "disks" entry point */
	uint64_t tasks; /**< State counter for the "tasks" entry point */
	uint64_t activity; /**< State counter for the "activity" entry point */
};

/**
 * Temperature
 */
struct snapraid_temp {
	time_t time_at; /**< Time of the measure */
	int temp; /**< Temperature value */
	tommy_node node;
};

/**
 * SMART Attribute flags
 */
#define SMART_ATTR_TYPE_PREFAIL 1
#define SMART_ATTR_TYPE_OLDAGE 2
#define SMART_ATTR_UPDATE_ALWAYS 4
#define SMART_ATTR_UPDATE_OFFLINE 8
#define SMART_ATTR_WHEN_FAILED_NOW 16
#define SMART_ATTR_WHEN_FAILED_PAST 32
#define SMART_ATTR_WHEN_FAILED_NEVER 64

struct smart_attr {
	char name[128]; /**< SMART attribute name. */
	uint64_t raw; /**< SMART attributes raw. */
	uint64_t norm; /**< SMART attributes normalized. */
	uint64_t worst; /**< SMART attributes worst. */
	uint64_t thresh; /**< SMART attributes threshold. */
	int flags; /**< SMART_ATTR_* flags */
};

/**
 * Device info entry.
 */
struct snapraid_device {
	char file[PATH_MAX]; /**< File device. */
	char serial[SMART_MAX]; /**< Serial number. */
	char family[SMART_MAX]; /**< Vendor and model family. */
	char model[SMART_MAX]; /**< Model. */
	char interf[SMART_MAX]; /**< Interface. */
	int64_t smart_time; /**< Time of the latest smart measure */
	struct smart_attr smart[SMART_COUNT]; /**< SMART attributes. */
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
	int split_index; /**< Index of the split */
	tommy_list temp_list; /**< Temperature measures */
	tommy_node node;
};

struct snapraid_split {
	int index; /**< Index of the split */
	char path[PATH_MAX]; /**< Parity file or mount dir */
	char uuid[UUID_MAX]; /**< Current UUID. */
	char content_path[PATH_MAX]; /**< Parity file stored in the content file. */
	char content_uuid[UUID_MAX]; /**< UUID stored in the content file. */
	uint64_t content_size; /**< Size of the parity file stored in the content file. */
	char fstype[FSINFO_MAX]; /**< Filesystem type */
	char fslabel[FSINFO_MAX]; /**< Filesystem label */
	uint64_t fssize; /**< Filesystem total size. At present unused. */
	uint64_t fsfree; /**< Filesystem free size. At present unused. */
	tommy_node node;
};

struct snapraid_disk {
	char name[DISK_MAX]; /**< Name of the disk. */
	uint64_t total_space_bytes; /**< Size of the disk stored in the content file or obtained from the filesystem. */
	uint64_t free_space_bytes; /**< Free size of the disk stored in the content file or obtained from the filesystem. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	uint64_t error_io; /**< Accumulator of all I/O errors encountered. */
	uint64_t error_data; /**< Accumulator of all silent data errors encountered. */

	tommy_list device_list; /**< List of snapraid_device */
	tommy_list split_list; /**< List of snapraid_split */
	tommy_node node;
};

#define CMD_PROBE 1
#define CMD_UP 2
#define CMD_DOWN 3
#define CMD_SMART 4
#define CMD_LIST 5
#define CMD_DIFF 6
#define CMD_DUP 7
#define CMD_SYNC 8
#define CMD_SCRUB 9
#define CMD_FIX 10
#define CMD_CHECK 11
#define CMD_REPORT 101 /**< Additional command that generate a report */
#define CMD_DOWN_IDLE 102 /**< Additional command that spin down inactive disks */
#define CMD_MAINTENANCE 201 /**< High level command. Never enter the queue. */
#define CMD_HEAL 202 /**< High level command. Never enter the queue. */
#define CMD_UNDELETE 203 /**< High level command. Never enter the queue. */
#define CMD_SUSPEND_IDLE 204 /**< High level command. Never enter the queue. */


#define PROCESS_STATE_QUEUE 0 /**< The process is queued */
#define PROCESS_STATE_START 1 /**< The process is starting */
#define PROCESS_STATE_RUN 2 /**< The task sent a "begin"/"pos" log telling its progress */
#define PROCESS_STATE_SIGNAL 3 /**< The task sent a "signal" log (running!=0) or it's signaled (running==0) and exit_sig has the signal */
#define PROCESS_STATE_TERM 4 /**< The task set a "end" log (running!=0) or it's terminated (running==0) and exit_code has the status code */
#define PROCESS_STATE_CANCEL 5 /**< The task is canceled */

#define HISTORY_PAST_DAYS 31 /**< Number of days the history is kept in memory (not affecting log files) */
#define HISTORY_TASKS_MAX 10000 /**< Max number of tasks in the history kept in memory */

#define SECONDS_IN_A_DAY (24 * 3600)

#define MESSAGES_MAX 1000 /**< Max number of messages and errors before stop colleting messages */

#define MESSAGE_LEVEL_FATAL 0
#define MESSAGE_LEVEL_ERROR 1
#define MESSAGE_LEVEL_INFO 2

#define MESSAGE_TYPE_NONE 0
#define MESSAGE_TYPE_SOFTWARE 1
#define MESSAGE_TYPE_HARDWARE 2

struct snapraid_message {
	tommy_node node;
	int level; /**< One of MESSAGE_LEVEL_* */
	int type; /**< One of MESSAGE_TYPE_* */
	char msg[]; /**< The text message */
};

struct snapraid_task {
	char log_file[PATH_MAX]; /**< Log file of the task. */
	int cmd; /**< The command running */
	int high_cmd; /**< The high command generating this tasks. 0 if none. */
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
	int arg_custom; /**< If it's a custom argument list. It's the position of the first custom argument */
	tommy_list message_list; /**< List of snapraid_message */
	int message_list_count; /**< Count of messages, just to limit the number. */
	tommy_list fix_list; /**< List of recovered/recoverable/unrecoverable snapraid_file */

	char* text_report; /**< for CMD_REPORT it's the final text report */

	/* error stats */
	int health; /**< Health of the array after the task. */
	uint64_t hash_error_soft; /**< Total software errors during hashing phase (sync only). */
	uint64_t error_soft; /**< Total software errors encountered (sync/scrub only). */
	uint64_t error_io; /**< Total I/O errors encountered (sync/scrub only). */
	uint64_t error_data; /**< Total silent data errors encountered (sync/scrub only). */
	uint64_t error_recovered; /**< Total error recovered (fix only). */
	uint64_t error_unrecoverable; /**< Total error unrecoverable (fix only). */
	uint64_t block_bad; /**< Total blocks marked as bad (status/sync/scrub only). */

	tommy_node node;
};

struct snapraid_schedule {
	int cmd;
	sl_t args;
	tommy_node node;
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

#define FILE_CHANGE_DIFF_ADD 1 /**< A new file or link was found that is not in the content file. */
#define FILE_CHANGE_DIFF_REMOVE 2 /**< A file or link has been removed from the filesystem since the last sync. */
#define FILE_CHANGE_DIFF_UPDATE 3 /**< A file or link has been updated (size, timestamp, or link target changed). */
#define FILE_CHANGE_DIFF_MOVE 4 /**< A file was moved on the same disk. */
#define FILE_CHANGE_DIFF_COPY 5 /**< A new file was found to be a copy of a file from another disk. */
#define FILE_CHANGE_DIFF_RESTORE 6 /**< A file's inode has changed but not its date-time and size, which suggests the file may be restored from backup. */
#define FILE_CHANGE_RECOVERED 7 /**< A recoverable/recovered file */
#define FILE_CHANGE_UNRECOVERABLE 8 /**< A unrecoverable file */

struct snapraid_file {
	tommy_node node;
	int change; /**< One of the DIFF_CHANGE_* */
	char* path; /**< Path of the file */
	char* source_path; /**< Path of the source/old file, valid only if reason == DIFF_REASON_MOVE or DIFF_REASON_COPY */
	char* disk; /**< Name of the disk */
	char* source_disk; /**< Name of the source disk, valid only if reason == DIFF_REASON_MOVE or DIFF_REASON_COPY */
	char str[]; /**< Allocated string */
};

struct snapraid_diff_stat {
	/* diff counters. Updated in diff and sync */
	int64_t diff_equal; /**< Comparison of the content state with the real state of the array */
	int64_t diff_added;
	int64_t diff_removed;
	int64_t diff_updated;
	int64_t diff_moved;
	int64_t diff_copied;
	int64_t diff_restored;
	tommy_list file_list; /**< List of snapraid_file entries */
};

struct snapraid_fix_stat {
	/* fix counters. Updated in fix and sync */
	int64_t fix_recovered;
	int64_t fix_unrecoverable;
	tommy_list file_list; /**< List of snapraid_file entries */
};

struct snapraid_bucket {
	time_t time_at; /**< Time of latest write */
	uint64_t count_scrubbed; /**< Number of blocks scrubbed */
	uint64_t count_justsynced; /**< Number of blocks justsynced */
	tommy_node node;
};

struct snapraid_global {
	char version[64]; /**< SnapRAID engine full version. */
	int version_major;
	int version_minor;
	char conf_engine[PATH_MAX]; /**< Configuration file of the SnapRAID engine. */
	char content[PATH_MAX]; /**< Content file. */
	unsigned blocksize; /**< Block size */
	int64_t last_time; /**< Time of the latest command */
	char last_cmd[64]; /**< Last command started */

	int64_t sync_time; /**< Time of the last sync run. If 0 never run. */
	int64_t scrub_time; /**< Time of the last scrub run. If 0 never run. */
	int64_t diff_time; /**< Time of the last diff run. If 0 never run. */
	int64_t fix_time; /**< Time of the last fix run. If 0 never run. */

	/* info counters. Updated in sync/scrub */
	uint64_t file_total; /**< Total file count in the array as stored in the content file */
	uint64_t block_bad; /**< Total blocks marked as bad */
	uint64_t block_rehash; /**< Total blocks marked as rehash needed */
	uint64_t block_unscrubbed; /**< Total blocks marked as scrub needed */
	uint64_t block_unsynced; /**< Total blocks marked as sync needed */
	uint64_t block_total; /**< Total blocks */

	struct snapraid_diff_stat diff_parse; /**< Working diff stat while parsing */
	struct snapraid_diff_stat diff_prev; /**< Previous diff stat (used by report after a sync) */
	struct snapraid_diff_stat diff_current; /**< Latest complete diff stat */

	struct snapraid_fix_stat fix_current; /**< Latest complete fix stat */

	tommy_list bucket_list; /**< Latest bucket list */
	tommy_list bucket_parse_list; /**< Working bucket list while parsing */
};

#define CONFIG_MAX 512 /**< Max length of a configuration option */

#define RUN_DISABLED 0
#define RUN_DAILY 1
#define RUN_WEEKLY 7

#define LVL_CRITICAL 0
#define LVL_ERROR 1
#define LVL_WARNING 2
#define LVL_INFO 3
#define LVL_DEBUG 4

/**
 * Combine two LVL_* returning most critical one
 */
static inline int level_mix(int level, int new_level)
{
	if (level > new_level)
		level = new_level;
	return level;
}

/**
 * SnapRAID exit code when a sync is needed, like in 'diff'
 */
#define EXIT_SYNC_NEEDED 2

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
	int net_security_headers;
	char net_allowed_origin[CONFIG_MAX];
	int net_config_full_access;
	char net_web_root[PATH_MAX]; /**< Web pages directory */
	int maintenance_run;
	int maintenance_hour;
	int maintenance_minute;
	int maintenance_day_of_week;
	int sync_threshold_deletes;
	int sync_threshold_updates;
	int sync_prehash;
	int sync_force_zero;
	double scrub_percentage;
	int scrub_older_than;
	int probe_interval_minutes;
	int spindown_idle_minutes;
	char script_run_as_user[CONFIG_MAX];
	char script_pre_run[CONFIG_MAX];
	char script_post_run[CONFIG_MAX];
	char log_directory[CONFIG_MAX];
	int log_retention_days;
	int notify_syslog_enabled;
	int notify_syslog_level;
	char notify_run_as_user[CONFIG_MAX];
	char notify_heartbeat[CONFIG_MAX];
	char notify_result[CONFIG_MAX];
	int notify_result_level;
	int notify_differences;
};

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Structure containing host system metadata for the SnapRAID dashboard.
 * * This structure maps to the 'System' object in the OpenAPI specification
 * and is used to provide hardware and OS context to the web interface.
 */
struct snapraid_system {
	char hostname[256]; /**< Network hostname of the machine */
	char os_distribution[256]; /**< Operating system name and version (e.g., "Ubuntu 24.04 LTS") */
	char kernel_version[128]; /**< Running Linux kernel version string */
	char motherboard[256]; /**< Manufacturer and model of the motherboard */
	char cpu_model[256]; /**< Total physical RAM available in kilobytes */
	uint64_t memory_total_bytes; /**< Total physical RAM available */
	uint64_t memory_free_bytes; /**< Currently unused physical RAM */
	uint64_t uptime_seconds; /**< Number of seconds the system has been powered on */
	int is_ecc; /**< True if Error Correction Code (ECC) memory is detected and active */
};

#define DAEMON_QUIT 0
#define DAEMON_RUNNING 1
#define DAEMON_RELOAD 2

struct snapraid_state {
	volatile int daemon_running; /**< If the daemon is running or terminating */
	volatile int daemon_sig; /**< Signal received by the daemon that made it stopping */
	thread_mutex_t lock; /**< Main lock for accessing the state */
	struct snapraid_pulse pulse; /**< Pulse counters. */
	int foreground; /**< Daemon running in foreground */
	int verbose; /**< Verbose output */
	struct mg_context* rest_context; /**< The context of the rest support */
	struct mg_callbacks rest_callbacks;
	struct snapraid_runner runner;
	struct snapraid_scheduler scheduler;
	struct snapraid_global global;
	struct snapraid_config config;
	struct snapraid_system system;
	tommy_list data_list;
	tommy_list parity_list;
	int page_nocache; /**< If pages are not cached but read at runtime */
	thread_rwlock_t page_lock;
	tommy_list page_list; /**< List of web pages */
	time_t page_time; /**< Time of the pages loaded from disk */
};

/****************************************************************************/
/* state */

/**
 * Initialize the global state system.
 */
struct snapraid_state* state_init(void);

/**
 * Cleanup the global state system.
 */
void state_done(struct snapraid_state* state);

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

/****************************************************************************/
/* page */

/**
 * Acquire lock for accessing the web.
 */
void page_rdlock(void);

/**
 * Acquire lock for accessing the web.
 */
void page_wrlock(void);

/**
 * Release lock for accessing the web.
 */
void page_unlock(void);

#endif

