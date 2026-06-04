// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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
 * Max keyword length
 *
 * It's the size of all the fields/commands/configuration options lengths.
 */
#define KEYWORD_MAX 128

/**
 * Max length of a free text message
 **/
#define MSG_MAX 256

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
#define SMARTCTL_FLAG_SELFTEST_ERROR_LOGGED (1 << 7) /**< The device self-test log contains records of errors. */

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
#define HEALTH_PASSED 1
#define HEALTH_PENDING 0
#define HEALTH_CORRUPT -1
#define HEALTH_PREFAIL -2
#define HEALTH_FAILING -3

/**
 * Pulse masks
 */
#define PULSE_ARRAY 1 /* change in the /array entry point */
#define PULSE_CONFIG 2 /* change in the /config entry point */
#define PULSE_DISKS 4 /* change in the /disks entry point */

/*
 * Change in the /disks entry point causing an UI update but not an important
 * attribute change that needs to be kept forever.
 *
 * These changes do not prevent the deletion of the probes.
 */
#define PULSE_DISKS_UI 8

#define PULSE_TASKS 16 /* change in the /tasks entry point */
#define PULSE_ACTIVITY 32 /* change in the /activity entry point */

/**
 * Pulse
 */
struct snapraid_pulse {
	uint64_t array; /**< State counter for the "array" entry point */
	uint64_t config; /**< State counter for the "config" entry point */
	uint64_t disks_attr; /**< State counter for the "disks" entry point */
	uint64_t disks_ui; /**< State counter for the "disk" entry point for temperature */
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

struct snapraid_tracked {
	uint64_t value; /**< current value */
	uint64_t prev; /**< previous value */
	uint64_t lowest; /**< lowest ever seen */
	int64_t prev_last; /**< Time of when the attribute got the current value */
	int64_t lowest_last; /**< Time of when the lowest attribute was last seen */
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
	char name[KEYWORD_MAX]; /**< SMART attribute name. */
	struct snapraid_tracked raw; /**< SMART attributes raw. */
	uint64_t norm; /**< SMART attributes normalized. */
	uint64_t worst; /**< SMART attributes worst. */
	uint64_t thresh; /**< SMART attributes threshold. */
	int flags; /**< SMART_ATTR_* flags */
};

#define HEALTH_REASON_MAX 256

/**
 * Device info entry.
 */
struct snapraid_device {
	char file[PATH_MAX]; /**< Device node. Always set. */
	sl_t id_list; /**< List of unique identifiers of the device */
	char serial[SMART_MAX]; /**< Serial number. Empty if not set. */
	char family[SMART_MAX]; /**< Vendor and model family. Empty if not set. */
	char model[SMART_MAX]; /**< Model. Empty if not set. */
	char interf[SMART_MAX]; /**< Interface. Empty if not set. */
	int64_t smart_time; /**< Time of the latest smart measure */
	struct smart_attr smart[SMART_COUNT]; /**< SMART attributes. */
	uint64_t size; /**< Physical size in bytes. SMART_UNASSIGNED if not set. */
	uint64_t rotational; /**< 1 if rotational, 0 if SSD. SMART_UNASSIGNED if not set. */
	struct snapraid_tracked error_protocol; /**< Protocol error counter. */
	struct snapraid_tracked error_medium; /**< Medium error counter. */
	uint64_t wear_level; /**< Device wear level percentage (SSD only). SMART_UNASSIGNED if not set. */
	uint64_t flags; /**< Smartctl flags. SMART_UNASSIGNED if not set. */
	double afr; /**< Estimated annual failure rate (the average number of failures you expect in a year) */
	double prob; /**< Estimated probability of failure (the probability of at least one failure in the next year) */
	int last_update_at_number; /**< The latest task number that updated the device */
	int power; /**< POWER mode. POWER_PENDING if not set. */
	int health; /**< HEALTH code. HEALTH_PENDING if not set. */
	char health_reason[HEALTH_REASON_MAX]; /**< Human readable health issue description. Empty if not set. */
	int temperature; /**< Latest measured temperature, 0 if none */
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

#define DISK_UNDEFINED 0
#define DISK_DATA 1
#define DISK_PARITY 2
#define DISK_EXTRA 3

struct snapraid_disk {
	char name[KEYWORD_MAX]; /**< Name of the disk. */
	uint64_t total_space_bytes; /**< Size of the disk stored in the content file. SMART_UNASSIGNED if not set. */
	uint64_t free_space_bytes; /**< Free size of the disk stored in the content file. SMART_UNASSIGNED if not set. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. SMART_UNASSIGNED if not set. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	uint64_t error_io; /**< Accumulator of all I/O errors encountered. */
	uint64_t error_data; /**< Accumulator of all silent data errors encountered. */
	int last_update_at_number; /**< The latest task number that updated the disk */
	int kind; /**< Kind of the disk. One of DISK_* */

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
#define CMD_STATUS 12
#define CMD_READ 13
#define CMD_REPORT 101 /**< Additional command that generates a report */
#define CMD_DOWN_IDLE 102 /**< Additional command that spin down inactive disks */
#define CMD_MAINTENANCE 201 /**< High level command. Never enter the queue. */
#define CMD_HEAL 202 /**< High level command. Never enter the queue. */
#define CMD_UNDELETE 203 /**< High level command. Never enter the queue. */
#define CMD_SUSPEND_IDLE 204 /**< High level command. Never enter the queue. */
#define CMD_REFRESH 205  /**< High level command. Never enter the queue. */
#define CMD_STARTUP 206  /**< High level command. Never enter the queue. */

#define PROCESS_STATE_QUEUE 0 /**< The process is queued */
#define PROCESS_STATE_START 1 /**< The process is starting */
#define PROCESS_STATE_RUN 2 /**< The task sent a "begin"/"pos" log telling its progress */
#define PROCESS_STATE_SIGNAL 3 /**< The task sent a "signal" log (running!=0) or it's signaled (running==0) and exit_sig has the signal */
#define PROCESS_STATE_TERM 4 /**< The task set a "end" log (running!=0) or it's terminated (running==0) and exit_code has the status code */
#define PROCESS_STATE_CANCEL 5 /**< The task is canceled */

#define HISTORY_PAST_DAYS 120 /**< Number of days the history is kept in memory (not affecting log files) */
#define HISTORY_TASKS_MAX 10000 /**< Max number of tasks in the history kept in memory */

#define SECONDS_IN_A_DAY (24 * 3600)

#define MESSAGES_MAX 5000 /**< Max number of messages and errors kept in memory for each task */

#define FILES_MAX 100000 /**< Max number of files in fix/diff kept in memory. The correct counters are obtained regardless of this. */

#define MESSAGE_LEVEL_FATAL 0
#define MESSAGE_LEVEL_ERROR 1
#define MESSAGE_LEVEL_INFO 2
#define MESSAGE_LEVEL_VERBOSE 3

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
	char exit_msg[MSG_MAX]; /** Exit message. Valid only for PROCESS_STATE_CANCEL */
	unsigned pulse; /**< Pulse flags triggered by the task */

	sl_t arg_list; /**< List of arguments */
	int arg_custom; /**< If it's a custom argument list. It's the position of the first custom argument. 0 if none */
	tommy_list message_list; /**< List of snapraid_message */
	int message_list_count; /**< Count of messages, just to limit the number. */
	int message_omit_error; /**< Number of messages over the limit. */
	int message_omit_info; /**< Number of messages over the limit. */
	int message_omit_verbose; /**< Number of messages over the limit. */

	uint64_t fix_counter; /**< Number of elements inserted in fix_list */
	tommy_list fix_list; /**< List of recovered/recoverable/unrecoverable snapraid_file. Limit of FILES_MAX applied. */

	char* text_report; /**< for CMD_REPORT it's the final text report */

	/* error stats */
	int health; /**< Health of the array after the task. */
	uint64_t error_soft; /**< Total software errors encountered (sync/scrub only). */
	uint64_t error_io; /**< Total I/O errors encountered (sync/scrub only). */
	uint64_t error_data; /**< Total silent data errors encountered (sync/scrub only). */
	uint64_t error_recovered; /**< Total error recovered (fix only). */
	uint64_t error_unrecoverable; /**< Total error unrecoverable (fix only). */

	tommy_node node;
};

struct snapraid_schedule {
	int cmd; /**< Command to schedule */
	sl_t args; /**< Arguments for the command */
	tommy_node node;
};

struct snapraid_runner {
	thread_cond_t cond;
	thread_id_t thread_id;
	int number_allocator; /**< Allocator of number of tasks */
	int64_t last_start_time; /**< Latest start time used */
	struct snapraid_task* latest; /**< Task running, or latest one finished */
	int script_skip; /**< If the post_run script was skipped because a following task is coming */
	tommy_list waiting_list; /**< List of snapraid_task waiting to be executed */
	tommy_list history_list; /**< List of snapraid_task already executed */
	int hold_off; /**< Hold off the next maintenance */
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
#define FILE_CHANGE_DIFF_RELOCATE 6 /**< A new file was found to be a copy of a file from another disk now disappeared. */
#define FILE_CHANGE_DIFF_RESTORE 7 /**< A file's inode has changed but not its date-time and size, which suggests the file may be restored from backup. */
#define FILE_CHANGE_RECOVERED 8 /**< A recoverable/recovered file */
#define FILE_CHANGE_UNRECOVERABLE 9 /**< A unrecoverable file */

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
	int64_t diff_added; /**< Number of added files */
	int64_t diff_removed; /**< Number of removed files */
	int64_t diff_updated; /**< Number of updated files */
	int64_t diff_moved; /**< Number of moved files */
	int64_t diff_copied; /**< Number of copied files */
	int64_t diff_relocated; /**< Number of relocated files */
	int64_t diff_restored; /**< Number of restored files */
	uint64_t file_counter; /**< Number of elements inserted in file_list */
	tommy_list file_list; /**< List of snapraid_file entries. Limit of FILES_MAX applied. */
};

struct snapraid_fix_stat {
	/* fix counters. Updated in fix and sync */
	int64_t fix_recovered; /**< Number of recovered files */
	int64_t fix_unrecoverable; /**< Number of unrecoverable files */
	tommy_list file_list; /**< List of snapraid_file entries. Limit of FILES_MAX applied in the task and not here. */
};

struct snapraid_bucket {
	time_t time_at; /**< Time of latest write */
	uint64_t count_scrubbed; /**< Number of blocks scrubbed */
	uint64_t count_justsynced; /**< Number of blocks justsynced */
	tommy_node node;
};

struct snapraid_global {
	char version[64]; /**< SnapRAID engine full version. */
	char conf_engine[PATH_MAX]; /**< Configuration file of the SnapRAID engine. */
	char content[PATH_MAX]; /**< Content file. */
	int64_t content_probe_unixtime; /**< Modification time of the content file. 0 if unknown. */
	int64_t content_last_unixtime; /**< Last write or read of the content file. 0 if unknown. */
	unsigned blocksize; /**< Block size */
	int64_t last_time; /**< Time of the latest command */
	char last_cmd[64]; /**< Last command started */
	int health; /**< Health of the array. Updated after any task. */
	char health_reason[HEALTH_REASON_MAX]; /**< Human readable health issue description. Empty if not set. */

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

struct snapraid_run {
	int hour; /**< Hour for scheduled maintenance */
	int minute; /**< Minute for scheduled maintenance */
	int day_of_week; /**< Day of week for scheduled maintenance. -1 for all. */
	tommy_node node;
};

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
	char text[CONFIG_LINE_MAX]; /**< Raw configuration string. */
	tommy_node node;
};

struct snapraid_config {
	/* private part of the configuration */
	char conf[PATH_MAX]; /**< Configuration file of the daemon. */
	const char* pidfile_arg; /**< PID file specified as argument, or 0 */
	tommy_list line_list; /**< List of snapraid_config_line */

	/* public part of the configuration */
	/* empty string or 0 value means value not set and/or disabled */
	char sys_engine[CONFIG_MAX]; /**< Engine path. */
	char sys_log_directory[CONFIG_MAX]; /**< Directory for log files */
	int sys_log_retention_days; /**< Number of days to keep logs */
	int net_enabled; /**< 1 if network interface is enabled, 0 otherwise */
	char net_port[CONFIG_MAX]; /**< Network port to bind to */
	char net_acl[CONFIG_MAX]; /**< IP access control list */
	int net_security_headers; /**< 1 to enable security headers, 0 otherwise */
	char net_allowed_origin[CONFIG_MAX]; /**< Allowed origin for CORS */
	int net_config_full_access; /**< 1 if full configuration access is allowed from network, 0 otherwise */
	char net_web_root[PATH_MAX]; /**< Web pages directory */
	tommy_list maintenance_list; /**< List of snapraid_run */
	int sync_threshold_deletes; /**< Threshold for deletes before sync fails */
	int sync_threshold_updates; /**< Threshold for updates before sync fails */
	int sync_prehash; /**< 1 to enable prehash, 0 otherwise */
	int sync_prevent_truncations; /**< 0 to force sync with zero size, 1 otherwise */
	double scrub_percentage; /**< Percentage of array to scrub */
	int scrub_older_than; /**< Scrub blocks older than this many days */
	int touch_zero_subseconds; /**< 1 to touch befoer sync, 0 otherwise */
	int probe_interval_minutes; /**< Interval for disk probing in minutes */
	int spindown_idle_minutes; /**< Interval for disk spindown in minutes */
	char hook_run_as_user[CONFIG_MAX]; /**< User to run scripts as */
	char hook_script[CONFIG_MAX]; /**< Hook script path */
	int notify_syslog;
	int notify_syslog_level;
	char notify_run_as_user[CONFIG_MAX]; /**< User to run notifications as */
	char notify_heartbeat[CONFIG_MAX]; /**< Heartbeat notification URL */
	char notify_result[CONFIG_MAX]; /**< Result notification URL/script */
	int notify_result_level; /**< Minimum level for result notification */
	int notify_differences; /**< 1 to include differences in notification, 0 otherwise */
};

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Structure containing host system metadata for the SnapRAID dashboard.
 *
 * This structure maps to the 'System' object in the OpenAPI specification
 * and is used to provide hardware and OS context to the web interface.
 */
struct snapraid_system {
	char hostname[KEYWORD_MAX]; /**< Network hostname of the machine */
	char os_distribution[MSG_MAX]; /**< Operating system name and version (e.g., "Ubuntu 24.04 LTS") */
	char kernel_version[KEYWORD_MAX]; /**< Running Linux/Windoes kernel version string */
	char motherboard[MSG_MAX]; /**< Manufacturer and model of the motherboard */
	char cpu_model[MSG_MAX]; /**< CPU model string */
	uint64_t memory_total_bytes; /**< Total physical RAM available */
	uint64_t memory_free_bytes; /**< Currently unused physical RAM */
	uint64_t uptime_seconds; /**< Number of seconds the system has been powered on */
	int is_ecc; /**< True if Error Correction Code (ECC) memory is detected and active */
};

#define DAEMON_QUIT 0
#define DAEMON_LOADING 1 /**< Loading past logs */
#define DAEMON_STARTING 2 /**< Starting components */
#define DAEMON_RUNNING 3
#define DAEMON_RELOAD 4

struct snapraid_log {
	int foreground; /**< Daemon running in foreground */
	int verbose; /**< Verbose output */
	int syslog; /**< 1 if syslog is enabled, 0 otherwise */
	int syslog_level; /**< Minimum level for syslog messages */
	tommy_list task_list; /**< List of snapraid_message */
};

struct snapraid_web {
	int page_nocache; /**< If pages are not cached but read at runtime */
	tommy_list page_list; /**< List of web pages */
	time_t page_time; /**< Time of the pages loaded from disk */
};

struct snapraid_association {
	char file[PATH_MAX]; /**< Device node. */
	char id[KEYWORD_MAX]; /**< Unique id. */
	tommy_node node;
};

struct snapraid_state {
	volatile int daemon_running; /**< If the daemon is running or terminating */
	volatile int daemon_sig; /**< Signal received by the daemon that made it stopping */

	/* Data private for the parser. The parser run only one at a time, so no lock is required */
	int parser_version_major; /**< Major version number */
	int parser_version_minor; /**< Minor version number */
	tommy_list parser_association; /**< Associations of device<->id */
	int parser_previous_was_association; /**< If the previous entry was an association */

	/**< Data protected by the state lock */
	thread_mutex_t state_lock; /**< Protection for the following data */
	struct snapraid_pulse pulse; /**< Pulse counters. */
	struct mg_context* rest_context; /**< The context of the rest support */
	struct mg_callbacks rest_callbacks; /**< CivetWeb callbacks */
	struct snapraid_runner runner; /**< Task runner system */
	struct snapraid_scheduler scheduler; /**< Maintenance scheduler */
	struct snapraid_global global; /**< Global array metadata */
	struct snapraid_config config; /**< Runtime configuration */
	struct snapraid_system system; /**< Host system information */
	tommy_list disk_list; /**< List of disks */

	/**< Data protected by the web lock */
	thread_rwlock_t web_lock; /**< Protection for the following data */
	struct snapraid_web web; /**< Web asset cache */

	/**< Data protected by the log lock */
	thread_mutex_t log_lock; /**< Protection for the following data */
	struct snapraid_log log; /**< Logging configuration */
};

/****************************************************************************/
/* state */

/**
 * Initialize the global state system.
 * @return Pointer to global state structure
 */
struct snapraid_state* state_init(void);

/**
 * Cleanup the global state system.
 * @param state State structure to cleanup
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
/* log */

/**
 * Acquire lock for accessing the log.
 */
void log_lock(void);

/**
 * Release lock for accessing the log.
 */
void log_unlock(void);

/****************************************************************************/
/* page */

/**
 * Acquire lock for accessing the web.
 */
void web_rdlock(void);

/**
 * Acquire lock for accessing the web.
 */
void web_wrlock(void);

/**
 * Release lock for accessing the web.
 */
void web_unlock(void);

#endif

