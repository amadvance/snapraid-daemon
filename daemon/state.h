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
#define POWER_STANDBY 0
#define POWER_ACTIVE 1

/**
 * Health
 */
#define HEALTH_PASSED 0
#define HEALTH_FAILING 1
    
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
	uint64_t error;
	uint64_t flags;
	uint64_t power; /**< POWER mode. */
	uint64_t health; /**< HEALTH code. */

	tommy_node node;
};

struct snapraid_data {
	char name[PATH_MAX]; /**< Name of the disk. */
	char dir[PATH_MAX]; /**< Mount point */
	char uuid[UUID_MAX]; /**< Current UUID. */
	char content_uuid[UUID_MAX]; /**< UUID stored in the content file. */
	uint64_t content_size; /**< Size of the disk stored in the content file. */
	uint64_t content_free; /**< Free size of the disk stored in the content file. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	tommy_list device_list; /**< Lis of snapraid_devices */
	tommy_node node;
};

struct snapraid_split {
	int index; /**< Index of the split */
	char path[PATH_MAX]; /**< Parity file */
	char uuid[UUID_MAX]; /**< Current UUID. */
	char content_path[PATH_MAX]; /**< Parity file stored in the content file. */
	uint64_t content_size; /**< Size of the parity file stored in the content file. */
	char content_uuid[UUID_MAX]; /**< UUID stored in the content file. */
	tommy_list device_list; /**< Lis of snapraid_devices */
	tommy_node node;
};

struct snapraid_parity {
	char name[PATH_MAX]; /**< Name of the parity. */
	tommy_list split_list; /**< Lis of snapraid_splits */
	uint64_t content_size; /**< Size of the disk stored in the content file. */
	uint64_t content_free; /**< Free size of the disk stored in the content file. */
	uint64_t access_count; /**< Counter of the number of read and write accesses to the disk. */
	int64_t access_count_initial_time; /**< Time of the first access_count to this value. */
	int64_t access_count_latest_time; /**< Time of latest access_count to this value. */
	tommy_node node;
};


#define CMD_NONE 0
#define CMD_PROBE 1
#define CMD_UP 2
#define CMD_DOWN 3
#define CMD_SMART 4
#define CMD_STATUS 5
#define CMD_LIST 6
#define CMD_DIFF 7
#define CMD_SYNC 8
#define CMD_SCRUB 9
#define CMD_FIX 10
#define CMD_CHECK 11

#define PROCESS_STATE_INIT 0
#define PROCESS_STATE_BEGIN 1
#define PROCESS_STATE_POS 2
#define PROCESS_STATE_SIGINT 3
#define PROCESS_STATE_END 4

struct snapraid_process {
	int state; /**< 0 if in preparation, 1 after begin, 2 after the first pos, 3 after the end */
	unsigned progress; /**< Completion percentage, 0 <= process <= 100 */
	unsigned eta_seconds; /**< Estimate seconds for the end */
	unsigned speed_mbs; /**< Processing speed in in MBytes/s */
	unsigned cpu_usage; /**< CPU occupation in percentage, 0 <= cpu_usage <= 100. */
	unsigned elapsed_seconds; /**< Number of seconds elapsed from the begin of the process. */
	unsigned block_begin; /**< First block to be processed */
	unsigned block_end; /**< Latest block +1 to be processed */
	unsigned block_count; /**< Number of blocks to be processed, it may be less than end - begin */
	unsigned block_idx; /**< Block currently processed. block_begin <= processed_block < block_end */
	unsigned block_done; /**< Incremental number of block processed. 0 <= block_done < block_count */
	uint64_t size_done; /**< Number of bytes processed until now */
	int exit_code; /**< Exit code of SnapRAID */
	int exit_sig; /**< Signal that termianted SnapRAID */
};

#define MESSAGE_MAX 256

struct snapraid_message {
	char str[MESSAGE_MAX];
	tommy_node node;
};

struct snapraid_runner {
	thread_cond_t cond;
	thread_id_t thread_id;
	int stderr_f;
	int cmd; /**< The latest command run or running */
	int running; /**< If the command is running or finished */
	pid_t pid; /**< PID of the SnapRAID process. */
	tommy_list message_list; /**< List of messages */
};

struct snapraid_global {
	char conf[PATH_MAX]; /**< Configuration file. */
	char content[PATH_MAX]; /**< Content file. */
	int version_major; /**< SnapRAID major version */
	int version_minor; /**< SnapRAID minor version */
	int blocksize; /**< Block size */
	int64_t unixtime; /**< Time of the latest command */
};

struct snapraid_state {
	volatile int daemon_running; /**< If the daemon is running or terminating */
	thread_mutex_t lock; /**< Main lock for accessing the state */
	struct mg_context* rest_context; /**< The context of the rest support */
	struct mg_callbacks rest_callbacks;
	struct snapraid_runner runner;
	struct snapraid_process process;
	struct snapraid_global global;
	tommy_list data_list;
	tommy_list parity_list;
};

void state_init(void);
void state_done(void);

struct snapraid_state* state_ptr(void);

void state_lock(void);
void state_unlock(void);

#endif
