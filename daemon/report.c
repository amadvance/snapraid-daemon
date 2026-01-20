/*
 * Copyright (C) 2026 Andrea Mazzoleni
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

#include "report.h"
#include "state.h"
#include "support.h"
#include "elem.h"

/**
 * Format a duration in seconds to a human-readable string.
 */
static void format_duration(ss_t* ss, int64_t seconds)
{
	if (seconds < 0) {
		ss_printf(ss, "N/A");
		return;
	}

	int64_t hours = seconds / 3600;
	int64_t mins = (seconds % 3600) / 60;
	int64_t secs = seconds % 60;

	if (hours > 0)
		ss_printf(ss, "%ldh %ldm %lds", (long)hours, (long)mins, (long)secs);
	else if (mins > 0)
		ss_printf(ss, "%ldm %lds", (long)mins, (long)secs);
	else
		ss_printf(ss, "%lds", (long)secs);
}

/**
 * Format a timestamp to a human-readable string.
 */
static void format_timestamp(ss_t* ss, int64_t timestamp)
{
	if (timestamp == 0) {
		ss_printf(ss, "Never");
		return;
	}

	time_t t = (time_t)timestamp;
	struct tm* tm_info = localtime(&t);
	if (tm_info) {
		ss_printf(ss, "%04d-%02d-%02d %02d:%02d:%02d",
			tm_info->tm_year + 1900,
			tm_info->tm_mon + 1,
			tm_info->tm_mday,
			tm_info->tm_hour,
			tm_info->tm_min,
			tm_info->tm_sec);
	} else {
		ss_printf(ss, "Invalid");
	}
}

/**
 * Print separator line.
 */
static void print_separator(ss_t* ss)
{
	ss_printf(ss, "================================================================================\n");
}

static void print_line_separator(ss_t* ss)
{
	ss_printf(ss, "--------------------------------------------------------------------------------\n");
}

/**
 * Print task information (sync or scrub).
 */
static void print_task(ss_t* ss, const char* task_name, struct snapraid_task* task)
{
	if (!task) {
		ss_printf(ss, "%s: Not run\n", task_name);
		return;
	}

	ss_printf(ss, "%s (", task_name);
	format_timestamp(ss, task->unix_end_time);
	ss_printf(ss, ")\n");

	/* duration */
	ss_printf(ss, "  Duration:       ");
	if (task->unix_end_time > 0 && task->unix_start_time > 0) {
		format_duration(ss, task->unix_end_time - task->unix_start_time);
	} else {
		ss_printf(ss, "N/A");
	}
	ss_printf(ss, "\n");

	/* exit status */
	ss_printf(ss, "  Status:         ");
	if (task->state == PROCESS_STATE_TERM) {
		if (task->exit_code == 0)
			ss_printf(ss, "Completed successfully (exit code 0)\n");
		else
			ss_printf(ss, "Failed (exit code %d)\n", task->exit_code);
	} else if (task->state == PROCESS_STATE_SIGNAL) {
		ss_printf(ss, "Terminated by signal %d\n", task->exit_sig);
	} else if (task->state == PROCESS_STATE_CANCEL) {
		ss_printf(ss, "Canceled: %s\n", task->exit_msg);
	} else {
		ss_printf(ss, "Unknown state\n");
	}

	/* error statistics for sync */
	if (task->cmd == CMD_SYNC) {
		ss_printf(ss, "  Hash Errors:    %" PRIu64 "\n", task->hash_error_soft);
	}

	/* error statistics for both sync and scrub */
	ss_printf(ss, "  Soft Errors:    %" PRIu64 "\n", task->error_soft);
	ss_printf(ss, "  I/O Errors:     %" PRIu64 "\n", task->error_io);
	ss_printf(ss, "  Data Errors:    %" PRIu64 "\n", task->error_data);
	ss_printf(ss, "  Bad Blocks:     %" PRIu64 "\n", task->block_bad);

	/* print error messages if any */
	if (!tommy_list_empty(&task->error_list)) {
		ss_printf(ss, "\nERROR MESSAGES:\n");
		for (tommy_node* i = tommy_list_head(&task->error_list); i; i = i->next) {
			sn_t* error = i->data;
			ss_printf(ss, "  - %s\n", error->str);
		}
	}
}

/**
 * Print differences list.
 */
static void print_differences(ss_t* ss, struct snapraid_state* state)
{
	if (tommy_list_empty(&state->global.diff_list))
		return;

	ss_printf(ss, "CHANGED FILES:\n\n");

	/* group by change type */
	for (int change = DIFF_CHANGE_ADD; change <= DIFF_CHANGE_RESTORE; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(&state->global.diff_list); i; i = i->next) {
			struct snapraid_diff* diff = i->data;
			if (diff->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "  %s:\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(&state->global.diff_list); i; i = i->next) {
			struct snapraid_diff* diff = i->data;
			if (diff->change != change)
				continue;

			if (diff->change == DIFF_CHANGE_MOVE || diff->change == DIFF_CHANGE_COPY) {
				ss_printf(ss, "    %s: %s <- %s: %s\n",
					diff->disk, diff->path,
					diff->source_disk, diff->source_path);
			} else {
				ss_printf(ss, "    %s: %s\n", diff->disk, diff->path);
			}
		}
		ss_printf(ss, "\n");
	}
}

/****************************************************************************/
/* report */

const char* health_report(int health)
{
	switch (health) {
	case HEALTH_PASSED : return "[passed] ";
	case HEALTH_FAILING : return "[FAILING]";
	case HEALTH_PENDING : return "[pending]";
	}

	return "-";
}

int report(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub)
{
	int array_health;
	time_t now = time(0);

	/* header */
	print_separator(ss);
	ss_printf(ss, "SnapRAID Array Status Report\n");
	ss_printf(ss, "Generated: ");
	format_timestamp(ss, now);
	ss_printf(ss, "\n");
	print_separator(ss);
	ss_printf(ss, "\n");

	/* array health */
	array_health = health_array(state);
	ss_printf(ss, "ARRAY HEALTH: %s\n", health_report(array_health));

	/* overall status message */
	if (array_health == HEALTH_PASSED)
		ss_printf(ss, "  Overall Status: All systems nominal\n");
	else if (array_health == HEALTH_FAILING)
		ss_printf(ss, "  Overall Status: FAILURES DETECTED\n");
	else
		ss_printf(ss, "  Overall Status: Pending\n");

	/* bad blocks */
	ss_printf(ss, "  Bad Blocks:     %" PRIu64 "\n", state->global.block_bad);

	ss_printf(ss, "\n");

	int name_len = 0;
	int serial_len = 0;
	int model_len = 0;
	int tab_len = 2;
	int health_len = 9;

	/* get field lenghts */
	if (!tommy_list_empty(&state->data_list)) {
		for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
			struct snapraid_data* data = i->data;
			int len = strlen(data->name);
			if (name_len < len)
				name_len = len;
			for (tommy_node* j = tommy_list_head(&data->device_list); j; j = j->next) {
				struct snapraid_device* device = j->data;
				len = strlen(device->model);
				if (model_len < len)
					model_len = len;
				len = strlen(device->serial);
				if (serial_len < len)
					serial_len = len;
			}
		}
	}
	if (!tommy_list_empty(&state->parity_list)) {
		/* get field lenghts */
		for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
			struct snapraid_parity* parity = i->data;
			int len = strlen(parity->name);
			if (name_len < len)
				name_len = len;
			for (tommy_node* j = tommy_list_head(&parity->split_list); j; j = j->next) {
				struct snapraid_split* split = j->data;
				for (tommy_node* k = tommy_list_head(&split->device_list); k; k = k->next) {
					struct snapraid_device* device = k->data;
					len = strlen(device->model);
					if (model_len < len)
						model_len = len;
					len = strlen(device->serial);
					if (serial_len < len)
						serial_len = len;
				}
			}
		}
	}

	++name_len; /* extra space after the name */

	/* data disks */
	if (!tommy_list_empty(&state->data_list)) {
		ss_printf(ss, "DATA DISKS:\n");
		for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
			struct snapraid_data* data = i->data;
			int data_health = health_data(data);

			ss_printf(ss, "  ");
			ss_printl(ss, data->name, name_len);
			ss_prints(ss, health_report(data_health));

			for (tommy_node* j = tommy_list_head(&data->device_list); j; j = j->next) {
				struct snapraid_device* device = j->data;
				if (j != tommy_list_head(&data->device_list))
					ss_printc(ss, ' ', tab_len + name_len + health_len);
				ss_printf(ss, "  Model: ");
				ss_printl(ss, device->model[0] ? device->model : "-", model_len);
				ss_printf(ss, "   Serial: ");
				ss_printl(ss, device->serial[0] ? device->serial : "-", serial_len);
				ss_printf(ss, "\n");
			}

			/* print error counters if not zero */
			if (data->error_io != 0 || data->error_data != 0) {
				ss_printc(ss, ' ', tab_len + name_len);
				ss_printf(ss, "I/O Errors: %" PRIu64 ", Data Errors: %" PRIu64 "\n", data->error_io, data->error_data);
			}
		}
		ss_printf(ss, "\n");
	}

	/* parity disks */
	if (!tommy_list_empty(&state->parity_list)) {
		ss_printf(ss, "PARITY DISKS:\n");
		for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
			struct snapraid_parity* parity = i->data;
			int parity_health = health_parity(parity);

			ss_printf(ss, "  ");
			ss_printl(ss, parity->name, name_len);
			ss_prints(ss, health_report(parity_health));

			for (tommy_node* j = tommy_list_head(&parity->split_list); j; j = j->next) {
				struct snapraid_split* split = j->data;
				for (tommy_node* k = tommy_list_head(&split->device_list); k; k = k->next) {
					struct snapraid_device* device = k->data;
					if (k != tommy_list_head(&split->device_list))
						ss_printc(ss, ' ', tab_len + name_len + health_len);
					ss_printf(ss, "  Model: ");
					ss_printl(ss, device->model[0] ? device->model : "-", model_len);
					ss_printf(ss, "   Serial: ");
					ss_printl(ss, device->serial[0] ? device->serial : "-", serial_len);
					ss_printf(ss, "\n");
				}
			}

			/* print error counters if not zero */
			if (parity->error_io != 0 || parity->error_data != 0) {
				ss_printc(ss, ' ', tab_len + name_len);
				ss_printf(ss, "I/O Errors: %" PRIu64 ", Data Errors: %" PRIu64 "\n", parity->error_io, parity->error_data);
			}
		}
		ss_printf(ss, "\n");
	}

	/* latest Sync */
	print_line_separator(ss);
	print_task(ss, "SYNC", latest_sync);

	/* latest Scrub */
	ss_printf(ss, "\n");
	print_line_separator(ss);
	print_task(ss, "SCRUB", latest_scrub);

	/* global statistics */
	ss_printf(ss, "\n");
	print_line_separator(ss);
	ss_printf(ss, "GLOBAL STATISTICS\n");
	ss_printf(ss, "  Total Files:    %" PRIu64 "\n", state->global.file_total);
	ss_printf(ss, "\n");
	ss_printf(ss, "DIFFERENCES:\n");
	ss_printf(ss, "  Equal:          %" PRId64 "\n", state->global.diff_equal);
	ss_printf(ss, "  Added:          %" PRId64 "\n", state->global.diff_added);
	ss_printf(ss, "  Removed:        %" PRId64 "\n", state->global.diff_removed);
	ss_printf(ss, "  Updated:        %" PRId64 "\n", state->global.diff_updated);
	ss_printf(ss, "  Moved:          %" PRId64 "\n", state->global.diff_moved);
	ss_printf(ss, "  Copied:         %" PRId64 "\n", state->global.diff_copied);
	ss_printf(ss, "  Restored:       %" PRId64 "\n", state->global.diff_restored);

	/* differences list if enabled */
	if (state->config.notify_differences != 0) {
		ss_printf(ss, "\n");
		print_line_separator(ss);
		print_differences(ss, state);
	}

	/* footer */
	ss_printf(ss, "\n");
	print_separator(ss);

	return 0;
}
