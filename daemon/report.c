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

static int disk_count_device(struct snapraid_disk* disk)
{
	return tommy_list_count(&disk->device_list);
}

static const char* health_report(int health)
{
	switch (health) {
	case HEALTH_PASSED : return " [passed]";
	case HEALTH_FAILING : return "[FAILING]";
	case HEALTH_PENDING : return "[pending]";
	}

	return "-";
}

static const char* smart_report(int flag)
{
	if (flag & SMARTCTL_FLAG_FAIL)
		return "FAILING";
	else if (flag & SMARTCTL_FLAG_PREFAIL)
		return "PREFAIL";
	else if (flag & SMARTCTL_FLAG_PREFAIL_LOGGED)
		return "Prefail condition in the past";
	else if (flag & SMARTCTL_FLAG_ERROR_LOGGED)
		return "Error Logged";
	else if (flag & SMARTCTL_FLAG_SELFERROR_LOGGED)
		return "Selt Test Error Logged";

	return 0;
}

/**
 * Format a duration in seconds to a human-readable string.
 */
static void format_duration(ss_t* ss, int64_t seconds)
{
	if (seconds < 0) {
		ss_prints(ss, "N/A");
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
		ss_prints(ss, "Never");
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
		ss_prints(ss, "Invalid");
	}
}

/**
 * Print separator line.
 */
static void print_separator(ss_t* ss)
{
	ss_printc(ss, '=', 80);
	ss_prints(ss, "\n");
}


static void print_line_separator(ss_t* ss)
{
	ss_printc(ss, '-', 80);
	ss_prints(ss, "\n");
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
	ss_prints(ss, ")\n");

	/* duration */
	ss_prints(ss, "  Duration:       ");
	if (task->unix_end_time > 0 && task->unix_start_time > 0) {
		format_duration(ss, task->unix_end_time - task->unix_start_time);
	} else {
		ss_prints(ss, "N/A");
	}
	ss_prints(ss, "\n");

	/* exit status */
	ss_prints(ss, "  Status:         ");
	if (task->state == PROCESS_STATE_TERM) {
		if (task->exit_code == 0)
			ss_prints(ss, "Completed successfully (exit code 0)\n");
		else
			ss_printf(ss, "Failed (exit code %d)\n", task->exit_code);
	} else if (task->state == PROCESS_STATE_SIGNAL) {
		ss_printf(ss, "Terminated by signal %d\n", task->exit_sig);
	} else if (task->state == PROCESS_STATE_CANCEL) {
		ss_printf(ss, "Canceled: %s\n", task->exit_msg);
	} else {
		ss_prints(ss, "Unknown state\n");
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
		ss_prints(ss, "\nERROR MESSAGES:\n");
		for (tommy_node* i = tommy_list_head(&task->error_list); i; i = i->next) {
			sn_t* error = i->data;
			ss_printf(ss, "  - %s\n", error->str);
		}
	}
}

/**
 * Print differences list.
 */
static void print_differences(ss_t* ss, struct snapraid_diff_stat* diff_stat)
{
	/* group by change type */
	for (int change = DIFF_CHANGE_ADD; change <= DIFF_CHANGE_RESTORE; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(&diff_stat->diff_list); i; i = i->next) {
			struct snapraid_diff* diff = i->data;
			if (diff->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "  list_%s:\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(&diff_stat->diff_list); i; i = i->next) {
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
		ss_prints(ss, "\n");
	}
}

struct disk_spacing {
	int tab_len;
	int name_len;
	int health_len;
	int model_len;
	int serial_len;
};

static void spacing_disk_list(tommy_list* disk_list, struct disk_spacing* sp)
{
	for (tommy_node* i = tommy_list_head(disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		int len = strlen(disk->name);
		if (sp->name_len < len)
			sp->name_len = len;
		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			len = strlen(device->model);
			if (sp->model_len < len)
				sp->model_len = len;
			len = strlen(device->serial);
			if (sp->serial_len < len)
				sp->serial_len = len;
		}
	}
}

static void print_device(struct snapraid_device* device, ss_t* ss, struct disk_spacing* sp, int has_many)
{
	if (has_many) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len);
		ss_prints(ss, health_report(device->health));
	}
	if (device->prob != 0)
		ss_printf(ss, "   FP:%3d%%", (int)(device->prob * 100));
	else if (device->wear_level != SMART_UNASSIGNED)
		ss_printf(ss, "   WL:%3d%%", (int)(device->wear_level));
	else
		ss_prints(ss, "          ");
	ss_prints(ss, "   Model: ");
	ss_printl(ss, device->model[0] ? device->model : "-", sp->model_len);
	ss_prints(ss, "   Serial: ");
	ss_printl(ss, device->serial[0] ? device->serial : "-", sp->serial_len);
	ss_prints(ss, "\n");
	if (device->error_medium != SMART_UNASSIGNED || device->error_protocol != SMART_UNASSIGNED) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len + sp->health_len);
		ss_printf(ss, ">> Medium Errors: %" PRIu64 ", Protocol Errors: %" PRIu64 "\n", device->error_medium, device->error_protocol);
	}
	const char* smart = smart_report(device->flags);
	if (smart) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len + sp->health_len);
		ss_printf(ss, ">> SMART reports: %s\n", smart);
	}
}

static void print_disk_list(tommy_list* disk_list, ss_t* ss, struct disk_spacing* sp)
{
	for (tommy_node* i = tommy_list_head(disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		int disk_health = health_disk(disk);

		ss_prints(ss, "  ");
		ss_printl(ss, disk->name, sp->name_len);
		ss_prints(ss, health_report(disk_health));

		int has_many = disk_count_device(disk) > 1;
		if (has_many)
			ss_prints(ss, "\n");

		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			print_device(device, ss, sp, has_many);
		}

		/* print error counters if not zero */
		if (disk->error_io != 0 || disk->error_data != 0) {
			ss_printc(ss, ' ', sp->tab_len + sp->name_len);
			ss_printf(ss, ">> I/O Errors: %" PRIu64 ", Data Errors: %" PRIu64 "\n", disk->error_io, disk->error_data);
		}
	}
}

/****************************************************************************/
/* report */

int report(struct snapraid_state* state, ss_t* ss, struct snapraid_task* latest_sync, struct snapraid_task* latest_scrub, struct snapraid_diff_stat* diff_stat)
{
	int array_health;
	time_t now = time(0);

	/* header */
	print_separator(ss);
	ss_prints(ss, "SnapRAID Array Status Report\n");
	ss_prints(ss, "Generated: ");
	format_timestamp(ss, now);
	ss_prints(ss, "\n");
	print_separator(ss);
	ss_prints(ss, "\n");

	/* array health */
	array_health = health_array(state);
	ss_printf(ss, "ARRAY HEALTH: %s\n", health_report(array_health));

	/* overall status message */
	if (array_health == HEALTH_PASSED)
		ss_prints(ss, "  Overall Status: All systems nominal\n");
	else if (array_health == HEALTH_FAILING)
		ss_prints(ss, "  Overall Status: FAILURES DETECTED\n");
	else
		ss_prints(ss, "  Overall Status: Pending\n");

	/* bad blocks */
	ss_printf(ss, "  Bad Blocks:     %" PRIu64 "\n", state->global.block_bad);

	ss_prints(ss, "\n");

	struct disk_spacing sp;
	sp.name_len = 0;
	sp.serial_len = 0;
	sp.model_len = 0;
	sp.tab_len = 2;
	sp.health_len = 9;

	/* get field lenghts */
	spacing_disk_list(&state->data_list, &sp);
	spacing_disk_list(&state->parity_list, &sp);

	++sp.name_len; /* extra space after the name */

	/* data disks */
	if (!tommy_list_empty(&state->data_list)) {
		ss_prints(ss, "DATA DISKS:\n");
		print_disk_list(&state->data_list, ss, &sp);
		ss_prints(ss, "\n");
	}

	/* parity disks */
	if (!tommy_list_empty(&state->parity_list)) {
		ss_prints(ss, "PARITY DISKS:\n");
		print_disk_list(&state->parity_list, ss, &sp);
		ss_prints(ss, "\n");
	}

	/* latest Sync */
	print_line_separator(ss);
	print_task(ss, "SYNC", latest_sync);

	/* latest Scrub */
	ss_prints(ss, "\n");
	print_line_separator(ss);
	print_task(ss, "SCRUB", latest_scrub);

	/* global statistics */
	ss_prints(ss, "\n");
	print_line_separator(ss);
	ss_prints(ss, "DIFFERENCES:\n\n");
	ss_printf(ss, "  equal:   %10" PRId64 "\n", diff_stat->diff_equal);
	ss_printf(ss, "  added:   %10" PRId64 "\n", diff_stat->diff_added);
	ss_printf(ss, "  removed: %10" PRId64 "\n", diff_stat->diff_removed);
	ss_printf(ss, "  updated: %10" PRId64 "\n", diff_stat->diff_updated);
	ss_printf(ss, "  moved:   %10" PRId64 "\n", diff_stat->diff_moved);
	ss_printf(ss, "  copied:  %10" PRId64 "\n", diff_stat->diff_copied);
	ss_printf(ss, "  restored:%10" PRId64 "\n", diff_stat->diff_restored);

	/* differences list if enabled */
	if (state->config.notify_differences != 0) {
		ss_prints(ss, "\n");
		print_differences(ss, diff_stat);
	}

	/* footer */
	print_separator(ss);

	return 0;
}

