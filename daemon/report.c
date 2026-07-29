// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "os/portable.h"

#include "app.h"
#include "report.h"
#include "state.h"
#include "support.h"
#include "log.h"
#include "elem.h"
#include "smart.h"

static int disk_count_device(struct snapraid_disk* disk)
{
	return tommy_list_count(&disk->device_list);
}

static const char* health_report_wide(int health)
{
	switch (health) {
	case HEALTH_PASSED : return " [passed]";
	case HEALTH_FAILING : return "[FAILING]";
	case HEALTH_PREFAIL : return "[PREFAIL]";
	case HEALTH_CORRUPT : return "[CORRUPT]";
	case HEALTH_PENDING : return "[pending]";
	}

	return "[-]";
}

static const char* health_report_narrow(int health)
{
	switch (health) {
	case HEALTH_PASSED : return "[OK]";
	case HEALTH_FAILING : return "[FAIL]";
	case HEALTH_PREFAIL : return "[PRE]";
	case HEALTH_CORRUPT : return "[BAD]";
	case HEALTH_PENDING : return "[??]";
	}

	return "[-]";
}

static const char* smart_report_wide(int flag)
{
	if (flag & SMARTCTL_FLAG_FAIL)
		return "FAILING";
	else if (flag & SMARTCTL_FLAG_PREFAIL)
		return "PREFAIL";
	else if (flag & SMARTCTL_FLAG_PREFAIL_LOGGED)
		return "Prefail condition in the past but not now";
	else if (flag & SMARTCTL_FLAG_ERROR_LOGGED)
		return "Error Logged";
	else if (flag & SMARTCTL_FLAG_SELFTEST_ERROR_LOGGED)
		return "Selt Test Error Logged";

	return 0;
}

static const char* smart_report_narrow(int flag)
{
	if (flag & SMARTCTL_FLAG_FAIL)
		return "FAILING";
	else if (flag & SMARTCTL_FLAG_PREFAIL)
		return "PREFAIL";
	else if (flag & SMARTCTL_FLAG_PREFAIL_LOGGED)
		return "Prefail in the past";
	else if (flag & SMARTCTL_FLAG_ERROR_LOGGED)
		return "Error Logged";
	else if (flag & SMARTCTL_FLAG_SELFTEST_ERROR_LOGGED)
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
	struct tm res;
	struct tm* tm_info = localtime_r(&t, &res);
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
 * Print differences list.
 */
static void print_differences_wide(ss_t* ss, tommy_list* diff_list)
{
	/* group by change type */
	for (int change = FILE_CHANGE_DIFF_FIRST; change <= FILE_CHANGE_DIFF_LAST; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(diff_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "  %s:\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(diff_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change != change)
				continue;

			if (file->change == FILE_CHANGE_DIFF_MOVE || file->change == FILE_CHANGE_DIFF_COPY || file->change == FILE_CHANGE_DIFF_RELOCATE) {
				ss_printf(ss, "    %s:%s <- %s:%s\n", file->disk, file->path, file->source_disk, file->source_path);
			} else {
				ss_printf(ss, "    %s:%s\n", file->disk, file->path);
			}
		}
		ss_prints(ss, "\n");
	}
}

static void print_differences_narrow(ss_t* ss, tommy_list* diff_list)
{
	/* group by change type */
	for (int change = FILE_CHANGE_DIFF_FIRST; change <= FILE_CHANGE_DIFF_LAST; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(diff_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "- %s\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(diff_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change != change)
				continue;

			if (file->change == FILE_CHANGE_DIFF_MOVE || file->change == FILE_CHANGE_DIFF_COPY || file->change == FILE_CHANGE_DIFF_RELOCATE) {
				ss_printf(ss, "%s:%s <- %s:%s\n", file->disk, file->path, file->source_disk, file->source_path);
			} else {
				ss_printf(ss, "%s:%s\n", file->disk, file->path);
			}
		}
		ss_prints(ss, "\n");
	}
}

/**
 * Print fix list.
 */
static void print_fix_wide(ss_t* ss, tommy_list* fix_list)
{
	/* group by change type */
	for (int change = FILE_CHANGE_FIX_FIRST; change <= FILE_CHANGE_FIX_LAST; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(fix_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "  %s:\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(fix_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change != change)
				continue;

			ss_printf(ss, "    %s: %s\n", file->disk, file->path);
		}
		ss_prints(ss, "\n");
	}
}

static void print_fix_narrow(ss_t* ss, tommy_list* fix_list)
{
	/* group by change type */
	for (int change = FILE_CHANGE_FIX_FIRST; change <= FILE_CHANGE_FIX_LAST; ++change) {
		int found = 0;

		/* check if there are any changes of this type */
		for (tommy_node* i = tommy_list_head(fix_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change == change) {
				found = 1;
				break;
			}
		}

		if (!found)
			continue;

		/* print section header */
		ss_printf(ss, "- %s\n", change_name(change));

		/* print all changes of this type */
		for (tommy_node* i = tommy_list_head(fix_list); i; i = i->next) {
			struct snapraid_file* file = i->data;
			if (file->change != change)
				continue;

			ss_printf(ss, "%s:%s\n", file->disk, file->path);
		}
		ss_prints(ss, "\n");
	}
}

/**
 * If there is an error message, return it
 */
static struct snapraid_message* has_reason(tommy_list* list)
{
	/* first for fatal errors */
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_message* message = i->data;
		switch (message->level) {
		case MESSAGE_LEVEL_FATAL :
			return message;
		}
	}

	/* then for errors */
	for (tommy_node* i = tommy_list_head(list); i; i = i->next) {
		struct snapraid_message* message = i->data;
		switch (message->level) {
		case MESSAGE_LEVEL_ERROR :
			return message;
		}
	}

	return 0;
}

/**
 * Print task information (sync or scrub).
 */
static void print_task_wide(ss_t* ss, const char* task_name, struct snapraid_task* task)
{
	tommy_node* i;

	if (!task) {
		ss_printf(ss, "%s: Not run\n", task_name);
		return;
	}

	ss_printf(ss, "%s (", task_name);
	format_timestamp(ss, task->unix_end_time);
	ss_prints(ss, ")\n");

	/* duration */
	ss_prints(ss, "\n");
	ss_prints(ss, "  Duration:       ");
	if (task->unix_end_time > 0 && task->unix_start_time > 0) {
		format_duration(ss, task->unix_end_time - task->unix_start_time);
	} else {
		ss_prints(ss, "N/A");
	}
	ss_prints(ss, "\n");

	if (task->arg_custom) {
		int j = 0;
		ss_prints(ss, "  Arguments:      ");
		for (i = tommy_list_head(&task->arg_list); i != 0; i = i->next) {
			if (j >= task->arg_custom) {
				sn_t* sn = i->data;
				if (j > task->arg_custom)
					ss_prints(ss, " ");
				ss_printf(ss, "%s", sn->str);
			}
			++j;
		}
		ss_prints(ss, "\n");
	}

	/* exit status */
	ss_prints(ss, "  Status:         ");
	struct snapraid_message* reason = has_reason(&task->message_list);
	if (task->state == PROCESS_STATE_TERM) {
		if (task->exit_code == 0) {
			if (reason) {
				if (reason->type == MESSAGE_TYPE_HARDWARE)
					ss_printf(ss, "Completed with non-fatal HARDWARE ERRORS\n");
				else
					ss_printf(ss, "Completed with non-fatal ERRORS\n");
			} else
				ss_prints(ss, "Completed successfully\n");
		} else {
			if (reason) {
				if (reason->type == MESSAGE_TYPE_HARDWARE)
					ss_printf(ss, "Failed: [HARDWARE FAILURE] %s\n", reason->msg);
				else
					ss_printf(ss, "Failed: %s\n", reason->msg);
			} else {
				ss_printf(ss, "Failed (exit code %d)\n", task->exit_code);
			}
		}
	} else if (task->state == PROCESS_STATE_SIGNAL) {
		if (reason)
			ss_printf(ss, "Signaled: %s\n", reason->msg);
		else
			ss_printf(ss, "Signaled %s\n", os_signal_name(task->exit_sig));
	} else if (task->state == PROCESS_STATE_CANCEL) {
		ss_printf(ss, "Canceled: %s\n", task->exit_msg);
	} else {
		ss_prints(ss, "Unknown state\n");
	}

	/* error statistics for both sync and scrub */
	if (task->state != PROCESS_STATE_CANCEL) {
		ss_printf(ss, "  I/O Errors:     %" PRIu64 "\n", task->error_io);
		ss_printf(ss, "  Data Errors:    %" PRIu64 "\n", task->error_data);
		ss_printf(ss, "  Soft Errors:    %" PRIu64 "\n", task->error_soft);
	}

	/* canceled tasks don't have real messages, just the exit_msg already shown */
	if (task->state != PROCESS_STATE_CANCEL) {
		/* print error messages if any */
		int first = 1;
		for (i = tommy_list_head(&task->message_list); i; i = i->next) {
			struct snapraid_message* message = i->data;
			switch (message->level) {
			case MESSAGE_LEVEL_FATAL :
			case MESSAGE_LEVEL_ERROR :
				if (first) {
					ss_prints(ss, "\nERRORS:\n");
					first = 0;
				}
				if (message->type == MESSAGE_TYPE_HARDWARE)
					ss_printf(ss, "  - [HARDWARE FAILURE] %s\n", message->msg);
				else
					ss_printf(ss, "  - %s\n", message->msg);
				break;
			}
		}
	}

	/* print recovered files if any */
	if (!tommy_list_empty(&task->fix_list)) {
		ss_prints(ss, "\nRECOVER:\n");
		print_fix_wide(ss, &task->fix_list);
	}
}

static void print_task_narrow(ss_t* ss, const char* task_name, struct snapraid_task* task)
{
	if (!task) {
		ss_printf(ss, "%s: Not run\n", task_name);
		return;
	}

	ss_printf(ss, "%s: ", task_name);
	struct snapraid_message* reason = has_reason(&task->message_list);
	if (task->state == PROCESS_STATE_TERM) {
		if (task->exit_code == 0) {
			if (reason)
				ss_prints(ss, "Completed with non-fatal ERRORS\n");
			else
				ss_prints(ss, "Completed successfully\n");
		} else {
			ss_printf(ss, "FAILED (%d)\n", task->exit_code);
			if (reason) {
				if (reason->type == MESSAGE_TYPE_HARDWARE)
					ss_printf(ss, "!! [HW FAIL] %s\n", reason->msg);
				else
					ss_printf(ss, "!! %s\n", reason->msg);
			}
		}
	} else if (task->state == PROCESS_STATE_SIGNAL) {
		ss_printf(ss, "SIGNALED (%s)\n", os_signal_name(task->exit_sig));
		if (reason)
			ss_printf(ss, "!! %s\n", reason->msg);
	} else if (task->state == PROCESS_STATE_CANCEL) {
		ss_prints(ss, "CANCELED\n");
		ss_printf(ss, "!! %s\n", task->exit_msg);
	} else {
		ss_prints(ss, "UNKNOWN\n");
	}

	ss_prints(ss, "Duration: ");
	if (task->unix_end_time > 0 && task->unix_start_time > 0) {
		format_duration(ss, task->unix_end_time - task->unix_start_time);
	} else {
		ss_prints(ss, "N/A");
	}
	ss_prints(ss, "\n");

	/* error statistics for both sync and scrub */
	if (task->state != PROCESS_STATE_CANCEL) {
		ss_printf(ss, "I/O Errs: %" PRIu64 "\n", task->error_io);
		ss_printf(ss, "Data Errs: %" PRIu64 "\n", task->error_data);
		ss_printf(ss, "Soft Errors: %" PRIu64 "\n", task->error_soft);
	}

	/* canceled tasks don't have real messages, just the exit_msg already shown */
	if (task->state != PROCESS_STATE_CANCEL) {
		/* print error messages if any */
		int first = 1;
		for (tommy_node* i = tommy_list_head(&task->message_list); i; i = i->next) {
			struct snapraid_message* message = i->data;
			switch (message->level) {
			case MESSAGE_LEVEL_FATAL :
			case MESSAGE_LEVEL_ERROR :
				if (first) {
					ss_prints(ss, "\nERRORS:\n");
					first = 0;
				}
				if (message->type == MESSAGE_TYPE_HARDWARE)
					ss_printf(ss, "- [HW FAIL] %s\n", message->msg);
				else
					ss_printf(ss, "- %s\n", message->msg);
				break;
			}
		}
	}

	/* print recovered files if any */
	if (!tommy_list_empty(&task->fix_list)) {
		ss_prints(ss, "\nRECOVER:\n");
		print_fix_narrow(ss, &task->fix_list);
	}
}

struct disk_spacing {
	int tab_len;
	int name_len;
	int health_len;
	int model_len;
	int serial_len;
	int interf_len;
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
			len = strlen(device->interf);
			if (sp->interf_len < len)
				sp->interf_len = len;
		}
	}
}

static void print_device_wide(struct snapraid_state* state, const char* disk_name, struct snapraid_device* device, ss_t* ss, struct disk_spacing* sp, int has_many)
{
	if (has_many) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len);
		ss_prints(ss, health_report_wide(device->health));
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
	ss_prints(ss, "   Interface: ");
	ss_printl(ss, device->interf[0] ? device->interf : "-", sp->interf_len);
	ss_prints(ss, "\n");
	if (device->error_medium.value != SMART_UNASSIGNED && device->error_medium.value != 0) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len + sp->health_len);
		if (smartignore_match(disk_name, 0, "error_medium", &state->config.smartignore_list)) {
			ss_printf(ss, "(ignored) Medium Errors: %" PRIu64 "\n", device->error_medium.value);
		} else {
			ss_printf(ss, "!! Medium Errors: %" PRIu64 "\n", device->error_medium.value);
		}
	}
	if (device->error_protocol.value != SMART_UNASSIGNED && device->error_protocol.value != 0) {
		ss_printc(ss, ' ', sp->tab_len + sp->name_len + sp->health_len);
		if (smartignore_match(disk_name, 0, "error_protocol", &state->config.smartignore_list)) {
			ss_printf(ss, "(ignored) Protocol Errors: %" PRIu64 "\n", device->error_protocol.value);
		} else {
			ss_printf(ss, "!! Protocol Errors: %" PRIu64 "\n", device->error_protocol.value);
		}
	}
	if (device->flags != SMART_UNASSIGNED) {
		const char* smart = smart_report_wide(device->flags);
		if (smart) {
			ss_printc(ss, ' ', sp->tab_len + sp->name_len + sp->health_len);
			ss_printf(ss, ">> SMART reports: %s\n", smart);
		}
	}
}

static void print_device_narrow(struct snapraid_state* state, const char* disk_name, struct snapraid_device* device, ss_t* ss, int has_many)
{
	if (has_many) {
		ss_printf(ss, " %s", health_report_narrow(device->health));
	}

	if (device->prob != 0)
		ss_printf(ss, " %2d%%", (int)(device->prob * 100));
	else if (device->wear_level != SMART_UNASSIGNED)
		ss_printf(ss, " %2d%%", (int)(device->wear_level));
	else
		ss_prints(ss, "    ");

	ss_printf(ss, " %s\n", device->serial[0] ? device->serial : "-");

	if (device->error_medium.value != SMART_UNASSIGNED && device->error_medium.value != 0) {
		if (smartignore_match(disk_name, 0, "error_medium", &state->config.smartignore_list)) {
			ss_printf(ss, "(ignored) Medium Errors: %" PRIu64 "\n", device->error_medium.value);
		} else {
			ss_printf(ss, "!! Medium Errors: %" PRIu64 "\n", device->error_medium.value);
		}
	}
	if (device->error_protocol.value != SMART_UNASSIGNED && device->error_protocol.value != 0) {
		if (smartignore_match(disk_name, 0, "error_protocol", &state->config.smartignore_list)) {
			ss_printf(ss, "(ignored) Protocol Errors: %" PRIu64 "\n", device->error_protocol.value);
		} else {
			ss_printf(ss, "!! Protocol Errors: %" PRIu64 "\n", device->error_protocol.value);
		}
	}
	if (device->flags != SMART_UNASSIGNED) {
		const char* smart = smart_report_narrow(device->flags);
		if (smart) {
			ss_printf(ss, ">> %s\n", smart);
		}
	}
}

static void print_disk_list_wide(struct snapraid_state* state, tommy_list* disk_list, int kind, ss_t* ss, struct disk_spacing* sp)
{
	for (tommy_node* i = tommy_list_head(disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		if (disk->kind != kind)
			continue;

		int disk_health = health_disk(disk, 0, 0);

		ss_prints(ss, "  ");
		ss_printl(ss, disk->name, sp->name_len);
		ss_prints(ss, health_report_wide(disk_health));

		int has_none = tommy_list_empty(&disk->device_list);
		int has_many = disk_count_device(disk) > 1;
		if (has_many || has_none)
			ss_prints(ss, "\n");

		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			print_device_wide(state, disk->name, device, ss, sp, has_many);
		}

		/* print error counters if not zero */
		if (disk->transient_error_io != 0 || disk->transient_error_data != 0) {
			ss_printc(ss, ' ', sp->tab_len + sp->name_len);
			ss_printf(ss, "!! I/O Errors: %" PRIu64 ", Data Errors: %" PRIu64 "\n",
				disk->transient_error_io, disk->transient_error_data);
		}
	}
}

static void print_disk_list_narrow(struct snapraid_state* state, tommy_list* disk_list, int kind, ss_t* ss)
{
	for (tommy_node* i = tommy_list_head(disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;

		if (disk->kind != kind)
			continue;

		int disk_health = health_disk(disk, 0, 0);

		ss_prints(ss, disk->name);
		ss_prints(ss, " ");
		ss_prints(ss, health_report_narrow(disk_health));

		int has_none = tommy_list_empty(&disk->device_list);
		int has_many = disk_count_device(disk) > 1;
		if (has_many || has_none)
			ss_prints(ss, "\n");

		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			print_device_narrow(state, disk->name, device, ss, has_many);
		}

		/* print error counters if not zero */
		if (disk->transient_error_io != 0 || disk->transient_error_data != 0) {
			ss_printf(ss, "!! I/O Errors: %" PRIu64 "\n", disk->transient_error_io);
			ss_printf(ss, "!! Data Errors: %" PRIu64 "\n", disk->transient_error_data);
		}
	}
}

struct smart_header {
	int header_printed;
	int disk_printed;
	int attr_printed;
};

static void print_smart_header_wide(ss_t* ss, struct smart_header* sh, const char* disk_name, const char* dev_serial, const char* attr_name, int is_ignored)
{
	if (!sh->header_printed) {
		print_line_separator(ss);
		ss_prints(ss, "ATTRIBUTES CHANGES:\n\n");
		sh->header_printed = 1;
	}
	if (!sh->disk_printed) {
		if (dev_serial)
			ss_printf(ss, "Disk %s (serial: %s):\n", disk_name, dev_serial);
		else
			ss_printf(ss, "Disk %s:\n", disk_name);
		sh->disk_printed = 1;
	}
	if (!sh->attr_printed) {
		ss_printf(ss, "%s%s\n", attr_name, is_ignored ? " (ignored)" : "");
		sh->attr_printed = 1;
	}
}

static void print_smart_header_narrow(ss_t* ss, struct smart_header* sh, const char* disk_name, const char* attr_name, int is_ignored)
{
	if (!sh->header_printed) {
		ss_prints(ss, "ATTRIBUTES CHANGES\n");
		sh->header_printed = 1;
	}
	if (!sh->disk_printed) {
		ss_printf(ss, "Disk %s:\n", disk_name);
		sh->disk_printed = 1;
	}
	if (!sh->attr_printed) {
		ss_printf(ss, "%s%s\n", attr_name, is_ignored ? " (ignored)" : "");
		sh->attr_printed = 1;
	}
}

static void print_smart_changes_wide(struct snapraid_state* state, ss_t* ss, time_t queue_time)
{
	struct smart_header sh;
	sh.header_printed = 0;

	for (tommy_node* i = tommy_list_head(&state->array.disk_list); i != 0; i = i->next) {
		struct snapraid_disk* disk = i->data;

		sh.disk_printed = 0;

		/* error_io change */
		sh.attr_printed = 0;
		if (disk->error_io.value != SMART_UNASSIGNED
			&& disk->error_io.prev != SMART_UNASSIGNED
			&& disk->error_io.value != disk->error_io.prev
			&& disk->error_io.prev_last >= queue_time
		) {
			uint64_t cv_val = disk->error_io.value;
			uint64_t cv_old = disk->error_io.prev;

			if (cv_val != cv_old) {
				int ignored = smartignore_match(disk->name, 0, "error_io", &state->config.smartignore_list);
				print_smart_header_wide(ss, &sh, disk->name, 0, "Input_Output_Errors", ignored);

				const char* changed = cv_old < cv_val ? "degraded" : "improved";
				int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
				ss_printf(ss, "raw %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")\n", changed, cv_old, cv_val, delta);
			}
		}

		/* error_data change */
		sh.attr_printed = 0;
		if (disk->error_data.value != SMART_UNASSIGNED
			&& disk->error_data.prev != SMART_UNASSIGNED
			&& disk->error_data.value != disk->error_data.prev
			&& disk->error_data.prev_last >= queue_time
		) {
			uint64_t cv_val = disk->error_data.value;
			uint64_t cv_old = disk->error_data.prev;

			if (cv_val != cv_old) {
				int ignored = smartignore_match(disk->name, 0, "error_data", &state->config.smartignore_list);
				print_smart_header_wide(ss, &sh, disk->name, 0, "Silent_Errors", ignored);

				const char* changed = cv_old < cv_val ? "degraded" : "improved";
				int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
				ss_printf(ss, "raw %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")\n", changed, cv_old, cv_val, delta);
			}
		}

		for (tommy_node* j = tommy_list_head(&disk->device_list); j != 0; j = j->next) {
			struct snapraid_device* dev = j->data;

			sh.disk_printed = 0; /* it prints the serial, so reset it for each devices */

			for (int k = 0; k < SMART_COUNT; ++k) {
				struct smart_attr* attr = &dev->smart[k];
				sh.attr_printed = 0;

				/*
				 * Raw change
				 *
				 * No explicit kind/critical filtering is needed here because raw.prev
				 * is only updated in parser.c for tracked critical/count attributes.
				 */
				if (attr->raw.value != SMART_UNASSIGNED
					&& attr->raw.prev != SMART_UNASSIGNED
					&& attr->raw.value != attr->raw.prev
					&& attr->raw.prev_last >= queue_time
				) {
					int kind = smart_kind(k, attr->name);
					uint64_t cv_val = smart_conv(attr->raw.value, kind);
					uint64_t cv_old = smart_conv(attr->raw.prev, kind);

					if (cv_val != cv_old) {
						print_smart_header_wide(ss, &sh, disk->name, dev->serial, attr->name, smartignore_match(disk->name, k, attr->name, &state->config.smartignore_list));

						const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
						int64_t delta = (int64_t)cv_val - (int64_t)cv_old;

						ss_printf(ss, "raw %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")\n", changed, cv_old, cv_val, delta);
					}
				}

				/*
				 * Norm change
				 *
				 * No explicit kind/prefail filtering is needed here because norm.prev
				 * is only updated in parser.c for tracked prefail attributes.
				 */
				if (attr->norm.value != SMART_UNASSIGNED
					&& attr->norm.prev != SMART_UNASSIGNED
					&& attr->norm.value != attr->norm.prev
					&& attr->norm.prev_last >= queue_time
				) {
					uint64_t cv_val = smart_conv(attr->norm.value, SMART_KIND_NORM);
					uint64_t cv_old = smart_conv(attr->norm.prev, SMART_KIND_NORM);

					if (cv_val != cv_old) {
						print_smart_header_wide(ss, &sh, disk->name, dev->serial, attr->name, smartignore_match(disk->name, k, attr->name, &state->config.smartignore_list));

						const char* changed = cv_old > cv_val ? "degraded" : "improved"; /* lower is worse */
						int64_t delta = (int64_t)cv_val - (int64_t)cv_old;

						ss_printf(ss, "norm %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")", changed, cv_old, cv_val, delta);
						if (attr->worst != SMART_UNASSIGNED && attr->thresh != SMART_UNASSIGNED) {
							ss_printf(ss, " (worst: %" PRIu64 ", thresh: %" PRIu64 ")", attr->worst, attr->thresh);
						}
						ss_printf(ss, "\n");
					}
				}
			}

			/* error_protocol change */
			sh.attr_printed = 0;
			if (dev->error_protocol.value != SMART_UNASSIGNED
				&& dev->error_protocol.prev != SMART_UNASSIGNED
				&& dev->error_protocol.value != dev->error_protocol.prev
				&& dev->error_protocol.prev_last >= queue_time
			) {
				uint64_t cv_val = dev->error_protocol.value;
				uint64_t cv_old = dev->error_protocol.prev;

				if (cv_val != cv_old) {
					int ignored = smartignore_match(disk->name, 0, "error_protocol", &state->config.smartignore_list);
					print_smart_header_wide(ss, &sh, disk->name, dev->serial, "Protocol_Errors", ignored);

					const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
					int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
					ss_printf(ss, "raw %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")\n", changed, cv_old, cv_val, delta);
				}
			}

			/* error_medium change */
			sh.attr_printed = 0;
			if (dev->error_medium.value != SMART_UNASSIGNED
				&& dev->error_medium.prev != SMART_UNASSIGNED
				&& dev->error_medium.value != dev->error_medium.prev
				&& dev->error_medium.prev_last >= queue_time
			) {
				uint64_t cv_val = dev->error_medium.value;
				uint64_t cv_old = dev->error_medium.prev;

				if (cv_val != cv_old) {
					int ignored = smartignore_match(disk->name, 0, "error_medium", &state->config.smartignore_list);
					print_smart_header_wide(ss, &sh, disk->name, dev->serial, "Medium_Errors", ignored);

					const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
					int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
					ss_printf(ss, "raw %s from %" PRIu64 " to %" PRIu64 " (%+" PRId64 ")\n", changed, cv_old, cv_val, delta);
				}
			}
		}
	}
	if (sh.header_printed) {
		ss_prints(ss, "\n");
	}
}

static void print_smart_changes_narrow(struct snapraid_state* state, ss_t* ss, time_t queue_time)
{
	struct smart_header sh;
	sh.header_printed = 0;

	for (tommy_node* i = tommy_list_head(&state->array.disk_list); i != 0; i = i->next) {
		struct snapraid_disk* disk = i->data;

		sh.disk_printed = 0; /* it doesn't print the serial, so all devices goes in the same disk section */

		/* error_io change */
		sh.attr_printed = 0;
		if (disk->error_io.value != SMART_UNASSIGNED
			&& disk->error_io.prev != SMART_UNASSIGNED
			&& disk->error_io.value != disk->error_io.prev
			&& disk->error_io.prev_last >= queue_time
		) {
			uint64_t cv_val = disk->error_io.value;
			uint64_t cv_old = disk->error_io.prev;

			if (cv_val != cv_old) {
				int ignored = smartignore_match(disk->name, 0, "error_io", &state->config.smartignore_list);
				print_smart_header_narrow(ss, &sh, disk->name, "Input_Output_Errors", ignored);

				const char* changed = cv_old < cv_val ? "degraded" : "improved";
				int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
				ss_printf(ss, "raw %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
			}
		}

		/* error_data change */
		sh.attr_printed = 0;
		if (disk->error_data.value != SMART_UNASSIGNED
			&& disk->error_data.prev != SMART_UNASSIGNED
			&& disk->error_data.value != disk->error_data.prev
			&& disk->error_data.prev_last >= queue_time
		) {
			uint64_t cv_val = disk->error_data.value;
			uint64_t cv_old = disk->error_data.prev;

			if (cv_val != cv_old) {
				int ignored = smartignore_match(disk->name, 0, "error_data", &state->config.smartignore_list);
				print_smart_header_narrow(ss, &sh, disk->name, "Silent_Errors", ignored);

				const char* changed = cv_old < cv_val ? "degraded" : "improved";
				int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
				ss_printf(ss, "raw %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
			}
		}

		for (tommy_node* j = tommy_list_head(&disk->device_list); j != 0; j = j->next) {
			struct snapraid_device* dev = j->data;

			for (int k = 0; k < SMART_COUNT; ++k) {
				struct smart_attr* attr = &dev->smart[k];
				sh.attr_printed = 0;

				/*
				 * Raw change
				 *
				 * No explicit kind/critical filtering is needed here because raw.prev
				 * is only updated in parser.c for tracked critical/count attributes.
				 */
				if (attr->raw.value != SMART_UNASSIGNED
					&& attr->raw.prev != SMART_UNASSIGNED
					&& attr->raw.value != attr->raw.prev
					&& attr->raw.prev_last >= queue_time
				) {
					int kind = smart_kind(k, attr->name);
					uint64_t cv_val = smart_conv(attr->raw.value, kind);
					uint64_t cv_old = smart_conv(attr->raw.prev, kind);

					if (cv_val != cv_old) {
						print_smart_header_narrow(ss, &sh, disk->name, attr->name, smartignore_match(disk->name, k, attr->name, &state->config.smartignore_list));

						const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
						int64_t delta = (int64_t)cv_val - (int64_t)cv_old;

						ss_printf(ss, "raw %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
					}
				}

				/*
				 * Norm change
				 *
				 * No explicit kind/prefail filtering is needed here because norm.prev
				 * is only updated in parser.c for tracked prefail attributes.
				 */
				if (attr->norm.value != SMART_UNASSIGNED
					&& attr->norm.prev != SMART_UNASSIGNED
					&& attr->norm.value != attr->norm.prev
					&& attr->norm.prev_last >= queue_time
				) {
					uint64_t cv_val = smart_conv(attr->norm.value, SMART_KIND_NORM);
					uint64_t cv_old = smart_conv(attr->norm.prev, SMART_KIND_NORM);

					if (cv_val != cv_old) {
						print_smart_header_narrow(ss, &sh, disk->name, attr->name, smartignore_match(disk->name, k, attr->name, &state->config.smartignore_list));

						const char* changed = cv_old > cv_val ? "degraded" : "improved"; /* lower is worse */
						int64_t delta = (int64_t)cv_val - (int64_t)cv_old;

						ss_printf(ss, "norm %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
						if (attr->worst != SMART_UNASSIGNED && attr->thresh != SMART_UNASSIGNED)
							ss_printf(ss, "worst %" PRIu64 " thresh %" PRIu64 "\n", attr->worst, attr->thresh);
					}
				}
			}

			/* error_protocol change */
			sh.attr_printed = 0;
			if (dev->error_protocol.value != SMART_UNASSIGNED
				&& dev->error_protocol.prev != SMART_UNASSIGNED
				&& dev->error_protocol.value != dev->error_protocol.prev
				&& dev->error_protocol.prev_last >= queue_time
			) {
				uint64_t cv_val = dev->error_protocol.value;
				uint64_t cv_old = dev->error_protocol.prev;

				if (cv_val != cv_old) {
					int ignored = smartignore_match(disk->name, 0, "error_protocol", &state->config.smartignore_list);
					print_smart_header_narrow(ss, &sh, disk->name, "Protocol_Errors", ignored);

					const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
					int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
					ss_printf(ss, "raw %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
				}
			}

			/* error_medium change */
			sh.attr_printed = 0;
			if (dev->error_medium.value != SMART_UNASSIGNED
				&& dev->error_medium.prev != SMART_UNASSIGNED
				&& dev->error_medium.value != dev->error_medium.prev
				&& dev->error_medium.prev_last >= queue_time
			) {
				uint64_t cv_val = dev->error_medium.value;
				uint64_t cv_old = dev->error_medium.prev;

				if (cv_val != cv_old) {
					int ignored = smartignore_match(disk->name, 0, "error_medium", &state->config.smartignore_list);
					print_smart_header_narrow(ss, &sh, disk->name, "Medium_Errors", ignored);

					const char* changed = cv_old < cv_val ? "degraded" : "improved"; /* higher is worse */
					int64_t delta = (int64_t)cv_val - (int64_t)cv_old;
					ss_printf(ss, "raw %s to %" PRIu64 " %+" PRId64 "\n", changed, cv_val, delta);
				}
			}
		}
	}
	if (sh.header_printed) {
		ss_prints(ss, "\n");
	}
}

/****************************************************************************/
/* report */

static void report_wide_locked(struct snapraid_state* state, ss_t* ss,
	struct snapraid_task* latest_report,
	struct snapraid_task* latest_fix,
	struct snapraid_task* latest_sync,
	struct snapraid_task* latest_scrub,
	struct snapraid_diff_stat* diff_stat)
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

	if (state->instance[0] != 0)
		ss_printf(ss, "INSTANCE: %s\n", state->instance);

	if (state->system.hostname[0] != 0)
		ss_printf(ss, "HOSTNAME: %s\n", state->system.hostname);

	/* array health */
	array_health = state->array.health;
	ss_printf(ss, "ARRAY HEALTH: %s\n", health_report_wide(array_health));

	/* overall status message */
	if (array_health == HEALTH_PASSED)
		ss_prints(ss, "  Overall Status: All systems nominal\n");
	else if (array_health == HEALTH_FAILING)
		ss_prints(ss, "  Overall Status: FAILING\n");
	else if (array_health == HEALTH_PREFAIL)
		ss_prints(ss, "  Overall Status: PRE FAILING\n");
	else if (array_health == HEALTH_CORRUPT)
		ss_prints(ss, "  Overall Status: CORRUPT\n");
	else
		ss_prints(ss, "  Overall Status: Pending\n");

	/* bad blocks */
	ss_printf(ss, "  Bad Blocks:     %" PRIu64 "\n", state->array.block_bad);

	ss_prints(ss, "\n");

	struct disk_spacing sp;
	sp.name_len = 0;
	sp.model_len = 0;
	sp.serial_len = 0;
	sp.interf_len = 0;
	sp.tab_len = 2;
	sp.health_len = 9;

	/* get field lenghts */
	spacing_disk_list(&state->array.disk_list, &sp);

	++sp.name_len; /* extra space after the name */

	/* data disks */
	if (disk_count(&state->array.disk_list, DISK_DATA) != 0) {
		ss_prints(ss, "DATA DISKS:\n");
		print_disk_list_wide(state, &state->array.disk_list, DISK_DATA, ss, &sp);
		ss_prints(ss, "\n");
	}

	/* parity disks */
	if (disk_count(&state->array.disk_list, DISK_PARITY) != 0) {
		ss_prints(ss, "PARITY DISKS:\n");
		print_disk_list_wide(state, &state->array.disk_list, DISK_PARITY, ss, &sp);
		ss_prints(ss, "\n");
	}

	/* other disks */
	if (disk_count(&state->array.disk_list, DISK_EXTRA) != 0) {
		ss_prints(ss, "EXTRA DISKS:\n");
		print_disk_list_wide(state, &state->array.disk_list, DISK_EXTRA, ss, &sp);
		ss_prints(ss, "\n");
	}

	print_smart_changes_wide(state, ss, latest_report->unix_queue_time);

	if (latest_fix) {
		print_line_separator(ss);
		print_task_wide(ss, "FIX", latest_fix);
		ss_prints(ss, "\n");
	}

	if (latest_sync) {
		print_line_separator(ss);
		print_task_wide(ss, "SYNC", latest_sync);
		ss_prints(ss, "\n");
	}

	if (latest_scrub) {
		print_line_separator(ss);
		print_task_wide(ss, "SCRUB", latest_scrub);
		ss_prints(ss, "\n");
	}

	if (diff_stat) {
		print_line_separator(ss);
		ss_prints(ss, "DIFFERENCES:\n\n");
		ss_printf(ss, "  equal:    %10" PRId64 "\n", diff_stat->diff_equal);
		ss_printf(ss, "  added:    %10" PRId64 "\n", diff_stat->diff_added);
		ss_printf(ss, "  removed:  %10" PRId64 "\n", diff_stat->diff_removed);
		ss_printf(ss, "  updated:  %10" PRId64 "\n", diff_stat->diff_updated);
		ss_printf(ss, "  moved:    %10" PRId64 "\n", diff_stat->diff_moved);
		ss_printf(ss, "  copied:   %10" PRId64 "\n", diff_stat->diff_copied);
		ss_printf(ss, "  relocated:%10" PRId64 "\n", diff_stat->diff_relocated);
		ss_printf(ss, "  restored: %10" PRId64 "\n", diff_stat->diff_restored);
		ss_prints(ss, "\n");

		/* differences list if enabled */
		if (state->config.notify_differences != 0) {
			print_differences_wide(ss, &diff_stat->file_list);
			ss_prints(ss, "\n");
		}
	}

	print_separator(ss);
}

void report_narrow_locked(struct snapraid_state* state, ss_t* ss,
	struct snapraid_task* latest_report,
	struct snapraid_task* latest_fix,
	struct snapraid_task* latest_sync,
	struct snapraid_task* latest_scrub,
	struct snapraid_diff_stat* diff_stat)
{
	(void)latest_fix;
	(void)diff_stat;

	if (state->instance[0] != 0)
		ss_printf(ss, "INSTANCE: %s\n", state->instance);

	if (state->system.hostname[0] != 0)
		ss_printf(ss, "HOSTNAME: %s\n", state->system.hostname);

	int array_health = state->array.health;
	ss_printf(ss, "HEALTH: %s\n", health_report_wide(array_health));

	ss_prints(ss, "STATUS: ");
	if (array_health == HEALTH_PASSED)
		ss_prints(ss, "All nominal\n");
	else if (array_health == HEALTH_FAILING)
		ss_prints(ss, "FAILING\n");
	else if (array_health == HEALTH_PREFAIL)
		ss_prints(ss, "PRE FAILING\n");
	else if (array_health == HEALTH_CORRUPT)
		ss_prints(ss, "CORRUPT\n");
	else
		ss_prints(ss, "Pending\n");

	ss_printf(ss, "BAD BLOCKS: %" PRIu64 "\n", state->array.block_bad);
	ss_prints(ss, "\n");

	if (disk_count(&state->array.disk_list, DISK_DATA) != 0) {
		ss_prints(ss, "DATA DISKS\n");
		print_disk_list_narrow(state, &state->array.disk_list, DISK_DATA, ss);
		ss_prints(ss, "\n");
	}

	if (disk_count(&state->array.disk_list, DISK_PARITY) != 0) {
		ss_prints(ss, "PARITY DISKS\n");
		print_disk_list_narrow(state, &state->array.disk_list, DISK_PARITY, ss);
		ss_prints(ss, "\n");
	}

	if (disk_count(&state->array.disk_list, DISK_EXTRA) != 0) {
		ss_prints(ss, "EXTRA DISKS\n");
		print_disk_list_narrow(state, &state->array.disk_list, DISK_EXTRA, ss);
		ss_prints(ss, "\n");
	}

	print_smart_changes_narrow(state, ss, latest_report->unix_queue_time);

	if (latest_fix) {
		print_task_narrow(ss, "FIX", latest_fix);
		ss_prints(ss, "\n");
	}

	if (latest_sync) {
		print_task_narrow(ss, "SYNC", latest_sync);
		ss_prints(ss, "\n");
	}

	if (latest_scrub) {
		print_task_narrow(ss, "SCRUB", latest_scrub);
		ss_prints(ss, "\n");
	}

	if (diff_stat) {
		ss_prints(ss, "DIFFERENCES:\n");
		ss_printf(ss, "- equal:    %10" PRId64 "\n", diff_stat->diff_equal);
		ss_printf(ss, "- added:    %10" PRId64 "\n", diff_stat->diff_added);
		ss_printf(ss, "- removed:  %10" PRId64 "\n", diff_stat->diff_removed);
		ss_printf(ss, "- updated:  %10" PRId64 "\n", diff_stat->diff_updated);
		ss_printf(ss, "- moved:    %10" PRId64 "\n", diff_stat->diff_moved);
		ss_printf(ss, "- copied:   %10" PRId64 "\n", diff_stat->diff_copied);
		ss_printf(ss, "- relocated:%10" PRId64 "\n", diff_stat->diff_relocated);
		ss_printf(ss, "- restored: %10" PRId64 "\n", diff_stat->diff_restored);
		ss_prints(ss, "\n");

		/* differences list if enabled */
		if (state->config.notify_differences != 0) {
			print_differences_narrow(ss, &diff_stat->file_list);
			ss_prints(ss, "\n");
		}
	}
}

void report_locked(struct snapraid_state* state, ss_t* ss,
	struct snapraid_task* latest_report,
	struct snapraid_task* latest_fix,
	struct snapraid_task* latest_sync,
	struct snapraid_task* latest_scrub,
	struct snapraid_diff_stat* diff_stat)
{
	int is_mail = 0;
	const char* cmd = state->config.notify_result;

	/* autodetection of the format */
	is_mail |= strstr(cmd, "mail") != 0;
	is_mail |= strstr(cmd, "smtp") != 0;
	is_mail |= strstr(cmd, "mutt") != 0;
	is_mail |= strstr(cmd, "swaks") != 0;

	/* forced */
	if (strstr(cmd, "--wide") != 0)
		is_mail = 1;
	if (strstr(cmd, "--narrow") != 0)
		is_mail = 0;

	if (is_mail)
		report_wide_locked(state, ss, latest_report, latest_fix, latest_sync, latest_scrub, diff_stat);
	else
		report_narrow_locked(state, ss, latest_report, latest_fix, latest_sync, latest_scrub, diff_stat);
}

