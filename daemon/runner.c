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

#include "portable.h"

#include "state.h"
#include "support.h"
#include "log.h"
#include "parser.h"
#include "daemon.h"
#include "elem.h"
#include "report.h"
#include "notify.h"
#include "runner.h"

/****************************************************************************/
/* runner */

/**
 * Update the health state of the array
 * If there is a change in health, schedule a report task if not yet present
 */
static int runner_health_check_locked(struct snapraid_state* state)
{
	state->global.health_reason[0] = 0;
	int new_health = health_array(state, state->global.health_reason, sizeof(state->global.health_reason));

	if (state->global.health == HEALTH_PENDING)
		state->global.health = new_health;

	/* if health change, run a report */
	if (state->global.health != new_health) {
		pulse(state, PULSE_ARRAY);

		state->global.health = new_health;

		/* check if the current task is a report or if there is a scheduled one */
		int has_report = state->runner.latest->cmd == CMD_REPORT;
		if (!has_report) {
			for (tommy_node* i = tommy_list_head(&state->runner.waiting_list); i != 0; i = i->next) {
				struct snapraid_task* task = i->data;
				if (task->cmd == CMD_REPORT) {
					has_report = 1;
					break;
				}
			}
		}

		/* if no report, schedule a new one */
		if (!has_report) {
			char msg[MSG_MAX];
			int status;
			runner_locked(state, 0, CMD_REPORT, 0, 0, msg, sizeof(msg), &status);
		}
	}

	return state->global.health;
}

static int runner_need_script(int cmd)
{
	switch (cmd) {
	case CMD_SYNC : return 1;
	case CMD_SCRUB : return 1;
	case CMD_FIX : return 1;
	case CMD_CHECK : return 1;
	case CMD_DIFF : return 1;
	}

	return 0;
}

static int runner_report_locked(struct snapraid_state* state)
{
	struct snapraid_task* report_task = state->runner.latest;
	struct snapraid_task* diff_task = 0;
	struct snapraid_task* fix_task = 0;
	struct snapraid_task* sync_task = 0;
	struct snapraid_task* scrub_task = 0;
	struct snapraid_task* latest_not_canceled_task = 0;
	int report_level = LVL_INFO;
	int report_high_cmd = report_task->high_cmd;
	ss_t ss;

	pulse(state, PULSE_TASKS | PULSE_ACTIVITY);

	/* find the latest sync and scrub tasks from history */
	tommy_node* i = tommy_list_tail(&state->runner.history_list);
	while (i != 0) {
		struct snapraid_task* task = i->data;

		/* they should have the same queue time */
		if (task->unix_queue_time != report_task->unix_queue_time)
			break;

		/* keep track of the most critical level */
		report_level = level_mix(report_level, task_level(task));

		if (diff_task == 0 && task->cmd == CMD_DIFF)
			diff_task = task;

		if (fix_task == 0 && task->cmd == CMD_FIX)
			fix_task = task;

		if (sync_task == 0 && task->cmd == CMD_SYNC)
			sync_task = task;

		if (scrub_task == 0 && task->cmd == CMD_SCRUB)
			scrub_task = task;

		if (latest_not_canceled_task == 0 && task->state != PROCESS_STATE_CANCEL)
			latest_not_canceled_task = task;

		/* stop if we reached the head of the circular list */
		if (i == tommy_list_head(&state->runner.history_list))
			break;

		i = i->prev;
	}

	ss_init(&ss, 16384);

	struct snapraid_diff_stat* diff_stat = 0;

	/* if we run a diff completed, use its result as diff (note that its exit_code is 2 on differences) */
	if (diff_task != 0 && task_success(diff_task))
		diff_stat = &state->global.diff_current;

	/* if we have sync completed, use the previous diff stat */
	if (sync_task != 0 && task_success(sync_task))
		diff_stat = &state->global.diff_prev;

	report_locked(state, &ss, fix_task, sync_task, scrub_task, diff_stat);

	/* propagate the array health to the report task */
	/* do not call health_task() as the report cannot fail */
	report_task->health = runner_health_check_locked(state);
	if (report_task->health == HEALTH_CORRUPT || report_task->health == HEALTH_PREFAIL || report_task->health == HEALTH_FAILING)
		report_level = level_mix(report_level, LVL_CRITICAL);

	/* store the report (dup to shrink the allocation) */
	report_task->text_report = ss_dup(&ss);

	report_task->running = 0;
	report_task->state = PROCESS_STATE_TERM;
	report_task->exit_code = 0;
	report_task->unix_end_time = report_task->unix_start_time;

	/* insert the task in the done list */
	tommy_list_insert_tail(&state->runner.history_list, &report_task->node, report_task);

	/* set the latest pointer to the real executed task and not to the report */
	if (latest_not_canceled_task != 0)
		state->runner.latest = latest_not_canceled_task;

	/* notify the report */
	if (notify_locked(state, report_high_cmd, report_level, ss_extract(&ss)) != 0) {
		char exit_msg[MSG_MAX];
		report_task->exit_code = -1;
		snprintf(exit_msg, sizeof(exit_msg), "Notification failed (check " SYSLOG " for details)");
		message_insert(&report_task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, exit_msg);
	}

	ss_done(&ss);

	return 0;
}

/**
 * Check if the previous task can be omitted
 */
static struct snapraid_task* omit_task(struct snapraid_state* state, struct snapraid_task* task)
{
	if (tommy_list_empty(&state->runner.history_list))
		return 0;

	/* only if the new task is a new probe  */
	if (task->high_cmd != CMD_SUSPEND_IDLE || task->cmd != CMD_PROBE)
		return 0;

	struct snapraid_task* tail = tommy_list_tail(&state->runner.history_list)->data;

	/* only automatic probe are removed */
	if (tail->high_cmd != CMD_SUSPEND_IDLE || tail->cmd != CMD_PROBE)
		return 0;

	/* if something changed, it cannot be removed (note we don't check PULSE_DISKS_UI) */
	if ((tail->pulse & (PULSE_DISKS | PULSE_ARRAY)) != 0)
		return 0;

	/* previous node is the reference (being a circular list, it's never 0) */
	struct snapraid_task* reference = tail->node.prev->data;

	/* we need a reference probe different than the tail */
	if (tail == reference)
		return 0;

	/* the reference must be a probe */
	if (reference->high_cmd != CMD_SUSPEND_IDLE || reference->cmd != CMD_PROBE)
		return 0;

	return tail;
}

static void runner_go(struct snapraid_state* state)
{
	char hook_script[CONFIG_MAX];
	char hook_run_as_user[CONFIG_MAX];
	char msg[MSG_MAX];
	char exit_neg_msg[MSG_MAX];
	char sys_log_directory[PATH_MAX];
	time_t unix_start_time;
	time_t unix_queue_time;
	time_t unix_end_time;
	pid_t pid;
	int cmd;
	int high_cmd;
	int status;
	pid_t pid_ret;
	char** argv;
	int argc;
	tommy_node* j;
	int i;
	int number;
	struct snapraid_task* task = state->runner.latest;
	struct snapraid_pulse pulse_before = state->pulse;

	sncpy(hook_script, sizeof(hook_script), state->config.hook_script);
	sncpy(hook_run_as_user, sizeof(hook_run_as_user), state->config.hook_run_as_user);
	sncpy(sys_log_directory, sizeof(sys_log_directory), state->config.sys_log_directory);
	unix_queue_time = task->unix_queue_time;
	unix_start_time = task->unix_start_time;
	cmd = task->cmd;
	high_cmd = task->high_cmd;
	number = task->number;
	argc = tommy_list_count(&task->arg_list);
	argv = calloc_nofail(argc + 1, sizeof(char*));
	for (i = 0, j = tommy_list_head(&task->arg_list); i < argc; ++i, j = j->next) {
		sn_t* arg = j->data;
		argv[i] = strdup_nofail(arg->str);
	}
	argv[argc] = 0;
	exit_neg_msg[0] = 0;

	char log_path[PATH_MAX + 64]; /* avoid warnings about snprintf() */
	log_path[0] = 0;
	if (sys_log_directory[0] != 0) {
		int mkdir_ret = mkdir(sys_log_directory, 0755);
		if (mkdir_ret != 0 && errno != EEXIST) {
			log_msg(LVL_ERROR, "failed to create log directory %s, errno=%s(%d)", sys_log_directory, strerror(errno), errno);
		} else {
			time_t now = unix_start_time;
			struct tm res;
			struct tm* local = localtime_r(&now, &res);
			if (local) {
				snprintf(log_path, sizeof(log_path), "%s/%04d%02d%02d-%02d%02d%02d-%s.log", sys_log_directory,
					local->tm_year + 1900,
					local->tm_mon + 1,
					local->tm_mday,
					local->tm_hour,
					local->tm_min,
					local->tm_sec,
					command_name(cmd)
				);
			} else {
				snprintf(log_path, sizeof(log_path), "%s/%s.log", sys_log_directory, command_name(cmd));
			}

			sncpy(task->log_file, sizeof(task->log_file), log_path);
		}
	}

	/* check if the have to skip the script */
	int pre_script_skip = state->runner.script_skip;
	int post_script = 0;
	int post_script_skip = 0;
	state->runner.script_skip = 0;

	parser_mapping_start(state);

	/* check if the next task needs a script */
	int next_need_script = 0;
	j = tommy_list_head(&state->runner.waiting_list);
	if (j) {
		struct snapraid_task* waiting = j->data;
		next_need_script = runner_need_script(waiting->cmd);
	}

	state_unlock();

	int f = -1;
	FILE* log_f = 0;

	if (log_path[0] != 0) {
		log_f = fopen(log_path, "w" FOPEN_TEXT FOPEN_CLOEXEC);
		if (log_f == 0) {
			log_msg(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}

	if (log_f != 0) {
		fprintf(log_f, "daemon:number:%d\n", number);
		fprintf(log_f, "daemon:command:%s\n", command_name(cmd));
		if (high_cmd != 0 && high_cmd != cmd)
			fprintf(log_f, "daemon:high_command:%s\n", command_name(high_cmd));
		fprintf(log_f, "daemon:scheduled:%" PRIi64 "\n", unix_queue_time);
		fprintf(log_f, "daemon:start:%" PRIi64 "\n", unix_start_time);
		for (i = 0; i < argc; ++i)
			fprintf(log_f, "daemon:argv:%d:%s\n", i, argv[i]);
		fflush(log_f);
	}

	if (pre_script_skip == 0 && hook_script[0] != 0 && runner_need_script(cmd)) {
		char* hook_argv[3];
		char hook_event[KEYWORD_MAX];
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, hook_script);
		if (log_f != 0)
			fprintf(log_f, "daemon:pre:%s\n", hook_script);
		sncpy(hook_event, sizeof(hook_event), "task-begin");
		hook_argv[0] = hook_script;
		hook_argv[1] = hook_event;
		hook_argv[2] = 0;
		script_ret = os_script(hook_argv, hook_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s failed start, errno=%s(%d)", number, hook_script, strerror(errno), errno);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_fail\n");
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The pre_run_script failed to start (check " SYSLOG " for details), errno=%s(%d)", strerror(errno), errno);
			pid_ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, hook_script);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_term:0\n");
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s exit code %d", number, hook_script, script_ret);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_term:%d\n", script_ret);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The pre_run_script terminated with exit code %d", script_ret);
			pid_ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s signal %s(%d)", number, hook_script, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_signal:%d\n", script_ret - 128);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The pre_run_script terminated with signal %s(%d)", signal_name(script_ret - 128), script_ret - 128);
			pid_ret = -1;
			goto bail;
		}
		if (log_f)
			fflush(log_f);
	}

	int success = 0;
	pid = os_spawn(argv, &f);
	if (pid < 0) {
		log_msg(LVL_ERROR, "task %d run %s failed spawn, errno=%s(%d)", number, command_name(cmd), strerror(errno), errno);
		snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The task %s failed to spawn (check " SYSLOG " for details), errno=%s(%d)", command_name(cmd), strerror(errno), errno);
		pid_ret = -1;
		/* continue to run the hook_script */
	} else {
		if (log_f != 0)
			log_msg(LVL_INFO, "task %d run %s (pid %" PRIu64 ") with log %s", number, command_name(cmd), (uint64_t)pid, log_path);
		else
			log_msg(LVL_INFO, "task %d run %s (pid %" PRIu64 ")", number, command_name(cmd), (uint64_t)pid);

		/* store the pid to allow stop actions */
		state_lock();
		task->pid = pid;
		state_unlock();

		parse_log(state, f, log_f, log_path);

		/* wait for the child process to terminate */
		pid_ret = os_wait(pid, &status);

		if (pid_ret == -1) {
			log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") failed wait, errno=%s(%d)", number, command_name(cmd), (uint64_t)pid, strerror(errno), errno);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The task %s failed to wait, errno=%s(%d)", command_name(cmd), strerror(errno), errno);
			if (log_f != 0)
				fprintf(log_f, "daemon:fail\n");
		} else {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0) {
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ")", number, command_name(cmd), (uint64_t)pid);
					success = 1;
				} else {
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") exit code %d", number, command_name(cmd), (uint64_t)pid, WEXITSTATUS(status));
				}
				if (log_f != 0)
					fprintf(log_f, "daemon:term:%d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") signal %s(%d)", number, command_name(cmd), (uint64_t)pid, signal_name(WTERMSIG(status)), WTERMSIG(status));
				if (log_f != 0)
					fprintf(log_f, "daemon:signal:%d\n", WTERMSIG(status));
			}
		}
		if (log_f)
			fflush(log_f);
	}

	/* if the next task uses the script, skip the post */
	if (hook_script[0] != 0 && runner_need_script(cmd)) {
		post_script = 1;

		if (pid_ret != -1
			&& WIFEXITED(status)
			&& WEXITSTATUS(status) == 0
			&& next_need_script) {
			/* postpone */
			post_script = 0;
			post_script_skip = 1;
		}
	}

	if (post_script) {
		char* hook_argv[3];
		char hook_event[KEYWORD_MAX];
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, hook_script);
		if (log_f != 0)
			fprintf(log_f, "daemon:post:%s\n", hook_script);
		if (success)
			sncpy(hook_event, sizeof(hook_event), "task-end");
		else
			sncpy(hook_event, sizeof(hook_event), "task-error");
		hook_argv[0] = hook_script;
		hook_argv[1] = hook_event;
		hook_argv[2] = 0;
		script_ret = os_script(hook_argv, hook_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s failed start (check " SYSLOG " for details), errno=%s(%d)", number, hook_script, strerror(errno), errno);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_fail\n");
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The post_run_script failed to start, errno=%s(%d)", strerror(errno), errno);
			pid_ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, hook_script);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_term:0\n");
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s exit code %d", number, hook_script, script_ret);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_term:%d\n", script_ret);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The post_run_script terminated with exit code %d", script_ret);
			pid_ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s signal %s(%d)", number, hook_script, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_signal:%d\n", script_ret - 128);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The post_run_script terminated with signal %s(%d)", signal_name(script_ret - 128), script_ret - 128);
			pid_ret = -1;
			goto bail;
		}
		if (log_f)
			fflush(log_f);
	}

bail:
	unix_end_time = time(0);
	if (unix_end_time < unix_start_time)
		unix_end_time = unix_start_time; /* time start time may be in the future of few seconds to guarantee uniqueness */

	/* store if the script was skipped */
	if (post_script_skip)
		state->runner.script_skip = 1;

	if (log_f != 0) {
		fprintf(log_f, "daemon:end:%" PRIi64 "\n", unix_end_time);
		if (fclose(log_f) != 0) {
			log_msg(LVL_WARNING, "failed to close log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}

	if (f != -1)
		close(f);

	for (i = 0; i < argc; ++i)
		free(argv[i]);
	free(argv);

	state_lock();

	/* the task is not running anymore */
	task->running = 0;
	task->unix_end_time = unix_end_time;

	/* compute the task health */
	task->health = health_task(task);

	/* check the array health, but DO NOT propagate it to the task */
	runner_health_check_locked(state);

	/* compare the pulse (after evaluating the array health) */
	task->pulse = pulse_rev(state, &pulse_before);

	/* if task completed succesfully */
	if (pid_ret != -1
		&& WIFEXITED(status)
		&& WEXITSTATUS(status) == 0
	) {
		struct snapraid_task* omit = omit_task(state, task);
		if (omit) {
			log_msg(LVL_INFO, "task %d removed probe for no activity", omit->number);
			/* delete its log file */
			if (omit->log_file[0]) {
				if (remove(omit->log_file) != 0) {
					log_msg(LVL_WARNING, "failed to close remove log file %s, errno=%s(%d)", omit->log_file, strerror(errno), errno);
				}
			}
			/* remove from the list */
			tommy_list_remove_existing(&state->runner.history_list, &omit->node);
			task_free(omit);
		}
	}

	/* insert the task in the done list, but keep it in the latest pointer */
	pulse(state, PULSE_TASKS | PULSE_ACTIVITY);
	tommy_list_insert_tail(&state->runner.history_list, &task->node, task);

	if (pid_ret == -1) {
		task->exit_code = -1;
		task->state = PROCESS_STATE_TERM;

		message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, exit_neg_msg);

		/* cancel queued tasks */
		snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);
		task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
	} else {
		if (WIFEXITED(status)) {
			/* child's exit(code) or return from main */
			task->exit_code = WEXITSTATUS(status);
			task->state = PROCESS_STATE_TERM;

			parser_mapping_done(state, task);

			if (!task_success(task)) {
				/* cancel all queued tasks on failure */
				snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);
				task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
			}
		} else if (WIFSIGNALED(status)) {
			/* child died from a signal */
			task->exit_sig = WTERMSIG(status);
			task->state = PROCESS_STATE_SIGNAL;

			/* cancel queued tasks */
			snprintf(msg, sizeof(msg), "The preceding %s operation was signaled with signal %s(%d)", command_name(cmd), signal_name(task->exit_sig), task->exit_sig);
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
		} else {
			/* it should never happen */
			task->exit_code = -1;
			task->state = PROCESS_STATE_TERM;

			/* cancel queued tasks */
			snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
		}
	}
}

static int runner_precondition(struct snapraid_state* state)
{
	struct snapraid_task* task = state->runner.latest;

	switch (task->cmd) {
	case CMD_PROBE :
	case CMD_UP :
	case CMD_DOWN :
	case CMD_SMART :
	case CMD_LIST :
	case CMD_DUP :
	case CMD_STATUS :
	case CMD_READ :
	case CMD_REPORT :
	case CMD_DOWN_IDLE :
		/* these taks are allowed regardless the health */
		break;
	default :
		/* other commands are run only if the array is sane */
		if (state->global.health == HEALTH_PREFAIL) {
			const char* msg = "Array is in PREFAIL! Task aborted!";
			sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), msg);
			message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_HARDWARE, msg);
			return -1;
		}

		if (state->global.health == HEALTH_FAILING) {
			const char* msg = "Array is FAILING!!! Task aborted!!!";
			sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), msg);
			message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_HARDWARE, msg);
			return -1;
		}
		break;
	}

	return 0;
}

static void runner_spindown_inactive_locked(struct snapraid_state* state)
{
	struct snapraid_task* task = state->runner.latest;
	int count = 0;

	int spindown_idle_minutes = state->config.spindown_idle_minutes;
	if (spindown_idle_minutes == 0)
		return; /* nothing to do */

	/* insert in the argument list the disk to spin down */
	for (tommy_node* i = tommy_list_head(&state->disk_list); i; i = i->next) {
		struct snapraid_disk* disk = i->data;
		int active = 0;

		/* do not spin down extra disks */
		if (disk->kind == DISK_EXTRA)
			continue;

		for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
			struct snapraid_device* device = j->data;
			/* POWER_PENDING is not really possible, because if we have the idle time to reach here we also have the power state */
			if (device->power == POWER_ACTIVE)
				active = 1;
		}

		int unused_minutes = (disk->access_count_latest_time - disk->access_count_initial_time) / 60;
		if (active && unused_minutes >= spindown_idle_minutes) {
			char msg[MSG_MAX];
			snprintf(msg, sizeof(msg), "Selecting disk %s unused by %d minutes", disk->name, unused_minutes);
			message_insert(&task->message_list, MESSAGE_LEVEL_INFO, MESSAGE_TYPE_NONE, msg);
			sl_insert_str(&task->arg_list, "-d");
			sl_insert_str(&task->arg_list, disk->name);
			++count;
		}
	}

	/* no count, nothing to do */
	if (count == 0) {
		/* set the latest task from the history, if any */
		tommy_node* tail = tommy_list_tail(&state->runner.history_list);
		if (tail) {
			state->runner.latest = tail->data;
		} else {
			state->runner.latest = 0;
		}

		/* free the down_idle task */
		task_free(task);
	} else {
		runner_go(state);
	}
}

static void* runner_thread(void* arg)
{
	struct snapraid_state* state = arg;

	state_lock();

	while (1) {
		while (state->daemon_running /* daemon is still running */
			&& (state->runner.latest == 0 || !state->runner.latest->running) /* no task is running */
			&& !tommy_list_empty(&state->runner.waiting_list)) { /* there is something to run */

			time_t now = time(0);

			pulse(state, PULSE_TASKS | PULSE_ACTIVITY);

			/* setup a new task to run */
			struct snapraid_task* task = tommy_list_remove_existing(&state->runner.waiting_list, tommy_list_head(&state->runner.waiting_list));
			task_set_unique_start_time(state, task, now);

			/* set in the latest */
			state->runner.latest = task;

			if (task->cmd == CMD_REPORT) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				runner_report_locked(state);
			} else if (runner_precondition(state) == 0) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				if (task->cmd == CMD_DOWN_IDLE) {
					runner_spindown_inactive_locked(state);
				} else {
					runner_go(state);
				}
			} else {
				task->state = PROCESS_STATE_CANCEL;
				task->unix_start_time = now; /* here we don't care about uniqueness as canceled tasks are not stored */
				task->unix_end_time = task->unix_start_time;
				log_msg(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));

				/* insert in the history */
				tommy_list_insert_tail(&state->runner.history_list, &task->node, task);
			}
		}

		if (!state->daemon_running)
			break;

		thread_cond_wait(&state->runner.cond, &state->state_lock);
	}

	state_unlock();

	return 0;
}

void runner_init(struct snapraid_state* state)
{
	thread_cond_init(&state->runner.cond);

	/* start the runner thread */
	thread_create(&state->runner.thread_id, runner_thread, state);
}

void runner_done(struct snapraid_state* state)
{
	void* retval;

	state_lock(); /* locking makes helgrind happy in the signal */

	/* signal the condition to allow the thread to stop */
	thread_cond_signal(&state->runner.cond);

	state_unlock();

	/* wait for the thread termination */
	thread_join(state->runner.thread_id, &retval);

	thread_cond_destroy(&state->runner.cond);
}

static int runner_with_lock(struct snapraid_state* state, int lock, int high_cmd, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status)
{
	if (lock)
		state_lock();

	const char* snapraid = os_find_engine(state->config.sys_engine);
	if (!snapraid) {
		if (lock)
			state_unlock();
		log_msg(LVL_ERROR, "snapraid executable not found");
		sncpy(msg, msg_size, "SnapRAID executable not found");
		*status = 500;
		return -1;
	}

	sncpy(msg, msg_size, "");

	if (now == 0)
		now = time(0);

	struct snapraid_task* task = task_alloc();
	task->cmd = cmd;
	task->high_cmd = high_cmd;
	task->unix_queue_time = now;

	/* translate some commands */
	int cmd_translate = cmd;
	switch (cmd_translate) {
	case CMD_DOWN_IDLE :
		cmd_translate = CMD_DOWN;
		break;
	}

	sl_insert_str(&task->arg_list, snapraid);
	sl_insert_str(&task->arg_list, command_name(cmd_translate));
	sl_insert_str(&task->arg_list, "--gui");
	sl_insert_str(&task->arg_list, "--log");
	sl_insert_str(&task->arg_list, ">&2");
	if (arg_list) {
		task->arg_custom = tommy_list_count(&task->arg_list);
		sl_insert_list(&task->arg_list, arg_list);
	}

	pulse(state, PULSE_TASKS | PULSE_ACTIVITY);

	if (!state->daemon_running) {
		if (lock)
			state_unlock();
		task_free(task);
		log_msg(LVL_ERROR, "failed to start runner %s because daemon is terminating", command_name(cmd));
		sncpy(msg, msg_size, "Daemon is terminating");
		*status = 503;
		return -1;
	}

	task->number = ++state->runner.number_allocator;

	/* insert the task in the queue */
	tommy_list_insert_tail(&state->runner.waiting_list, &task->node, task);

	/* signal the runner thread that there is a task to execute */
	thread_cond_signal(&state->runner.cond);

	if (lock)
		state_unlock();

	*status = 202;
	return 0;
}

int runner_locked(struct snapraid_state* state, int high_cmd, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status)
{
	return runner_with_lock(state, 0, high_cmd, cmd, now, arg_list, msg, msg_size, status);
}

int runner(struct snapraid_state* state, int high_cmd, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status)
{
	return runner_with_lock(state, 1, high_cmd, cmd, now, arg_list, msg, msg_size, status);
}

/**
 * Deletes all **regular files** in the specified directory (non-recursively)
 * that have a name representing a time older than N days.
 *
 * Note:
 * - This function does **not** recurse into subdirectories.
 * - It skips "." and ".." entries.
 * - It only deletes regular files (not directories, symlinks, etc.).
 */
static int delete_old_files(const char* dir_path, int days)
{
	DIR* dir = opendir(dir_path);
	if (dir == NULL) {
		log_msg(LVL_ERROR, "failed to open directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	time_t now = time(0);
	time_t cutoff_seconds = now - days * (int64_t)24 * 60 * 60;

	struct dirent* ent;
	while ((ent = readdir(dir)) != 0) {
		char full_path[PATH_MAX + 256]; /* avoid warnings about snprintf() */

		if (ent->d_name[0] == '.')
			continue;

		/* construct full path */
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, ent->d_name);

		/* only files matching the pattern */
		time_t ntime;
		if (parse_timestamp(ent->d_name, &ntime) != 0)
			continue;

		/* only files that are old enough */
		if (ntime >= cutoff_seconds)
			continue;

		if (unlink(full_path) == -1) {
			log_msg(LVL_ERROR, "failed to delete file %s, errno=%s(%d)", full_path, strerror(errno), errno);
			/* continue trying to delete others */
		}
	}

	if (closedir(dir) == -1) {
		log_msg(LVL_ERROR, "failed to close directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	return 0;
}

int runner_delete_old_log(struct snapraid_state* state, char* msg, size_t msg_size, int* status)
{
	char sys_log_directory[PATH_MAX];
	int sys_log_retention_days;

	sncpy(msg, msg_size, "");

	state_lock();
	sncpy(sys_log_directory, sizeof(sys_log_directory), state->config.sys_log_directory);
	sys_log_retention_days = state->config.sys_log_retention_days;
	state_unlock();

	if (delete_old_files(sys_log_directory, sys_log_retention_days) != 0) {
		sncpy(msg, msg_size, "Failed deleting old log files");
		*status = 500;
		return 0;
	}

	*status = 200;
	return 0;
}

int runner_delete_old_history(struct snapraid_state* state, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);
	time_t cutoff_seconds = now - HISTORY_PAST_DAYS * SECONDS_IN_A_DAY;

	sncpy(msg, msg_size, "");

	state_lock();

	pulse(state, PULSE_TASKS);

	int count = tommy_list_count(&state->runner.history_list);

	tommy_node* i = tommy_list_head(&state->runner.history_list);
	while (i) {
		struct snapraid_task* task = i->data;
		tommy_node* i_next = i->next;

		if (task->unix_start_time < cutoff_seconds || count >= HISTORY_TASKS_MAX) {
			/* remove and free */
			tommy_list_remove_existing(&state->runner.history_list, &task->node);
			task_free(task);
		}

		--count;

		i = i_next;
	}

	state_unlock();

	*status = 200;
	return 0;
}

int runner_stop(struct snapraid_state* state, char* msg, size_t msg_size, int* status, pid_t* stop_pid, int* stop_number)
{
	pid_t pid;
	int number;

	sncpy(msg, msg_size, "");

	state_lock();

	pulse(state, PULSE_ACTIVITY);

	struct snapraid_task* task = state->runner.latest;
	if (!task || !task->running || task->pid <= 0) {
		sncpy(msg, msg_size, "No task running");
		*status = 409;
		state_unlock();
		return -1;
	}

	pid = task->pid;
	number = task->number;

	message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, "Sent SIGTERM signal from STOP command");

	state_unlock();

	*stop_pid = pid;
	*stop_number = number;

	if (pid > 0) {
		if (os_term(pid) != 0) {
			log_msg(LVL_ERROR, "failed to send SIGTERM to task %d (pid %" PRIu64 "), errno=%s(%d)", number, (uint64_t)pid, strerror(errno), errno);
			sncpy(msg, msg_size, "Failed to stop task");
			*status = 500;
			return -1;
		}

		log_msg(LVL_INFO, "sent SIGTERM to task %d (pid %" PRIu64 ")", number, (uint64_t)pid);
	}

	sncpy(msg, msg_size, "Signal sent");
	*status = 202;
	return 0;
}

