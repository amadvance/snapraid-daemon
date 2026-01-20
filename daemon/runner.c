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
#include "runner.h"

/****************************************************************************/
/* runner */

static int runner_need_script(int cmd)
{
	switch (cmd) {
	case CMD_SYNC : return 1;
	case CMD_SCRUB : return 1;
	case CMD_FIX : return 1;
	}

	return 0;
}

static int runner_report(struct snapraid_state* state)
{
	struct snapraid_task* report_task = state->runner.latest;
	struct snapraid_task* sync_task = 0;
	struct snapraid_task* scrub_task = 0;
	ss_t ss;

	/* find the latest sync and scrub tasks from history */
	tommy_node* i = tommy_list_tail(&state->runner.history_list);
	while (i != 0) {
		struct snapraid_task* task = i->data;

		/* they should have the same queue time */
		if (task->unix_queue_time != report_task->unix_queue_time)
			break;

		if (task->cmd == CMD_SYNC && !sync_task)
			sync_task = task;

		if (task->cmd == CMD_SCRUB && !scrub_task)
			scrub_task = task;

		/* stop if we found both */
		if (sync_task != 0 && scrub_task != 0)
			break;

		/* stop if we reached the head of the circular list */
		if (i == tommy_list_head(&state->runner.history_list))
			break;

		i = i->prev;
	}

	ss_init(&ss, 8192);

	if (report(state, &ss, sync_task, scrub_task) != 0) {
		ss_done(&ss);
		log_msg(LVL_ERROR, "failed to generate report");
		return -1;
	}

	/* TODO log the report */
	printf("%s\n", ss_ptr(&ss));

	ss_done(&ss);

	return 0;
}

static void runner_go(struct snapraid_state* state)
{
	char script_pre_run[CONFIG_MAX];
	char script_post_run[CONFIG_MAX];
	char script_run_as_user[CONFIG_MAX];
	char msg[128];
	char log_directory[PATH_MAX];
	time_t unix_start_time;
	time_t unix_queue_time;
	time_t unix_end_time;
	pid_t pid;
	int cmd;
	int status;
	pid_t ret;
	char** argv;
	int argc;
	tommy_node* j;
	int i;
	int number;
	struct snapraid_task* task = state->runner.latest;

	sncpy(script_pre_run, sizeof(script_pre_run), state->config.script_pre_run);
	sncpy(script_post_run, sizeof(script_post_run), state->config.script_post_run);
	sncpy(script_run_as_user, sizeof(script_run_as_user), state->config.script_run_as_user);
	sncpy(log_directory, sizeof(log_directory), state->config.log_directory);
	unix_queue_time = task->unix_queue_time;
	unix_start_time = task->unix_start_time;
	cmd = task->cmd;
	number = task->number;
	argc = tommy_list_count(&task->arg_list);
	argv = calloc_nofail(argc + 1, sizeof(char*));
	for (i = 0, j = tommy_list_head(&task->arg_list); i < argc; ++i, j = j->next) {
		sn_t* arg = j->data;
		argv[i] = strdup_nofail(arg->str);
	}
	argv[argc] = 0;

	char log_path[PATH_MAX + 64]; /* avoid warnings about snprintf() */
	log_path[0] = 0;
	if (log_directory[0] != 0) {
		time_t now = unix_start_time;
		struct tm* local = localtime(&now);
		if (local) {
			snprintf(log_path, sizeof(log_path), "%s/%04d%02d%02d-%02d%02d%02d-%s.log", log_directory,
				local->tm_year + 1900,
				local->tm_mon + 1,
				local->tm_mday,
				local->tm_hour,
				local->tm_min,
				local->tm_sec,
				command_name(cmd)
			);
		} else {
			snprintf(log_path, sizeof(log_path), "%s/%s.log", log_directory, command_name(cmd));
		}

		sncpy(task->log_file, sizeof(task->log_file), log_path);
	}

	if (cmd == CMD_SYNC || cmd == CMD_DIFF) {
		/* these commands output a new diff list, so cleanup it */
		tommy_list_foreach(&state->global.diff_list, diff_free);
	}

	state_unlock();

	int f = -1;
	FILE* log_f = 0;

	if (log_path[0] != 0) {
		log_f = fopen(log_path, "wte");
		if (log_f == 0) {
			log_msg(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}

	if (log_f != 0) {
		fprintf(log_f, "daemon:command:%s\n", command_name(cmd));
		fprintf(log_f, "daemon:scheduled:%" PRIi64 "\n", unix_queue_time);
		fprintf(log_f, "daemon:start:%" PRIi64 "\n", unix_start_time);
	}

	if (script_pre_run[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, script_pre_run);
		if (log_f != 0)
			fprintf(log_f, "daemon:pre:%s\n", script_pre_run);
		script_ret = os_script(script_pre_run, script_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s with failed run", number, script_pre_run);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_fail\n");
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, script_pre_run);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_term:0\n");
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s with return code %d", number, script_pre_run, script_ret);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_term:%d\n", script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s with signal %s(%d)", number, script_pre_run, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				fprintf(log_f, "daemon:pre_signal:%d\n", script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

	pid = os_spawn(argv, &f);
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to start task %d run %s due to failed spawn, errno=%s(%d)", number, command_name(cmd), strerror(errno), errno);
		ret = -1;
		/* continue to run the script_post_run */
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
		do {
			ret = waitpid(pid, &status, 0);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with failed wait", number, command_name(cmd), (uint64_t)pid);
			if (log_f != 0)
				fprintf(log_f, "daemon:fail\n");
		} else {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0)
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ")", number, command_name(cmd), (uint64_t)pid);
				else
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with exit code %d", number, command_name(cmd), (uint64_t)pid, WEXITSTATUS(status));
				if (log_f != 0)
					fprintf(log_f, "daemon:term:%d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with signal %s(%d)", number, command_name(cmd), (uint64_t)pid, signal_name(WTERMSIG(status)), WTERMSIG(status));
				if (log_f != 0)
					fprintf(log_f, "daemon:signal:%d\n", WTERMSIG(status));
			}
		}
	}

	if (script_post_run[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, script_post_run);
		if (log_f != 0)
			fprintf(log_f, "daemon:post:%s\n", script_post_run);

		script_ret = os_script(script_post_run, script_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s with failed run", number, script_post_run);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_fail\n");
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, script_post_run);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_term:0\n");
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s with exit code %d", number, script_post_run, script_ret);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_term:%d\n", script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s with signal %s(%d)", number, script_post_run, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				fprintf(log_f, "daemon:post_signal:%d\n", script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

bail:
	unix_end_time = time(0);

	if (log_f != 0)
		fprintf(log_f, "daemon:end:%" PRIi64 "\n", unix_end_time);

	if (log_f != 0) {
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
	state->runner.latest->unix_end_time = unix_end_time;

	/* insert the task in the done list, but keep it in the latest pointer */
	tommy_list_insert_tail(&state->runner.history_list, &task->node, task);

	if (ret == -1) {
		task->exit_code = -1;
		task->state = PROCESS_STATE_TERM;

		snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);

		/* cancel all queued tasks */
		task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
	} else {
		if (WIFEXITED(status)) {
			/* child's exit(code) or return from main */
			task->exit_code = WEXITSTATUS(status);
			task->state = PROCESS_STATE_TERM;

			snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);

			/* cancel all queued tasks on failure */
			if (task->exit_code != 0)
				task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
		} else if (WIFSIGNALED(status)) {
			/* child died from a signal */
			task->exit_sig = WTERMSIG(status);
			task->state = PROCESS_STATE_SIGNAL;

			snprintf(msg, sizeof(msg), "The preceding %s operation was signaled with signal %s(%d)", command_name(cmd), signal_name(task->exit_sig), task->exit_sig);

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
		} else {
			/* it should never happen */
			task->exit_code = -1;
			task->state = PROCESS_STATE_TERM;
			
			snprintf(msg, sizeof(msg), "The preceding %s operation failed with exit code %d", command_name(cmd), task->exit_code);

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list, msg);
		}
	}
}

static int runner_precondition(struct snapraid_state* state)
{
	struct snapraid_task* task = state->runner.latest;

	if (task->cmd == CMD_SYNC) {
		if (state->config.sync_threshold_deletes) {
			if (state->global.diff_removed >= state->config.sync_threshold_deletes) {
				sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), "Too many deleted files");
				return -1;
			}
		}

		if (state->config.sync_threshold_updates) {
			if (state->global.diff_updated >= state->config.sync_threshold_deletes) {
				sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), "Too many updated files");
				return -1;
			}
		}
	}
	
	return 0;
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

			/* setup a new task to run */
			struct snapraid_task* task = tommy_list_remove_existing(&state->runner.waiting_list, tommy_list_head(&state->runner.waiting_list));
			task->unix_start_time = now;

			/* set in the latest */
			state->runner.latest = task;

			if (task->cmd == CMD_REPORT) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				runner_report(state);
				task->running = 0;
				task->state = PROCESS_STATE_TERM;
				task->unix_end_time = now;
			} else if (runner_precondition(state) == 0) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				runner_go(state);
			} else {
				task->state = PROCESS_STATE_CANCEL;
				task->unix_end_time = now;
			}
		}

		if (!state->daemon_running)
			break;

		thread_cond_wait(&state->runner.cond, &state->lock);
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

	/* signal the condition to allow the thread to stop */
	thread_cond_signal(&state->runner.cond);

	/* wait for the thread termination */
	thread_join(state->runner.thread_id, &retval);

	thread_cond_destroy(&state->runner.cond);
}

static const char* snapraid_paths[] = {
	/* Linux & BSD */
	"/usr/bin/snapraid",
	"/usr/local/bin/snapraid",
#ifdef __APPLE__
	/* macOS (Intel & Apple Silicon) */
	"/opt/homebrew/bin/snapraid",
#endif
	0
};

const char* find_snapraid(void)
{
	for (int i = 0; snapraid_paths[i]; ++i) {
		if (access(snapraid_paths[i], X_OK) == 0)
			return snapraid_paths[i];
	}

	return 0;
}

int runner(struct snapraid_state* state, int cmd, time_t now, sl_t* arg_list, char* msg, size_t msg_size, int* status)
{
	const char* snapraid = find_snapraid();
	if (!snapraid) {
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
	task->unix_queue_time = now;

	sl_insert_str(&task->arg_list, snapraid);
	sl_insert_str(&task->arg_list, command_name(cmd));
	sl_insert_str(&task->arg_list, "--gui");
	sl_insert_str(&task->arg_list, "--log");
	sl_insert_str(&task->arg_list, ">&2");
	if (arg_list)
		sl_insert_list(&task->arg_list, arg_list);

	state_lock();

	if (!state->daemon_running) {
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

	state_unlock();

	*status = 202;
	return 0;
}

int runner_spindown_inactive(struct snapraid_state* state, char* msg, size_t msg_size, int* status)
{
	int ret;
	sl_t arg_list;

	sncpy(msg, msg_size, "");
	sl_init(&arg_list);

	state_lock();

	int spindown_idle_minutes = state->config.spindown_idle_minutes;

	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_data* data = i->data;
		int active = 0;

		for (tommy_node* k = tommy_list_head(&data->device_list); k; k = k->next) {
			struct snapraid_device* device = k->data;
			/* POWER_PENDING is not really possible, because if we have the idle time to reach here we also have the power state */
			if (device->power == POWER_ACTIVE)
				active = 1;
		}

		if (active
			&& (data->access_count_latest_time - data->access_count_initial_time) / 60 >= spindown_idle_minutes) {
			sl_insert_str(&arg_list, "-d");
			sl_insert_str(&arg_list, data->name);
		}
	}

	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_parity* parity = i->data;
		int active = 0;

		for (tommy_node* j = tommy_list_head(&parity->split_list); j; j = j->next) {
			struct snapraid_split* split = j->data;

			for (tommy_node* k = tommy_list_head(&split->device_list); k; k = k->next) {
				struct snapraid_device* device = k->data;
				/* POWER_PENDING is not really possible, because if we have the idle time to reach here we also have the power state */
				if (device->power == POWER_ACTIVE)
					active = 1;
			}
		}

		if (active
			&& (parity->access_count_latest_time - parity->access_count_initial_time) / 60 >= spindown_idle_minutes) {
			sl_insert_str(&arg_list, "-d");
			sl_insert_str(&arg_list, parity->name);
		}
	}

	state_unlock();

	if (tommy_list_empty(&arg_list)) {
		sncpy(msg, msg_size, "Nothing to do");
		*status = 200;
		ret = 0;
	} else {
		ret = runner(state, CMD_DOWN, 0, &arg_list, msg, msg_size, status);
	}

	sl_free(&arg_list);

	return ret;
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
	char log_directory[PATH_MAX];
	int log_retention_days;

	sncpy(msg, msg_size, "");

	state_lock();
	sncpy(log_directory, sizeof(log_directory), state->config.log_directory);
	log_retention_days = state->config.log_retention_days;
	state_unlock();

	if (delete_old_files(log_directory, log_retention_days) != 0) {
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

	tommy_node* i = tommy_list_head(&state->runner.history_list);
	while (i) {
		struct snapraid_task* task = i->data;

		i = i->next; /* go to next before removal */

		if (task->unix_start_time < cutoff_seconds) {
			/* remove and free */
			task_free(tommy_list_remove_existing(&state->runner.history_list, i));
		}
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

	struct snapraid_task* task = state->runner.latest;
	if (!task || !task->running || task->pid <= 0) {
		sncpy(msg, msg_size, "No task running");
		*status = 409;
		state_unlock();
		return -1;
	}

	pid = task->pid;
	number = task->number;

	state_unlock();

	*stop_pid = pid;
	*stop_number = number;

	if (pid > 0) {
		/*
		 * Send signal to the negative PID to target the entire Process Group.
		 * This ensures that SnapRAID and any programs it may have spawned are
		 * terminated together, preventing orphaned worker processes.
		 */
		if (kill(-pid, SIGTERM) != 0) {
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
