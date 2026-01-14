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
#include "runner.h"

/****************************************************************************/
/* task */

struct snapraid_task* task_alloc(void)
{
	struct snapraid_task* task = calloc_nofail(1, sizeof(struct snapraid_task));
	sl_init(&task->arg_list);
	sl_init(&task->message_list);
	return task;
}

void task_free(struct snapraid_task* task)
{
	if (!task)
		return;
	sl_free(&task->arg_list);
	sl_free(&task->message_list);
	sl_free(&task->error_list);
	free(task);
}

/**
 * Move all the task in the done list
 */
void task_list_cancel(tommy_list* waiting_list, tommy_list* history_list)
{
	for (tommy_node* i = tommy_list_head(waiting_list); i != 0; i = i->next) {
		struct snapraid_task* task = i->data;
		task->state = PROCESS_STATE_CANCEL;
		log_msg_lock(LVL_WARNING, "task %d cancel %s", task->number, runner_cmd(task->cmd));
		tommy_list_insert_tail(history_list, &task->node, task);
	}
	tommy_list_init(waiting_list);
}


/****************************************************************************/
/* runner */

const char* runner_cmd(int cmd)
{
	switch (cmd) {
	case CMD_PROBE : return "probe";
	case CMD_UP : return "up";
	case CMD_DOWN : return "down";
	case CMD_SMART : return "smart";
	case CMD_STATUS : return "status";
	case CMD_LIST : return "list";
	case CMD_DIFF : return "diff";
	case CMD_SYNC : return "sync";
	case CMD_SCRUB : return "scrub";
	case CMD_FIX : return "fix";
	case CMD_CHECK : return "check";
	}

	return 0;
}

static int runner_need_script(int cmd)
{
	switch (cmd) {
	case CMD_SYNC : return 1;
	case CMD_SCRUB : return 1;
	case CMD_FIX : return 1;
	}

	return 0;
}

static void runner_go(struct snapraid_state* state)
{
	char script_pre_run[CONFIG_MAX];
	char script_post_run[CONFIG_MAX];
	char script_run_as_user[CONFIG_MAX];
	int f;
	pid_t pid;
	int cmd;
	int status;
	pid_t ret;
	char** argv;
	int argc;
	tommy_node* j;
	int i;
	int number;

	sncpy(script_pre_run, sizeof(script_pre_run), state->config.script_pre_run);
	sncpy(script_post_run, sizeof(script_post_run), state->config.script_post_run);
	sncpy(script_run_as_user, sizeof(script_run_as_user), state->config.script_run_as_user);
	cmd = state->runner.latest->cmd;
	number = state->runner.latest->number;
	argc = tommy_list_count(&state->runner.latest->arg_list);
	argv = calloc_nofail(argc + 1, sizeof(char*));
	for (i = 0, j = tommy_list_head(&state->runner.latest->arg_list); i < argc; ++i, j = j->next) {
		sn_t* arg = j->data;
		argv[i] = strdup_nofail(arg->str);
	}
	argv[argc] = 0;

	state_unlock();

	f = -1;

	if (script_pre_run[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, script_pre_run);
		script_ret = os_script(script_pre_run, script_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s with failed run", number, script_pre_run);
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, script_pre_run);
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s with return code %d", number, script_pre_run, script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s with signal %s(%d)", number, script_pre_run, log_signame(script_ret - 128), script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

	pid = os_spawn(argv, &f);
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to start task %d run %s for a failed spawn, errno=%s(%d)", number, runner_cmd(cmd), strerror(errno), errno);
		ret = -1;
		/* continue to run the script_post_run */
	} else {
		char log_path[PATH_MAX];

		log_path[0] = 0;

		if (state->config.log_directory[0] != 0) {
			time_t now = time(0);
			struct tm* local = localtime(&now);
			if (local) {
				snprintf(log_path, sizeof(log_path), "%s/%04d%02d%02d-%02d%02d%02d-%s.log", state->config.log_directory,
					local->tm_year + 1900,
					local->tm_mon + 1,
					local->tm_mday,
					local->tm_hour,
					local->tm_min,
					local->tm_sec,
					runner_cmd(cmd)
				);
			} else {
				snprintf(log_path, sizeof(log_path), "%s/%s.log", state->config.log_directory, runner_cmd(cmd));
			}
		}

		if (log_path[0])
			log_msg(LVL_INFO, "task %d run %s (pid %" PRIu64 ") with log %s", number, runner_cmd(cmd), (uint64_t)pid, log_path);
		else
			log_msg(LVL_INFO, "task %d run %s (pid %" PRIu64 ")", number, runner_cmd(cmd), (uint64_t)pid);

		parse_log(state, f, log_path);

		/* wait for the child process to terminate */
		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with failed run", number, runner_cmd(cmd), (uint64_t)pid);
		} else {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0)
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ")", number, runner_cmd(cmd), (uint64_t)pid);
				else
					log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with exit code %d", number, runner_cmd(cmd), (uint64_t)pid, WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				log_msg(LVL_INFO, "task %d end %s (pid %" PRIu64 ") with signal %s(%d)", number, runner_cmd(cmd), (uint64_t)pid, log_signame(WTERMSIG(status)), WTERMSIG(status));
			}
		}
	}

	if (script_post_run[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "task %d run %s", number, script_post_run);
		script_ret = os_script(script_post_run, script_run_as_user);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "task %d end %s with failed run", number, script_post_run);
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "task %d end %s", number, script_post_run);
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "task %d end %s with exit code %d", number, script_post_run, script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "task %d end %s with signal %s(%d)", number, script_post_run, log_signame(script_ret - 128), script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

bail:
	if (f != -1)
		close(f);

	for (i = 0; i < argc; ++i)
		free(argv[i]);
	free(argv);

	state_lock();

	struct snapraid_task* task = state->runner.latest;

	/* the task is not running anymore */
	task->running = 0;
	state->runner.latest->unix_end_time = time(0);

	/* insert the task in the done list, but keep it in the latest pointer */
	tommy_list_insert_tail(&state->runner.history_list, &task->node, task);

	if (ret == -1) {
		task->exit_code = -1;
		task->state = PROCESS_STATE_TERM;

		/* cancel all queued tasks */
		task_list_cancel(&state->runner.waiting_list, &state->runner.history_list);
	} else {
		if (WIFEXITED(status)) {
			/* child's exit(code) or return from main */
			task->exit_code = WEXITSTATUS(status);
			task->state = PROCESS_STATE_TERM;

			/* cancel all queued tasks on failure */
			if (task->exit_code != 0)
				task_list_cancel(&state->runner.waiting_list, &state->runner.history_list);
		} else if (WIFSIGNALED(status)) {
			/* child died from a signal */
			task->exit_sig = WTERMSIG(status);
			task->state = PROCESS_STATE_SIGNAL;

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list);
		} else {
			/* it should never happen */
			task->exit_code = -1;
			task->state = PROCESS_STATE_TERM;

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.waiting_list, &state->runner.history_list);
		}
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

			/* setup a new task to run, note that the task in latest is also in the history_list */
			state->runner.latest = tommy_list_remove_existing(&state->runner.waiting_list, tommy_list_head(&state->runner.waiting_list));
			state->runner.latest->running = 1;
			state->runner.latest->state = PROCESS_STATE_START;
			state->runner.latest->unix_start_time = time(0);

			runner_go(state);
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

int runner(struct snapraid_state* state, int cmd, sl_t* arg_list, char* msg, size_t msg_size, int* status)
{
	const char* snapraid = find_snapraid();
	if (!snapraid) {
		log_msg(LVL_ERROR, "snapraid executable not found");
		sncpy(msg, msg_size, "SnapRAID executable not found");
		*status = 503;
		return -1;
	}

	struct snapraid_task* task = task_alloc();
	task->cmd = cmd;
	task->unix_queue_time = time(0);

	sl_insert_str(&task->arg_list, snapraid);
	sl_insert_str(&task->arg_list, runner_cmd(cmd));
	sl_insert_str(&task->arg_list, "--gui");
	sl_insert_str(&task->arg_list, "--log");
	sl_insert_str(&task->arg_list, ">&2");
	if (arg_list)
		sl_insert_list(&task->arg_list, arg_list);

	state_lock();

	if (!state->daemon_running) {
		state_unlock();
		task_free(task);
		log_msg(LVL_ERROR, "failed to start runner %s for daemon terminating", runner_cmd(cmd));
		sncpy(msg, msg_size, "Daemon is terminating");
		*status = 409;
		return -1;
	}

	/* insert the task in the queue */
	task->number = ++state->runner.number_allocator;
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
		ret = runner(state, CMD_DOWN, &arg_list, msg, msg_size, status);
	}

	sl_free(&arg_list);

	return ret;
}

/**
 * Deletes all **regular files** in the specified directory (non-recursively)
 * that have a modification time older than N days.
 *
 * Note:
 * - This function does **not** recurse into subdirectories.
 * - It skips "." and ".." entries.
 * - It only deletes regular files (not directories, symlinks, etc.).
 * - Uses modification time (st_mtime) for comparison.
 * - Errors are printed to stderr for visibility.
 */
static int delete_old_files(const char* dir_path, int days)
{
	DIR* dir;
	struct dirent* entry;
	struct stat statbuf;
	time_t now;
	int64_t age_seconds;

	dir = opendir(dir_path);
	if (dir == NULL) {
		log_msg(LVL_ERROR, "failed to open directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	time(&now);

	age_seconds = days * (int64_t)24 * 60 * 60;

	while ((entry = readdir(dir)) != NULL) {
		char full_path[PATH_MAX];

		/* skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		/* construct full path */
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

		if (stat(full_path, &statbuf) == -1) {
			log_msg(LVL_ERROR, "failed to stat file %s, errno=%s(%d)", full_path, strerror(errno), errno);
			continue; /* skip this entry on error */
		}

		/* delete only regular files */
		if (!S_ISREG(statbuf.st_mode))
			continue;

		/* delete only files that are old enough */
		if (now - statbuf.st_mtime < age_seconds)
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
	if (delete_old_files(state->config.log_directory, state->config.log_retention_days) != 0) {
		sncpy(msg, msg_size, "Failed deleting old log files");
		*status = 503;
		return 0;
	}

	*status = 200;
	return 0;
}

