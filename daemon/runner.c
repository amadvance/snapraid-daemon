// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "os.h"
#include "app.h"
#include "state.h"
#include "support.h"
#include "log.h"
#include "parser.h"
#include "elem.h"
#include "report.h"
#include "notify.h"
#include "runner.h"

/****************************************************************************/
/* runner */
/**
 * Check if the specified command is currently running or scheduled in the queue.
 */
static int runner_has_cmd_locked(struct snapraid_state* state, int cmd)
{
	if (state->runner.latest != 0 && state->runner.latest->cmd == cmd)
		return 1;

	for (tommy_node* i = tommy_list_head(&state->runner.waiting_list); i != 0; i = i->next) {
		struct snapraid_task* task = i->data;
		if (task->cmd == cmd)
			return 1;
	}

	return 0;
}

/**
 * Update the health state of the array
 * If there is a change in health, schedule a report task if not yet present
 */
static int runner_health_check_locked(struct snapraid_state* state)
{
	state->array.health_reason[0] = 0;
	int new_health = health_array(state, state->array.health_reason, sizeof(state->array.health_reason));

	int old_health = state->array.health;

	/* if health change */
	if (old_health != new_health) {
		/* set the new health and pulse */
		pulse(state, PULSE_ARRAY);
		state->array.health = new_health;

		/* send a report, but not if it's a change from PENDING */
		if (old_health != HEALTH_PENDING) {
			/* check if the current task is a report or if there is a scheduled one */
			if (!runner_has_cmd_locked(state, CMD_REPORT)) {
				char msg[MSG_MAX];
				int status;
				runner_locked(state, 0, CMD_REPORT, 0, 0, msg, sizeof(msg), &status);
			}

			/* check if we should trigger a shutdown based on the new health status */
			int trigger_shutdown = 0;
			if (new_health == HEALTH_PREFAIL && config_shutdown_on(state->config.sys_shutdown_on, "prefail"))
				trigger_shutdown = 1;
			else if (new_health == HEALTH_FAILING && config_shutdown_on(state->config.sys_shutdown_on, "failing"))
				trigger_shutdown = 1;

			if (trigger_shutdown) {
				if (!runner_has_cmd_locked(state, CMD_SHUTDOWN)) {
					char msg[MSG_MAX];
					int status;
					runner_locked(state, 0, CMD_SHUTDOWN, 0, 0, msg, sizeof(msg), &status);
				}
			}
		}
	}

	return state->array.health;
}

static int runner_need_hook(int cmd)
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

#define CONTAINERS_MAX 128

static int run_docker_cmd(const char* docker_path, const char* action, const char* containers, const char* run_as_user, ZFILE* log_f, const char* log_prefix)
{
	if (log_f != 0) {
		zprintf(log_f, "daemon:%s:%s\n", log_prefix, containers);
		zflush(log_f);
	}

	/* copy containers to a mutable string to tokenize in-place */
	char* copy = strdup_nofail(containers);

	/* split the string using strsplit up to CONTAINERS_MAX tokens */
	char* tokens[CONTAINERS_MAX];
	unsigned n = strsplit(tokens, CONTAINERS_MAX, copy, ",", " \t");

	if (n == 0) {
		free(copy);
		return 0;
	}

	/* argv will have: docker_path, action, and then the containers, and then NULL */
	char** argv = calloc_nofail(n + 3, sizeof(char*));

	argv[0] = (char*)docker_path;
	argv[1] = (char*)action;

	for (unsigned i = 0; i < n; ++i) {
		argv[2 + i] = tokens[i];
	}
	argv[2 + n] = NULL;

	int ret = -1;
	os_privileges_acquire();
	pid_t pid = os_spawn(argv, NULL, NULL, run_as_user);
	os_privileges_release();
	if (pid < 0) {
		log_task(LVL_ERROR, "failed to spawn docker %s, errno=%s(%d)", action, strerror(errno), errno);
		if (log_f != 0)
			zprintf(log_f, "daemon:%s_fail\n", log_prefix);
	} else {
		int status;
		pid_t wait_pid = os_wait(pid, &status);
		if (wait_pid == -1) {
			log_task(LVL_ERROR, "failed to wait for docker %s, errno=%s(%d)", action, strerror(errno), errno);
			if (log_f != 0)
				zprintf(log_f, "daemon:%s_fail\n", log_prefix);
		} else {
			if (WIFEXITED(status)) {
				int exit_code = WEXITSTATUS(status);
				if (exit_code == 0) {
					log_task(LVL_INFO, "docker %s succeeded", action);
					ret = 0;
				} else {
					log_task(LVL_ERROR, "docker %s failed with exit code %d", action, exit_code);
				}
				if (log_f != 0)
					zprintf(log_f, "daemon:%s_term:%d\n", log_prefix, exit_code);
			} else if (WIFSIGNALED(status)) {
				log_task(LVL_ERROR, "docker %s terminated with signal %d", action, WTERMSIG(status));
				if (log_f != 0)
					zprintf(log_f, "daemon:%s_signal:%d\n", log_prefix, WTERMSIG(status));
			}
		}
	}

	free(argv);
	free(copy);

	return ret;
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

	ss_init(&ss, 48 * 1024);

	struct snapraid_diff_stat* diff_stat = 0;

	/* if we run a diff completed, use its result as diff (note that its exit_code is 2 on differences) */
	if (diff_task != 0 && task_success(diff_task))
		diff_stat = &state->array.diff_current;

	/* if we have sync completed, use the previous diff stat */
	if (sync_task != 0 && task_success(sync_task))
		diff_stat = &state->array.diff_prev;

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

	int exit_code = -1;
	if (latest_not_canceled_task != 0) {
		if (latest_not_canceled_task->state == PROCESS_STATE_TERM) {
			exit_code = latest_not_canceled_task->exit_code;
		} else {
			exit_code = -1;
		}
	}

	log_task_reset();

	/* notify the report */
	if (notify_result_locked(state, report_high_cmd, report_level, exit_code, ss_extract(&ss)) != 0) {
		char exit_msg[MSG_MAX];
		report_task->exit_code = -1;
		log_task_push(&report_task->message_list);
		snprintf(exit_msg, sizeof(exit_msg), "Notification failed (check " SYSLOG " for details)");
		message_insert(&report_task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_SOFTWARE, exit_msg);
	}

	ss_done(&ss);

	return 0;
}

static int runner_shutdown_locked(struct snapraid_state* state)
{
	log_task_reset();

	if (state->array.health == HEALTH_PREFAIL) {
		log_task(LVL_INFO, "executing system shutdown on prefail health status");
	} else if (state->array.health == HEALTH_FAILING) {
		log_task(LVL_INFO, "executing system shutdown on failing health status");
	} else {
		log_task(LVL_INFO, "executing system shutdown after maintenance");
	}

	state_unlock();

	int ret = os_shutdown();

	state_lock();

	struct snapraid_task* shutdown_task = state->runner.latest;

	shutdown_task->running = 0;
	shutdown_task->state = PROCESS_STATE_TERM;
	shutdown_task->exit_code = 0;
	shutdown_task->unix_end_time = time(0);

	if (ret != 0) {
		log_task(LVL_CRITICAL, "system shutdown failed");
		shutdown_task->exit_code = -1;
	}

	log_task_push(&shutdown_task->message_list);

	/* insert the task in the done list */
	tommy_list_insert_tail(&state->runner.history_list, &shutdown_task->node, shutdown_task);

	pulse(state, PULSE_TASKS | PULSE_ACTIVITY);

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

#define HOOK_FLAG_DOCKER 1
#define HOOK_FLAG_SCRIPT 2

#define ENVV_MAX 48

static void add_env(char** envv, int* envv_count, const char* name, const char* format, ...)
{
	if (*envv_count >= ENVV_MAX - 1)
		return;

	char value[PATH_MAX + 256];
	va_list args;
	va_start(args, format);
	vsnprintf(value, sizeof(value), format, args);
	va_end(args);

	char* entry = malloc(strlen(name) + 1 + strlen(value) + 1);
	if (entry) {
		sprintf(entry, "%s=%s", name, value);
		envv[*envv_count] = entry;
		(*envv_count)++;
	}
}

static int runner_hook_begin(struct snapraid_state* state, struct snapraid_task* task, ZFILE* log_f, char* exit_neg_msg, size_t exit_neg_msg_size, int* out_hook_flags)
{
	char hook_script[CONFIG_MAX];
	char hook_docker_pause[CONFIG_MAX];
	char hook_run_as_user[CONFIG_MAX];
	char conf[PATH_MAX];
	char engine_conf[PATH_MAX];
	char log_file[PATH_MAX];
	char instance[64];

	state_lock();
	int cmd = task->cmd;
	int high_cmd = task->high_cmd;
	int number = task->number;
	sncpy(log_file, sizeof(log_file), task->log_file);
	sncpy(hook_script, sizeof(hook_script), state->config.hook_script);
	sncpy(hook_docker_pause, sizeof(hook_docker_pause), state->config.hook_docker_pause);
	sncpy(hook_run_as_user, sizeof(hook_run_as_user), state->config.hook_run_as_user);
	sncpy(conf, sizeof(conf), state->config.conf);
	sncpy(engine_conf, sizeof(engine_conf), state->array.engine_conf);
	sncpy(instance, sizeof(instance), state->instance);
	state_unlock();

	if (hook_docker_pause[0] != 0 && runner_need_hook(cmd)) {
		const char* docker_path = app_find_docker();
		if (!docker_path) {
			log_task(LVL_ERROR, "docker executable not found");
			if (log_f != 0)
				zprintf(log_f, "daemon:pre_docker_fail\n");
			if (exit_neg_msg)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The docker executable was not found");
			return -1;
		}
		/*
		 * We set this flag BEFORE running the pause command.
		 * If the pause command fails halfway through a list of containers,
		 * we want runner_hook_end() to run the unpause command to cleanly
		 * unpause the partially paused list.
		 */
		*out_hook_flags |= HOOK_FLAG_DOCKER;

		log_task(LVL_INFO, "task %d pausing docker containers: %s", number, hook_docker_pause);
		if (run_docker_cmd(docker_path, "pause", hook_docker_pause, hook_run_as_user, log_f, "pre_docker") != 0) {
			if (exit_neg_msg)
				snprintf(exit_neg_msg, exit_neg_msg_size, "Failed to pause docker containers");
			return -1;
		}
		if (log_f)
			zflush(log_f);
	}

	if (hook_script[0] != 0 && runner_need_hook(cmd)) {
		char* hook_argv[3];
		char hook_event[KEYWORD_MAX];
		int script_ret;
		log_task(LVL_INFO, "task %d run %s", number, hook_script);
		if (log_f != 0)
			zprintf(log_f, "daemon:pre:%s\n", hook_script);
		sncpy(hook_event, sizeof(hook_event), "task-begin");
		hook_argv[0] = (char*)hook_script;
		hook_argv[1] = hook_event;
		hook_argv[2] = 0;

		char* envv[ENVV_MAX];
		int envv_count = 0;
		memset(envv, 0, sizeof(envv));

		add_env(envv, &envv_count, "SNAPRAID_EVENT", "%s", "task-begin");
		add_env(envv, &envv_count, "SNAPRAID_TASK_NUMBER", "%d", number);
		add_env(envv, &envv_count, "SNAPRAID_CMD", "%s", command_name(cmd));
		if (high_cmd != 0 && high_cmd != cmd) {
			add_env(envv, &envv_count, "SNAPRAID_HIGH_CMD", "%s", command_name(high_cmd));
		}
		if (log_file[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_LOG_FILE", "%s", log_file);
		}
		if (hook_run_as_user[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_RUN_AS_USER", "%s", hook_run_as_user);
		}
		if (conf[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_DAEMON_CONFIG", "%s", conf);
		}
		if (engine_conf[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_ENGINE_CONFIG", "%s", engine_conf);
		}
		if (instance[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_INSTANCE", "%s", instance);
		}
		envv[envv_count] = NULL;

		os_privileges_acquire();
		script_ret = os_script(hook_argv, envv, hook_run_as_user);
		os_privileges_release();

		for (int i = 0; i < envv_count; ++i) {
			free(envv[i]);
		}

		if (script_ret < 0) {
			log_task(LVL_INFO, "task %d end %s failed start (check " SYSLOG " for details), errno=%s(%d)", number, hook_script, strerror(errno), errno);
			if (log_f != 0)
				zprintf(log_f, "daemon:pre_fail\n");
			if (exit_neg_msg)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The pre_run_script failed to start (check " SYSLOG " for details), errno=%s(%d)", strerror(errno), errno);
			return -1;
		} else if (script_ret == 0) {
			/*
			 * We set this flag ONLY on success. If the pre_run_script fails,
			 * it is the responsibility of the script itself to undo any partial
			 * changes it made before exiting with an error. We do not invoke
			 * the post_run_script (task-error) fallback.
			 */
			*out_hook_flags |= HOOK_FLAG_SCRIPT;
			log_task(LVL_INFO, "task %d end %s", number, hook_script);
			if (log_f != 0)
				zprintf(log_f, "daemon:pre_term:0\n");
		} else if (script_ret < 128) {
			log_task(LVL_INFO, "task %d end %s exit code %d", number, hook_script, script_ret);
			if (log_f != 0)
				zprintf(log_f, "daemon:pre_term:%d\n", script_ret);
			if (exit_neg_msg)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The pre_run_script terminated with exit code %d", script_ret);
			return -1;
		} else {
			log_task(LVL_INFO, "task %d end %s signal %s(%d)", number, hook_script, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				zprintf(log_f, "daemon:pre_signal:%d\n", script_ret - 128);
			if (exit_neg_msg)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The pre_run_script terminated with signal %s(%d)", signal_name(script_ret - 128), script_ret - 128);
			return -1;
		}
		if (log_f)
			zflush(log_f);
	}

	return 0;
}

static void runner_hook_end(struct snapraid_state* state, struct snapraid_task* task, ZFILE* log_f, char* exit_neg_msg, size_t exit_neg_msg_size, int success, int hook_flags)
{
	char hook_script[CONFIG_MAX];
	char hook_docker_pause[CONFIG_MAX];
	char hook_run_as_user[CONFIG_MAX];
	char conf[PATH_MAX];
	char engine_conf[PATH_MAX];
	char instance[64];

	/* diff stats */
	int64_t diff_added = 0;
	int64_t diff_removed = 0;
	int64_t diff_updated = 0;
	int64_t diff_moved = 0;
	int64_t diff_copied = 0;

	/* copy of only the fields used from task */
	int has_task = 0;
	int number = 0;
	int cmd = CMD_SYNC;
	int high_cmd = 0;
	char log_file[PATH_MAX];
	log_file[0] = 0;
	int task_state = 0;
	int exit_sig = 0;
	int exit_code = 0;
	time_t unix_start_time = 0;
	time_t unix_end_time = 0;
	int task_health = HEALTH_PENDING;
	uint64_t error_io = 0;
	uint64_t error_data = 0;
	uint64_t error_soft = 0;
	uint64_t error_recovered = 0;
	uint64_t error_unrecoverable = 0;

	state_lock();
	if (task) { /* if called at daemon shutdown there is no task */
		has_task = 1;
		number = task->number;
		cmd = task->cmd;
		high_cmd = task->high_cmd;
		sncpy(log_file, sizeof(log_file), task->log_file);
		task_state = task->state;
		exit_sig = task->exit_sig;
		exit_code = task->exit_code;
		unix_start_time = task->unix_start_time;
		unix_end_time = task->unix_end_time;
		task_health = task->health;
		error_io = task->error_io;
		error_data = task->error_data;
		error_soft = task->error_soft;
		error_recovered = task->error_recovered;
		error_unrecoverable = task->error_unrecoverable;
	}
	int array_health = state->array.health;
	sncpy(hook_script, sizeof(hook_script), state->config.hook_script);
	sncpy(hook_docker_pause, sizeof(hook_docker_pause), state->config.hook_docker_pause);
	sncpy(hook_run_as_user, sizeof(hook_run_as_user), state->config.hook_run_as_user);
	sncpy(conf, sizeof(conf), state->config.conf);
	sncpy(engine_conf, sizeof(engine_conf), state->array.engine_conf);
	sncpy(instance, sizeof(instance), state->instance);
	if (cmd == CMD_DIFF || cmd == CMD_SYNC) {
		diff_added = state->array.diff_current.diff_added;
		diff_removed = state->array.diff_current.diff_removed;
		diff_updated = state->array.diff_current.diff_updated;
		diff_moved = state->array.diff_current.diff_moved;
		diff_copied = state->array.diff_current.diff_copied;
	}
	state_unlock();

	if ((hook_flags & HOOK_FLAG_SCRIPT) && hook_script[0] != 0 && runner_need_hook(cmd)) {
		char* hook_argv[3];
		char hook_event[KEYWORD_MAX];
		int script_ret;
		log_task(LVL_INFO, "task %d run %s", number, hook_script);
		if (log_f != 0)
			zprintf(log_f, "daemon:post:%s\n", hook_script);
		if (success)
			sncpy(hook_event, sizeof(hook_event), "task-end");
		else
			sncpy(hook_event, sizeof(hook_event), "task-error");
		hook_argv[0] = (char*)hook_script;
		hook_argv[1] = hook_event;
		hook_argv[2] = 0;

		char* envv[ENVV_MAX];
		int envv_count = 0;
		memset(envv, 0, sizeof(envv));

		add_env(envv, &envv_count, "SNAPRAID_EVENT", "%s", success ? "task-end" : "task-error");
		if (has_task) {
			add_env(envv, &envv_count, "SNAPRAID_NUMBER", "%d", number);
			add_env(envv, &envv_count, "SNAPRAID_COMMAND", "%s", command_name(cmd));
			if (high_cmd != 0 && high_cmd != cmd) {
				add_env(envv, &envv_count, "SNAPRAID_HIGH_COMMAND", "%s", command_name(high_cmd));
			}
			if (log_file[0] != 0) {
				add_env(envv, &envv_count, "SNAPRAID_LOG_FILE", "%s", log_file);
			}

			switch (task_state) {
			case PROCESS_STATE_TERM :
				add_env(envv, &envv_count, "SNAPRAID_STATUS", "terminated");
				add_env(envv, &envv_count, "SNAPRAID_EXIT_CODE", "%d", exit_code);
				break;
			case PROCESS_STATE_SIGNAL :
				add_env(envv, &envv_count, "SNAPRAID_STATUS", "signaled");
				add_env(envv, &envv_count, "SNAPRAID_EXIT_SIGNAL", "%d", exit_sig);
				break;
			case PROCESS_STATE_CANCEL :
				add_env(envv, &envv_count, "SNAPRAID_STATUS", "canceled");
				break;
			}

			int64_t elapsed = unix_end_time - unix_start_time;
			if (elapsed < 0)
				elapsed = 0;
			add_env(envv, &envv_count, "SNAPRAID_ELAPSED_SECONDS", "%" PRIi64, elapsed);
			add_env(envv, &envv_count, "SNAPRAID_ARRAY_HEALTH", "%s", health_name(array_health));
			add_env(envv, &envv_count, "SNAPRAID_HEALTH", "%s", health_name(task_health));

			add_env(envv, &envv_count, "SNAPRAID_ERROR_IO", "%" PRIu64, error_io);
			add_env(envv, &envv_count, "SNAPRAID_ERROR_DATA", "%" PRIu64, error_data);
			add_env(envv, &envv_count, "SNAPRAID_ERROR_SOFT", "%" PRIu64, error_soft);

			if (cmd == CMD_FIX) {
				add_env(envv, &envv_count, "SNAPRAID_ERROR_RECOVERED", "%" PRIu64, error_recovered);
				add_env(envv, &envv_count, "SNAPRAID_ERROR_UNRECOVERABLE", "%" PRIu64, error_unrecoverable);
			}

			if (cmd == CMD_DIFF || cmd == CMD_SYNC) {
				add_env(envv, &envv_count, "SNAPRAID_DIFF_ADDED", "%" PRIi64, diff_added);
				add_env(envv, &envv_count, "SNAPRAID_DIFF_REMOVED", "%" PRIi64, diff_removed);
				add_env(envv, &envv_count, "SNAPRAID_DIFF_UPDATED", "%" PRIi64, diff_updated);
				add_env(envv, &envv_count, "SNAPRAID_DIFF_MOVED", "%" PRIi64, diff_moved);
				add_env(envv, &envv_count, "SNAPRAID_DIFF_COPIED", "%" PRIi64, diff_copied);
			}
		} else {
			add_env(envv, &envv_count, "SNAPRAID_CMD", "%s", command_name(cmd));
		}
		if (hook_run_as_user[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_RUN_AS_USER", "%s", hook_run_as_user);
		}
		if (conf[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_DAEMON_CONFIG", "%s", conf);
		}
		if (engine_conf[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_ENGINE_CONFIG", "%s", engine_conf);
		}
		if (instance[0] != 0) {
			add_env(envv, &envv_count, "SNAPRAID_INSTANCE", "%s", instance);
		}
		envv[envv_count] = NULL;

		os_privileges_acquire();
		script_ret = os_script(hook_argv, envv, hook_run_as_user);
		os_privileges_release();

		for (int i = 0; i < envv_count; ++i) {
			free(envv[i]);
		}

		if (script_ret < 0) {
			log_task(LVL_INFO, "task %d end %s failed start (check " SYSLOG " for details), errno=%s(%d)", number, hook_script, strerror(errno), errno);
			if (log_f != 0)
				zprintf(log_f, "daemon:post_fail\n");
			if (exit_neg_msg && exit_neg_msg[0] == 0)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The post_run_script failed to start, errno=%s(%d)", strerror(errno), errno);
		} else if (script_ret == 0) {
			log_task(LVL_INFO, "task %d end %s", number, hook_script);
			if (log_f != 0)
				zprintf(log_f, "daemon:post_term:0\n");
		} else if (script_ret < 128) {
			log_task(LVL_INFO, "task %d end %s exit code %d", number, hook_script, script_ret);
			if (log_f != 0)
				zprintf(log_f, "daemon:post_term:%d\n", script_ret);
			if (exit_neg_msg && exit_neg_msg[0] == 0)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The post_run_script terminated with exit code %d", script_ret);
		} else {
			log_task(LVL_INFO, "task %d end %s signal %s(%d)", number, hook_script, signal_name(script_ret - 128), script_ret - 128);
			if (log_f != 0)
				zprintf(log_f, "daemon:post_signal:%d\n", script_ret - 128);
			if (exit_neg_msg && exit_neg_msg[0] == 0)
				snprintf(exit_neg_msg, exit_neg_msg_size, "The post_run_script terminated with signal %s(%d)", signal_name(script_ret - 128), script_ret - 128);
		}
		if (log_f)
			zflush(log_f);
	}

	if ((hook_flags & HOOK_FLAG_DOCKER) && hook_docker_pause[0] != 0 && runner_need_hook(cmd)) {
		const char* docker_path = app_find_docker();
		if (docker_path) {
			log_task(LVL_INFO, "task %d unpausing docker containers: %s", number, hook_docker_pause);
			(void)run_docker_cmd(docker_path, "unpause", hook_docker_pause, hook_run_as_user, log_f, "post_docker");
		} else {
			if (log_f != 0)
				zprintf(log_f, "daemon:post_docker_fail\n");
		}
		if (log_f)
			zflush(log_f);
	}
}

static void runner_go(struct snapraid_state* state)
{
	char hook_script[CONFIG_MAX];
	char hook_docker_pause[CONFIG_MAX];
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
	int success = 0;
	char** argv;
	int argc;
	tommy_node* j;
	int i;
	int number;
	struct snapraid_task* task = state->runner.latest;
	struct snapraid_pulse pulse_before = state->pulse;

	sncpy(hook_script, sizeof(hook_script), state->config.hook_script);
	sncpy(hook_docker_pause, sizeof(hook_docker_pause), state->config.hook_docker_pause);
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
		time_t now = unix_start_time;
		struct tm res;
		const char* ext = ".log";
#ifdef HAVE_ZLIB
		if (state->config.sys_log_compression) {
			ext = ".log.gz";
		}
#endif
		struct tm* local = localtime_r(&now, &res);
		if (local) {
			snprintf(log_path, sizeof(log_path), "%s/%04d%02d%02d-%02d%02d%02d-%s%s", sys_log_directory,
				local->tm_year + 1900,
				local->tm_mon + 1,
				local->tm_mday,
				local->tm_hour,
				local->tm_min,
				local->tm_sec,
				command_name(cmd),
				ext
			);
		} else {
			snprintf(log_path, sizeof(log_path), "%s/%s%s", sys_log_directory, command_name(cmd), ext);
		}

		sncpy(task->log_file, sizeof(task->log_file), log_path);
	}

	/* check if we have postponed hooks from the previous task */
	int pre_hook_flags = state->runner.hook_flags;
	int post_skip = 0;
	state->runner.hook_flags = 0;

	parse_begin(state);

	/* check if the next task needs a script */
	int next_need_script = 0;
	j = tommy_list_head(&state->runner.waiting_list);
	if (j) {
		struct snapraid_task* waiting = j->data;
		next_need_script = runner_need_hook(waiting->cmd);
	}

	log_task_reset();

	state_unlock();

	int f = -1;
	ZFILE* log_f = 0;

	if (log_path[0] != 0) {
		int log_fd;
		os_privileges_acquire();
		log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0666);
		os_privileges_release();
		if (log_fd == -1) {
			log_task(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		} else {
			log_f = zdopen(log_fd, "w" FOPEN_BINARY, is_gz_extension(log_path));
			if (log_f == 0) {
				log_task(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
				close(log_fd);
			}
		}
	}

	if (log_f != 0) {
		zprintf(log_f, "daemon:number:%d\n", number);
		zprintf(log_f, "daemon:command:%s\n", command_name(cmd));
		if (high_cmd != 0 && high_cmd != cmd)
			zprintf(log_f, "daemon:high_command:%s\n", command_name(high_cmd));
		zprintf(log_f, "daemon:scheduled:%" PRIi64 "\n", unix_queue_time);
		zprintf(log_f, "daemon:start:%" PRIi64 "\n", unix_start_time);
		for (i = 0; i < argc; ++i)
			zprintf(log_f, "daemon:argv:%d:%s\n", i, argv[i]);
		zflush(log_f);
	}

	int hook_flags = 0;
	if (pre_hook_flags == 0) {
		if (runner_hook_begin(state, task, log_f, exit_neg_msg, sizeof(exit_neg_msg), &hook_flags) < 0) {
			pid_ret = -1;
			goto bail;
		}
	} else {
		/* use the postponed flags from the previous task */
		hook_flags = pre_hook_flags;
	}

	os_privileges_acquire();
	pid = os_spawn(argv, NULL, &f, NULL);
	os_privileges_release();
	if (pid < 0) {
		log_task(LVL_ERROR, "task %d run %s failed spawn, errno=%s(%d)", number, command_name(cmd), strerror(errno), errno);
		snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The task %s failed to spawn (check " SYSLOG " for details), errno=%s(%d)", command_name(cmd), strerror(errno), errno);
		pid_ret = -1;
		/* continue to run the hook_script */
	} else {
		if (log_f != 0)
			log_task(LVL_INFO, "task %d run %s (pid %" PRIu64 ") with log %s", number, command_name(cmd), (uint64_t)pid, log_path);
		else
			log_task(LVL_INFO, "task %d run %s (pid %" PRIu64 ")", number, command_name(cmd), (uint64_t)pid);

		/* store the pid to allow stop actions */
		state_lock();
		task->pid = pid;
		state_unlock();

		parse_log(state, f, 0, log_f, log_path);

		/* wait for the child process to terminate */
		pid_ret = os_wait(pid, &status);

		if (pid_ret == -1) {
			log_task(LVL_INFO, "task %d end %s (pid %" PRIu64 ") failed wait, errno=%s(%d)", number, command_name(cmd), (uint64_t)pid, strerror(errno), errno);
			snprintf(exit_neg_msg, sizeof(exit_neg_msg), "The task %s failed to wait, errno=%s(%d)", command_name(cmd), strerror(errno), errno);
			if (log_f != 0)
				zprintf(log_f, "daemon:fail\n");
		} else {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0) {
					log_task(LVL_INFO, "task %d end %s (pid %" PRIu64 ")", number, command_name(cmd), (uint64_t)pid);
					success = 1;
				} else {
					log_task(LVL_INFO, "task %d end %s (pid %" PRIu64 ") exit code %d", number, command_name(cmd), (uint64_t)pid, WEXITSTATUS(status));
				}
				if (log_f != 0)
					zprintf(log_f, "daemon:term:%d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				log_task(LVL_INFO, "task %d end %s (pid %" PRIu64 ") signal %s(%d)", number, command_name(cmd), (uint64_t)pid, signal_name(WTERMSIG(status)), WTERMSIG(status));
				if (log_f != 0)
					zprintf(log_f, "daemon:signal:%d\n", WTERMSIG(status));
			}
		}
		if (log_f)
			zflush(log_f);
	}

	/* if the next task uses the hook, skip the post */
	if (success && next_need_script && runner_need_hook(cmd)) {
		/* postpone */
		post_skip = 1;
	}

bail:
	unix_end_time = time(0);
	if (unix_end_time < unix_start_time)
		unix_end_time = unix_start_time;

	state_lock();
	task->unix_end_time = unix_end_time;

	task->health = health_task(task, 0, 0);

	/* check the array health, but DO NOT propagate it to the task */
	runner_health_check_locked(state);
	state_unlock();

	if (post_skip == 0) {
		runner_hook_end(state, task, log_f, exit_neg_msg, sizeof(exit_neg_msg), success, hook_flags);
		if (exit_neg_msg[0] != 0) {
			pid_ret = -1;
		}
	}

	/* store if the hook was skipped */
	if (post_skip)
		state->runner.hook_flags = hook_flags;

	if (log_f != 0) {
		zprintf(log_f, "daemon:end:%" PRIi64 "\n", unix_end_time);
		if (zclose(log_f) != 0) {
			log_task(LVL_WARNING, "failed to close log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}

	if (f != -1)
		close(f);

	for (i = 0; i < argc; ++i)
		free(argv[i]);
	free(argv);

	state_lock();

	log_task_push(&task->message_list);

	/* the task is not running anymore */
	task->running = 0;

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
				os_privileges_acquire();
				int ret = remove(omit->log_file);
				os_privileges_release();
				if (ret != 0) {
					log_msg(LVL_WARNING, "failed to remove log file %s, errno=%s(%d)", omit->log_file, strerror(errno), errno);
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

			parse_end(state, task);

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
		if (state->array.health == HEALTH_PREFAIL) {
			const char* msg = "Array is in PREFAIL! Task aborted!";
			sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), msg);
			message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_HARDWARE, msg);
			return -1;
		}

		if (state->array.health == HEALTH_FAILING) {
			const char* msg = "Array is FAILING!!! Task aborted!!!";
			sncpy(state->runner.latest->exit_msg, sizeof(state->runner.latest->exit_msg), msg);
			message_insert(&task->message_list, MESSAGE_LEVEL_FATAL, MESSAGE_TYPE_HARDWARE, msg);
			return -1;
		}
		break;
	}

	return 0;
}

static void runner_postcondition(struct snapraid_state* state)
{
	struct snapraid_task* task = state->runner.latest;
	char msg[MSG_MAX];
	int status;

	if (task->high_cmd == CMD_STARTUP && task->cmd == CMD_PROBE) {
		/*
		 * Trigger read of the content file if needed
		 */
		if (state->array.content[0] == 0 /* it's the first run */
		        /* the content file was modified from command line */
			|| (state->array.content_last_unixtime != 0 && state->array.content_probe_unixtime > state->array.content_last_unixtime)
		) {
			if (runner_locked(state, CMD_STARTUP, CMD_READ, 0, 0, msg, sizeof(msg), &status) != 0) {
				log_msg(LVL_ERROR, "failed to run the startup read command");
				/* continue anyway to provide an interface */
			}
		}
	}
}

static void runner_spindown_inactive_locked(struct snapraid_state* state)
{
	struct snapraid_task* task = state->runner.latest;
	int count = 0;

	int spindown_data = state->config.spindown_idle_minutes_data;
	int spindown_parity = state->config.spindown_idle_minutes_parity;

	/* insert in the argument list the disk to spin down */
	if (spindown_data != 0 || spindown_parity != 0) {
		for (tommy_node* i = tommy_list_head(&state->array.disk_list); i; i = i->next) {
			struct snapraid_disk* disk = i->data;
			int active = 0;

			/* do not spin down extra disks */
			if (disk->kind == DISK_EXTRA)
				continue;

			int threshold = (disk->kind == DISK_PARITY) ? spindown_parity : spindown_data;
			if (threshold == 0)
				continue;

			for (tommy_node* j = tommy_list_head(&disk->device_list); j; j = j->next) {
				struct snapraid_device* device = j->data;
				/* POWER_PENDING is not really possible, because if we have the idle time to reach here we also have the power state */
				if (device->power == POWER_ACTIVE)
					active = 1;
			}

			int unused_minutes = (disk->access_count_latest_time - disk->access_count_initial_time) / 60;
			if (active && unused_minutes >= threshold) {
				char msg[MSG_MAX];
				snprintf(msg, sizeof(msg), "Selecting disk %s unused by %d minutes", disk->name, unused_minutes);
				message_insert(&task->message_list, MESSAGE_LEVEL_INFO, MESSAGE_TYPE_NONE, msg);
				sl_insert_str(&task->arg_list, "-d");
				sl_insert_str(&task->arg_list, disk->name);
				++count;
			}
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
			} else if (task->cmd == CMD_SHUTDOWN) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				runner_shutdown_locked(state);
			} else if (runner_precondition(state) == 0) {
				task->running = 1;
				task->state = PROCESS_STATE_START;
				if (task->cmd == CMD_DOWN_IDLE) {
					runner_spindown_inactive_locked(state);
				} else {
					runner_go(state);
					runner_postcondition(state);
				}
			} else {
				task->state = PROCESS_STATE_CANCEL;
				task->unix_start_time = now; /* here we don't care about uniqueness as canceled tasks are not stored */
				task->unix_end_time = task->unix_start_time;
				log_msg(LVL_WARNING, "task %d cancel %s", task->number, command_name(task->cmd));

				/* insert in the history */
				tommy_list_insert_tail(&state->runner.history_list, &task->node, task);

				/* if this canceled task was supposed to handle the hook, we must close the hook now */
				if (state->runner.hook_flags && runner_need_hook(task->cmd)) {
					int postponed_flags = state->runner.hook_flags;

					state_unlock();
					runner_hook_end(state, task, NULL, NULL, 0, 0, postponed_flags);
					state_lock();

					state->runner.hook_flags = 0;
				}
			}
		}

		if (!state->daemon_running)
			break;

		thread_cond_wait(&state->runner.cond, &state->state_lock);
	}

	/* if the daemon is shutting down and a hook was skipped, we must close it now */
	if (state->runner.hook_flags) {
		int postponed_flags = state->runner.hook_flags;

		state_unlock();
		runner_hook_end(state, NULL, NULL, NULL, 0, 0, postponed_flags);
		state_lock();

		state->runner.hook_flags = 0;
	}

	state_unlock();

	return 0;
}

void runner_init(struct snapraid_state* state)
{
	/* create the log directory at initialization */
	if (state->config.sys_log_directory[0] != 0) {
		int mkdir_ret = mkdir(state->config.sys_log_directory, 0755);
		if (mkdir_ret != 0 && errno != EEXIST) {
			log_msg(LVL_ERROR, "failed to create log directory %s, errno=%s(%d)", state->config.sys_log_directory, strerror(errno), errno);
		}
	}

	thread_cond_init(&state->runner.cond);

	/* start the runner thread */
	thread_create(&state->runner.thread_id, runner_thread, state);
}

void runner_done(struct snapraid_state* state)
{
	void* retval;

	state_lock(); /* locking makes helgrind happy in the signal */

	struct snapraid_task* task = state->runner.latest;
	if (task && task->running && task->pid > 0) {
		log_msg(LVL_INFO, "terminating helper process pid %" PRIu64 " due to daemon shutdown", (uint64_t)task->pid);
		os_term(task->pid);
	}

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

	const char* snapraid = app_find_engine(state->config.sys_engine);
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
	if (state->array.engine_conf[0] != 0) {
		sl_insert_str(&task->arg_list, "-c");
		sl_insert_str(&task->arg_list, state->array.engine_conf);
	}
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
 * Deletes all files in the specified directory (non-recursively)
 * that have a name representing a time older than N days.
 *
 * Note:
 * - This function does **not** recurse into subdirectories.
 * - It skips "." and ".." entries.
 */
static int delete_old_files(const char* dir_path, int days)
{
	/* nothing to do if disabled */
	if (days == 0)
		return 0;

	os_privileges_acquire();
	DIR* dir = opendir(dir_path);
	if (dir == NULL) {
		log_msg(LVL_ERROR, "failed to open directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		os_privileges_release();
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
		os_privileges_release();
		return -1;
	}

	os_privileges_release();

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
			/* remove and free, but only if it's not the latest */
			if (state->runner.latest != task) {
				tommy_list_remove_existing(&state->runner.history_list, &task->node);
				task_free(task);
			}
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

