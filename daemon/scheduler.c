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
#include "runner.h"
#include "log.h"
#include "scheduler.h"

void* scheduler_thread(void* arg)
{
	char msg[128];
	int status;
	struct snapraid_state* state = arg;
	int last_minute;
	int64_t last_probe_ts;
	int64_t last_spindown_ts;
	int64_t last_delete_ts;
	int64_t last_history_ts;

	last_minute = -1;
	last_probe_ts = 0;
	last_spindown_ts = 0;
	last_delete_ts = 0;
	last_history_ts = 0;

	state_lock();

	while (state->daemon_running) {
		struct timespec ts;
		time_t now = time(0);
		struct tm* tm_info = localtime(&now);
		int current_minute = tm_info->tm_min;
		int current_hour = tm_info->tm_hour;
		int current_wday = tm_info->tm_wday;
		int64_t mono_now_secs;

		if (last_minute < 0)
			last_minute = current_minute;

		/* check only one time every minute */
		while (current_minute != last_minute) {
			last_minute = current_minute;

			clock_gettime(CLOCK_MONOTONIC, &ts);
			mono_now_secs = ts.tv_sec;

			/* sync and scrub */
			if (current_hour == state->config.schedule_hour
				&& current_minute == state->config.schedule_minute
				&& (state->config.schedule_run == RUN_DAILY || (state->config.schedule_run == RUN_WEEKLY && current_wday == state->config.schedule_day_of_week))) {
				sl_t diff_arg_list;
				sl_t sync_arg_list;
				sl_t scrub_arg_list;
				int do_scrub = 0;
				int do_diff = 0;

				sl_init(&diff_arg_list);
				sl_init(&scrub_arg_list);
				sl_init(&sync_arg_list);
				if (state->config.sync_prehash) {
					sl_insert_str(&sync_arg_list, "-h");
				}
				if (state->config.sync_force_zero) {
					sl_insert_str(&sync_arg_list, "-Z");
				}
				if (state->config.notify_differences) {
					do_diff = 1;
				}
				if (state->config.scrub_percentage > 0) {
					do_scrub = 1;
					sl_insert_str(&scrub_arg_list, "-p");
					sl_insert_int(&scrub_arg_list, state->config.scrub_percentage);
					sl_insert_str(&scrub_arg_list, "-o");
					sl_insert_int(&scrub_arg_list, state->config.scrub_older_than);
				}

				state_unlock();

				/*
				 * Run all the actions, note that they are just scheduled,
				 * the eventual failure won't be detected here.
				 */
				int ret = 0;
				if (ret == 0 && do_diff)
					ret = runner(state, CMD_DIFF, &diff_arg_list, msg, sizeof(msg), &status);

				if (ret == 0)
					ret = runner(state, CMD_SYNC, &sync_arg_list, msg, sizeof(msg), &status);

				if (ret == 0 && do_scrub)
					(void)runner(state, CMD_SCRUB, &scrub_arg_list, msg, sizeof(msg), &status);

				sl_free(&diff_arg_list);
				sl_free(&sync_arg_list);
				sl_free(&scrub_arg_list);

				state_lock();
				break;
			}

			/* delete old log every hour */
			if (state->config.log_retention_days > 0
				&& state->config.log_directory[0] != 0
				&& mono_now_secs - last_delete_ts >= 3600) {
				state_unlock();

				last_delete_ts = mono_now_secs;
				(void)runner_delete_old_log(state, msg, sizeof(msg), &status); /* error already logged */

				state_lock();
				/* continue with other tasks */
			}
			
			/* clean history every 10 minutes */
			if (mono_now_secs - last_history_ts >= 10 * 60) {
				state_unlock();

				last_history_ts = mono_now_secs;
				(void)runner_delete_old_history(state, msg, sizeof(msg), &status); /* error already logged */

				state_lock();
				/* continue with other tasks */
			}

			/* skip following actions if something other is running */
			if (state->runner.latest && state->runner.latest->running)
				break;

			/* probe and spindown */
			int do_probe = 0;
			int do_spindown = 0;
			int spindown_idle_minutes = state->config.spindown_idle_minutes;

			if ((state->config.probe_interval_minutes > 0
				&& mono_now_secs - last_probe_ts >= state->config.probe_interval_minutes * (int64_t)60))
				do_probe = 1;

			if ((state->config.spindown_idle_minutes > 0
				&& mono_now_secs - last_spindown_ts >= state->config.spindown_idle_minutes * (int64_t)60))
				do_spindown = 1;

			if (do_probe || do_spindown) {
				state_unlock();

				last_probe_ts = mono_now_secs;
				if (runner(state, CMD_PROBE, 0, msg, sizeof(msg), &status) == 0) {
					if (spindown_idle_minutes > 0) {
						/* spindown inactive */
						last_spindown_ts = mono_now_secs;
						(void)runner_spindown_inactive(state, msg, sizeof(msg), &status); /* error already logged */
					}
				}

				state_lock();
				break;
			}
		}

		thread_cond_wait(&state->scheduler.cond, &state->lock);
	}

	state_unlock();

	return 0;
}

void scheduler_init(struct snapraid_state* state)
{
	thread_cond_init(&state->scheduler.cond);

	/* start the scheduler thread */
	thread_create(&state->scheduler.thread_id, scheduler_thread, state);
}

void scheduler(struct snapraid_state* state)
{
	thread_cond_signal(&state->scheduler.cond);
}

void scheduler_done(struct snapraid_state* state)
{
	void* retval;

	/* signal the condition to allow the thread to stop */
	thread_cond_signal(&state->scheduler.cond);

	/* wait for the thread termination */
	thread_join(state->scheduler.thread_id, &retval);

	thread_cond_destroy(&state->scheduler.cond);
}

