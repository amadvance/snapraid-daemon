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

void* scheduler_thread(void* arg) 
{
	char msg[128];
	struct snapraid_state* state = arg;
	int last_minute;
	int64_t last_probe_ts;
	int64_t last_spindown_ts;
	int64_t last_delete_ts;

	last_minute = -1;
	last_probe_ts = 0;
	last_spindown_ts = 0;
	last_delete_ts = 0;

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
		if (current_minute != last_minute) {
			last_minute = current_minute;

			clock_gettime(CLOCK_MONOTONIC, &ts);
			mono_now_secs = ts.tv_sec;

			/* sync and scrub */
			if (current_hour == state->config.schedule_hour
				&& current_minute == state->config.schedule_minute
				&& (state->config.schedule_run == RUN_DAILY
					|| (state->config.schedule_run == RUN_WEEKLY && current_wday == state->config.schedule_day_of_week))) 
			{
				state_unlock();

				if (runner(state, CMD_SYNC, 0, 0, msg, sizeof(msg)) == 200) {
					/* wait for the end of the sync */
					runner_wait(state);
					// TODO scrub
				}

				state_lock();
				continue;
			} 

			/* log_retention_days */
			if (state->config.log_retention_days > 0
				&& state->config.log_directory[0] != 0
				&& mono_now_secs - last_delete_ts >= 3600) {
				state_unlock();

				last_delete_ts = mono_now_secs;
				(void)delete_old_files(state->config.log_directory, state->config.log_retention_days); /* error already logged */

				state_lock();
			}

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
				if (runner(state, CMD_PROBE, 0, 0, msg, sizeof(msg)) == 200) {
					if (spindown_idle_minutes > 0) {
						/* wait for the end of the probe */
						runner_wait(state);

						/* spindown inactive */
						last_spindown_ts = mono_now_secs;
						(void)runner_spindown_inactive(state, spindown_idle_minutes, msg, sizeof(msg)); /* error already logged */
					}
				}

				state_lock();
				continue;
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
