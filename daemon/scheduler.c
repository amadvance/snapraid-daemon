// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "support.h"
#include "runner.h"
#include "log.h"
#include "scheduler.h"
#include "daemon.h"

static void schedule_maintenance_locked(struct snapraid_state* state, time_t now, int spindown, int threshold, char* msg, size_t msg_size, int* status)
{
	sl_t diff_arg_list;
	sl_t sync_arg_list;
	sl_t scrub_arg_list;
	int do_scrub = 0;

	sl_init(&diff_arg_list);
	sl_init(&scrub_arg_list);
	sl_init(&sync_arg_list);
	if (state->config.sync_prehash) {
		sl_insert_str(&sync_arg_list, "-h");
	}
	if (!state->config.sync_prevent_truncations) {
		sl_insert_str(&sync_arg_list, "-Z");
	}
	if (state->config.touch_zero_subseconds) {
		sl_insert_str(&sync_arg_list, "--gui-touch-before");
	}
	if (threshold) {
		if (state->config.sync_threshold_deletes) {
			sl_insert_str(&sync_arg_list, "--gui-threshold-removes");
			sl_insert_int(&sync_arg_list, state->config.sync_threshold_deletes);
		}
		if (state->config.sync_threshold_updates) {
			sl_insert_str(&sync_arg_list, "--gui-threshold-updates");
			sl_insert_int(&sync_arg_list, state->config.sync_threshold_updates);
		}
	}
	if (state->config.scrub_percentage > 0) {
		do_scrub = 1;
		sl_insert_str(&scrub_arg_list, "--plan");
		sl_insert_double(&scrub_arg_list, state->config.scrub_percentage);
		sl_insert_str(&scrub_arg_list, "--older-than");
		sl_insert_int(&scrub_arg_list, state->config.scrub_older_than);
	}

	if (spindown < 0) {
		/* if config has spindown management, don't wait, and spin down just after */
		spindown = state->config.spindown_idle_minutes != 0;
	}

	/*
	 * Schedule all the actions, note that they are just scheduled,
	 * the eventual failure won't be detected here.
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int ret = 0;
	if (ret == 0)
		ret = runner_locked(state, CMD_MAINTENANCE, CMD_UP, now, 0, msg, msg_size, status);

	if (ret == 0)
		ret = runner_locked(state, CMD_MAINTENANCE, CMD_SYNC, now, &sync_arg_list, msg, msg_size, status);

	if (ret == 0 && do_scrub)
		(void)runner_locked(state, CMD_MAINTENANCE, CMD_SCRUB, now, &scrub_arg_list, msg, msg_size, status);

	if (ret == 0 && spindown)
		ret = runner_locked(state, CMD_MAINTENANCE, CMD_DOWN, now, 0, msg, msg_size, status);

	(void)runner_locked(state, CMD_MAINTENANCE, CMD_REPORT, now, 0, msg, msg_size, status);

	sl_free(&diff_arg_list);
	sl_free(&sync_arg_list);
	sl_free(&scrub_arg_list);
}

void schedule_maintenance(struct snapraid_state* state, int spindown, int threshold, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);
	state_lock();
	schedule_maintenance_locked(state, now, spindown, threshold, msg, msg_size, status);
	state_unlock();
}

void schedule_heal(struct snapraid_state* state, int spindown, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);

	state_lock();

	sl_t fix_arg_list;
	sl_t scrub_arg_list;
	sl_init(&fix_arg_list);
	sl_init(&scrub_arg_list);
	sl_insert_str(&fix_arg_list, "-e");
	sl_insert_str(&scrub_arg_list, "-p");
	sl_insert_str(&scrub_arg_list, "bad");

	if (spindown < 0) {
		/* if config has spindown management, don't wait, and spin dow just after */
		spindown = state->config.spindown_idle_minutes != 0;
	}

	/*
	 * Schedule all the actions, note that they are just scheduled,
	 * the eventual failure won't be detected here.
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int ret = 0;
	if (ret == 0)
		ret = runner_locked(state, CMD_HEAL, CMD_UP, now, 0, msg, msg_size, status);

	if (ret == 0)
		ret = runner_locked(state, CMD_HEAL, CMD_FIX, now, &fix_arg_list, msg, msg_size, status);

	if (ret == 0)
		(void)runner_locked(state, CMD_HEAL, CMD_SCRUB, now, &scrub_arg_list, msg, msg_size, status);

	if (ret == 0 && spindown)
		ret = runner_locked(state, CMD_HEAL, CMD_DOWN, now, 0, msg, msg_size, status);

	(void)runner_locked(state, CMD_HEAL, CMD_REPORT, now, 0, msg, msg_size, status);

	sl_free(&fix_arg_list);
	sl_free(&scrub_arg_list);

	state_unlock();
}

void schedule_undelete(struct snapraid_state* state, int spindown, sl_t* filter_list, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);

	state_lock();

	sl_t fix_arg_list;
	sl_init(&fix_arg_list);

	sl_insert_str(&fix_arg_list, "--gui-rescan-after"); /* force a rescan after the fix, equivalent to a 'diff' */
	sl_insert_str(&fix_arg_list, "-m");
	for (tommy_node* i = tommy_list_head(filter_list); i != 0; i = i->next) {
		sn_t* sn = i->data;
		sl_insert_str(&fix_arg_list, "-f");
		sl_insert_str(&fix_arg_list, sn->str);
	}

	/*
	 * Schedule all the actions, note that they are just scheduled,
	 * the eventual failure won't be detected here.
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int ret = 0;
	if (ret == 0)
		ret = runner_locked(state, CMD_UNDELETE, CMD_UP, now, 0, msg, msg_size, status);

	if (ret == 0)
		ret = runner_locked(state, CMD_UNDELETE, CMD_FIX, now, &fix_arg_list, msg, msg_size, status);

	if (ret == 0 && spindown)
		ret = runner_locked(state, CMD_UNDELETE, CMD_DOWN, now, 0, msg, msg_size, status);

	(void)runner_locked(state, CMD_UNDELETE, CMD_REPORT, now, 0, msg, msg_size, status);

	sl_free(&fix_arg_list);

	state_unlock();
}

static void schedule_suspend_idle_locked(struct snapraid_state* state, time_t now, char* msg, size_t msg_size, int* status)
{
	/*
	 * Schedule a probe and spindown on idle
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int spindown_idle_minutes = state->config.spindown_idle_minutes;

	int ret = 0;
	if (ret == 0)
		ret = runner_locked(state, CMD_SUSPEND_IDLE, CMD_PROBE, now, 0, msg, msg_size, status);

	if (ret == 0 && spindown_idle_minutes > 0)
		(void)runner_locked(state, CMD_SUSPEND_IDLE, CMD_DOWN_IDLE, now, 0, msg, msg_size, status);
}

void schedule_suspend_idle(struct snapraid_state* state, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);
	state_lock();
	schedule_suspend_idle_locked(state, now, msg, msg_size, status);
	state_unlock();
}

void schedule_refresh(struct snapraid_state* state, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);

	state_lock();

	/*
	 * Schedule all the actions, note that they are just scheduled,
	 * the eventual failure won't be detected here.
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int ret = 0;
	if (ret == 0)
		ret = runner_locked(state, CMD_REFRESH, CMD_READ, now, 0, msg, msg_size, status);

	(void)runner_locked(state, CMD_REFRESH, CMD_REPORT, now, 0, msg, msg_size, status);

	state_unlock();
}

void schedule_commands(struct snapraid_state* state, tommy_list* scheds, char* msg, size_t msg_size, int* status)
{
	time_t now = time(0);

	state_lock();

	/*
	 * Schedule all the actions, note that they are just scheduled,
	 * the eventual failure won't be detected here.
	 *
	 * Keep the lock to ensure that no other task is inserted in between.
	 */
	int ret = 0;
	for (tommy_node* i = tommy_list_head(scheds); i != 0; i = i->next) {
		struct snapraid_schedule* sched = i->data;
		if (ret == 0 || sched->cmd == CMD_REPORT)
			ret = runner_locked(state, 0 /* sequence of commands */, sched->cmd, now, &sched->args, msg, msg_size, status);
	}

	state_unlock();
}

static int is_leap_year(int tm_year)
{
	int year = tm_year + 1900;
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int days_in_month(int month, int tm_year)
{
	/* days in each month (Jan=0, Feb=1, ..., Dec=11) */
	static const int days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

	if (month == 1 && is_leap_year(tm_year)) {
		return 29;
	}

	return days[month];
}

static int tm_compare_minute(const struct tm* a, const struct tm* b)
{
	if (a->tm_year != b->tm_year) return a->tm_year < b->tm_year ? -1 : 1;
	if (a->tm_mon != b->tm_mon) return a->tm_mon < b->tm_mon  ? -1 : 1;
	if (a->tm_mday != b->tm_mday) return a->tm_mday < b->tm_mday ? -1 : 1;
	if (a->tm_hour != b->tm_hour) return a->tm_hour < b->tm_hour ? -1 : 1;
	if (a->tm_min != b->tm_min) return a->tm_min < b->tm_min  ? -1 : 1;

	return 0;
}

static void tm_increment_minute(struct tm* t)
{
	t->tm_min++;
	if (t->tm_min < 60)
		return;

	/* minutes overflow */
	t->tm_min = 0;
	t->tm_hour++;
	if (t->tm_hour < 24)
		return;

	/* hours overflow */
	t->tm_hour = 0;
	t->tm_wday = (t->tm_wday + 1) % 7; /* Sunday is 0 */
	t->tm_mday++;
	if (t->tm_mday <= days_in_month(t->tm_mon, t->tm_year))
		return;

	/* days overflow */
	t->tm_mday = 1;
	t->tm_mon++;
	if (t->tm_mon < 12)
		return;

	/* months overflow */
	t->tm_mon = 0;
	t->tm_year++;
}

void* scheduler_thread(void* arg)
{
	char msg[MSG_MAX];
	int status;
	struct snapraid_state* state = arg;
	int64_t last;
	struct tm last_tm;
	int64_t last_probe_and_spindown_ts;
	int64_t last_delete_ts;
	int64_t last_history_ts;

	last = time(0);
	localtime_r(&last, &last_tm);
	last_probe_and_spindown_ts = os_tick_sec();
	last_delete_ts = last_probe_and_spindown_ts;
	last_history_ts = last_probe_and_spindown_ts;

	state_lock();

	while (state->daemon_running != DAEMON_QUIT) {
		int schedule = 0;
		time_t now = time(0);

		/*
		 * Detect manual changes using UTC
		 *
		 * If the system UTC clock jumps by more than 5 minutes (300s),
		 * we assume a manual user intervention or a massive NTP sync.
		 *
		 * We reset the tracker and skip scheduling.
		 */
		int64_t delta = now - last;
		if (delta < 0)
			delta = -delta;
		if (delta > 300) {
			last = now;
			localtime_r(&last, &last_tm);
			log_msg(LVL_WARNING, "manual time change detected. Skipping scheduler catch-up");
		} else {
			struct tm now_tm;

			last = now;
			localtime_r(&now, &now_tm);

			/*
			 * Local time catch-up logic
			 *
			 * We increment the internal cursor (last_tm) minute-by-minute
			 * until it matches the system local time (now_tm).
			 *
			 * DST SPRING FORWARD:
			 * System jumps from 01:59 to 03:00. 'now_tm' becomes 03:00.
			 * The loop increments last_tm through the "lost" hour, triggering missed tasks.
			 *
			 * DST FALL BACK:
			 * System jumps from 02:59 to 02:00. 'now_tm' becomes 02:00.
			 * Since last_tm (02:59) is now > now_tm (02:00), the loop condition fails.
			 * The cursor effectively "pauses" for an hour until the wall clock catches up,
			 * preventing tasks from being triggered twice.
			 */
			while (tm_compare_minute(&last_tm, &now_tm) < 0) {
				tm_increment_minute(&last_tm);

				for (tommy_node* i = tommy_list_head(&state->config.maintenance_list); i; i = i->next) {
					struct snapraid_run* run = i->data;
					if (last_tm.tm_hour == run->hour
						&& last_tm.tm_min == run->minute
						&& (run->day_of_week == -1 || (last_tm.tm_wday == run->day_of_week))) {
						schedule = 1;
					}
				}
			}
		}

		while (1) {
			if (schedule) {
				if (state->runner.hold_off) {
					/* hold off one event */
					state->runner.hold_off = 0;
					pulse(state, PULSE_ARRAY);
				} else {
					schedule_maintenance_locked(state, now, -1 /* autodetect spindown */, 1 /* apply_thresolds */, msg, sizeof(msg), &status);
				}
				/* do not schedule other tasks */
				break;
			}

			int64_t mono_now_secs = os_tick_sec();

			/* delete old log every hour */
			if (state->config.sys_log_retention_days > 0
				&& state->config.sys_log_directory[0] != 0
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

			/* probe and spindown, use the lowest interval */
			int64_t interval_minutes = state->config.probe_interval_minutes;
			if (state->config.spindown_idle_minutes > 0 && (interval_minutes == 0 || interval_minutes > state->config.spindown_idle_minutes))
				interval_minutes = state->config.spindown_idle_minutes;

			if (interval_minutes > 0
				&& mono_now_secs - last_probe_and_spindown_ts >= interval_minutes * (int64_t)60) {
				last_probe_and_spindown_ts = mono_now_secs;
				schedule_suspend_idle_locked(state, now, msg, sizeof(msg), &status);
				/* continue with other tasks */
			}

			break; /* nothing to execute */
		}

		thread_cond_wait(&state->scheduler.cond, &state->state_lock);
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

void scheduler_pulse(struct snapraid_state* state)
{
	thread_cond_signal(&state->scheduler.cond);
}

void scheduler_done(struct snapraid_state* state)
{
	void* retval;

	state_lock(); /* locking makes helgrind happy in the signal */

	/* signal the condition to allow the thread to stop */
	thread_cond_signal(&state->scheduler.cond);

	state_unlock();

	/* wait for the thread termination */
	thread_join(state->scheduler.thread_id, &retval);

	thread_cond_destroy(&state->scheduler.cond);
}

