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

#include "support.h"
#include "elem.h"
#include "conf.h"
#include "state.h"

struct snapraid_state STATE;

struct snapraid_state* state_init(void)
{
	memset(&STATE, 0, sizeof(STATE));
	struct snapraid_state* state = &STATE;

	thread_mutex_init(&state->state_lock);
	thread_mutex_init(&state->log_lock);
	thread_rwlock_init(&state->web_lock);
	state->daemon_running = DAEMON_STARTING;
	state->global.health = health_array(state, state->global.health_reason, sizeof(state->global.health_reason));

	return state;
}

void state_done(struct snapraid_state* state)
{
	assert(state == &STATE);

	tommy_list_foreach(&state->runner.waiting_list, task_free);
	if (state->runner.latest && state->runner.latest->running) /* if running it isn't in the lists */
		task_free(state->runner.latest);
	tommy_list_foreach(&state->runner.history_list, task_free);
	tommy_list_foreach(&state->global.diff_parse.file_list, file_free);
	tommy_list_foreach(&state->global.diff_current.file_list, file_free);
	tommy_list_foreach(&state->global.diff_prev.file_list, file_free);
	tommy_list_foreach(&state->global.fix_current.file_list, file_free);
	tommy_list_foreach(&state->global.bucket_parse_list, bucket_free);
	tommy_list_foreach(&state->global.bucket_list, bucket_free);
	tommy_list_foreach(&state->data_list, disk_free);
	tommy_list_foreach(&state->parity_list, disk_free);
	tommy_list_foreach(&state->web.page_list, page_free);
	tommy_list_foreach(&state->config.line_list, config_line_free);
	thread_mutex_destroy(&state->state_lock);
	thread_mutex_destroy(&state->log_lock);
	thread_rwlock_destroy(&state->web_lock);

	memset(&STATE, 0, sizeof(STATE)); /* clear to have leaks reported */
}

struct snapraid_state* state_ptr(void)
{
	return &STATE;
}

void state_lock(void)
{
	thread_mutex_lock(&STATE.state_lock);
}

void state_unlock(void)
{
	thread_mutex_unlock(&STATE.state_lock);
}

void log_lock(void)
{
	thread_mutex_lock(&STATE.log_lock);
}

void log_unlock(void)
{
	thread_mutex_unlock(&STATE.log_lock);
}

void web_rdlock(void)
{
	thread_rwlock_rdlock(&STATE.web_lock);
}

void web_wrlock(void)
{
	thread_rwlock_wrlock(&STATE.web_lock);
}

void web_unlock(void)
{
	thread_rwlock_unlock(&STATE.web_lock);
}

