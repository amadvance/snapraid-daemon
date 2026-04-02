// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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
	state->daemon_running = DAEMON_LOADING;
	state->global.health = health_array(state, state->global.health_reason, sizeof(state->global.health_reason));

	return state;
}

void state_done(struct snapraid_state* state)
{
	assert(state == &STATE);

	tommy_list_foreach(&state->log.task_list, message_free);
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
	tommy_list_foreach(&state->disk_list, disk_free);
	tommy_list_foreach(&state->web.page_list, page_free);
	tommy_list_foreach(&state->config.line_list, config_line_free);
	tommy_list_foreach(&state->parser_association, association_free);
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

