// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

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
	state->daemon_start_time = time(0);
	state->array.health = health_array(state, state->array.health_reason, sizeof(state->array.health_reason));

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
	tommy_list_foreach(&state->array.diff_parse.file_list, file_free);
	tommy_list_foreach(&state->array.diff_current.file_list, file_free);
	tommy_list_foreach(&state->array.diff_prev.file_list, file_free);
	tommy_list_foreach(&state->array.fix_current.file_list, file_free);
	tommy_list_foreach(&state->array.bucket_parse_list, bucket_free);
	tommy_list_foreach(&state->array.bucket_list, bucket_free);
	tommy_list_foreach(&state->array.disk_list, disk_free);
	tommy_list_foreach(&state->web.page_list, page_free);
	tommy_list_foreach(&state->parser_association, association_free);
	crypto_wipe(state->rest_auth_cache, sizeof(state->rest_auth_cache));
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

