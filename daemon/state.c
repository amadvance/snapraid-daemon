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
#include "state.h"

struct snapraid_state STATE;

void state_init(void)
{
	memset(&STATE, 0, sizeof(STATE));
	thread_mutex_init(&STATE.lock);
	STATE.daemon_running = 1;
}

void state_done(void)
{
	thread_mutex_destroy(&STATE.lock);
}

struct snapraid_state* state_ptr(void)
{
	return &STATE;
}

void state_lock(void)
{
	thread_mutex_lock(&STATE.lock);
}

void state_unlock(void)
{
	thread_mutex_unlock(&STATE.lock);
}

