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

#ifndef __CONFIG_H
#define __CONFIG_H

#include "state.h"

/****************************************************************************/
/* config */

int parse_scheduled_run(const char* input, struct snapraid_config* config);
int parse_level(const char* input, int* level);
int parse_int(const char* input, int low, int high, int* level);

const char* config_level_str(int level);
void config_schedule_str(const struct snapraid_config* config, char* buf, size_t size);

void config_init(struct snapraid_config* config, const char* argv0);
int config_load(struct snapraid_state* state);
int config_reload(struct snapraid_state* state);
int config_save(struct snapraid_config* config);
void config_set_string(struct snapraid_config* config, const char* key, char* new_value);
void config_set_int(struct snapraid_config* config, const char* key, int new_value);

#endif

