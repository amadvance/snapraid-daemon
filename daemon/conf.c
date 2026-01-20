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
#include "rest.h"
#include "conf.h"

static int parse_int(const char* input, int low, int high, int* out)
{
	long v;
	char* e;

	v = strtol(input, &e, 10);
	if (input == e || *e != 0)
		return -1;

	if (v < low || v > high)
		return -1;

	*out = (int)v;
	return 0;
}

const char* config_level_str(int level)
{
	switch (level) {
	case LVL_CRITICAL : return "critical";
	case LVL_ERROR : return "error";
	case LVL_WARNING : return "warning";
	case LVL_INFO : return "info";
	}

	return "critical";
}

void config_schedule_str(const struct snapraid_config* config, char* buf, size_t size)
{
	const char* days[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
	if (config->schedule_run == RUN_DAILY) {
		snprintf(buf, size, "daily %02d:%02d", config->schedule_hour, config->schedule_minute);
	} else if (config->schedule_run == RUN_WEEKLY && config->schedule_day_of_week >= 0 && config->schedule_day_of_week < 7) {
		snprintf(buf, size, "weekly %s %02d:%02d", days[config->schedule_day_of_week], config->schedule_hour, config->schedule_minute);
	} else {
		buf[0] = '\0';
	}
}

/*
 * Convert the day of the week to a number (0-6)
 * Return -1 if not valid
 */
static int get_day_index(const char* input)
{
	const char* days[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

	for (int i = 0; i < 7; i++) {
		if (strncasecmp(input, days[i], 3) == 0)
			return i;
	}

	return -1;
}

int config_parse_scheduled_run(const char* input, struct snapraid_config* config)
{
	char day_str[10];
	int hour, minute;

	if (!input || strlen(input) == 0) {
		config->schedule_run = RUN_DISABLED;
		return 0;
	}

	config->schedule_hour = 0;
	config->schedule_minute = 0;
	config->schedule_day_of_week = -1;

	if (sscanf(input, "daily %2d:%2d", &hour, &minute) == 2) {
		if (hour < 0 || hour > 24 || minute < 0 || minute > 59)
			return -1;
		config->schedule_run = RUN_DAILY;
		config->schedule_hour = hour;
		config->schedule_minute = minute;
		return 0;
	}

	if (sscanf(input, "weekly %9s %2d:%2d", day_str, &hour, &minute) == 3) {
		int day_of_week = get_day_index(day_str);
		if (day_of_week == -1)
			return -1;
		if (hour < 0 || hour > 24 || minute < 0 || minute > 59)
			return -1;
		config->schedule_run = RUN_WEEKLY;
		config->schedule_day_of_week = day_of_week;
		config->schedule_hour = hour;
		config->schedule_minute = minute;
		return 0;
	}

	return -1;
}

int config_parse_level(const char* input, int* out)
{
	const char* levels[] = { "critical", "error", "warning", "info" };

	for (unsigned i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		if (strcasecmp(input, levels[i]) == 0) {
			*out = i;
			return 0;
		}
	}

	return -1;
}

int config_load(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	char buffer[CONFIG_LINE_MAX];
	FILE* fp;

	fp = fopen(config->conf, "rte");
	if (!fp) {
		log_msg(LVL_ERROR, "failed to load config in open, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp)) {
		char key[CONFIG_MAX], val[CONFIG_MAX];
		char* s;
		struct snapraid_config_line* line = malloc_nofail(sizeof(struct snapraid_config_line));
		sncpy(line->text, sizeof(line->text), buffer);
		tommy_list_insert_tail(&config->line_list, &line->node, line);

		/* skip initial spaces */
		s = buffer;
		while (*s != 0 && isspace((unsigned char)*s))
			++s;

		/* skip empty or comment lines */
		if (*s == 0 || *s == '#')
			continue;

		if (sscanf(s, "%63[^=]=%127[^\n]", key, val) == 2) {
			strtrim(key);
			strtrim(val);

			if (strcmp(key, "net_enabled") == 0) {
				if (parse_int(val, 0, 1, &config->net_enabled) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "net_port") == 0) {
				sncpy(config->net_port, sizeof(config->net_port), val);
			} else if (strcmp(key, "net_acl") == 0) {
				sncpy(config->net_acl, sizeof(config->net_acl), val);
			} else if (strcmp(key, "scheduled_run") == 0) {
				if (config_parse_scheduled_run(val, config) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "probe_interval_minutes") == 0) {
				if (parse_int(val, 0, 1440, &config->probe_interval_minutes) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "spindown_idle_minutes") == 0) {
				if (parse_int(val, 0, 1440, &config->spindown_idle_minutes) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sync_threshold_deletes") == 0) {
				if (parse_int(val, 0, 10000, &config->sync_threshold_deletes) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sync_threshold_updates") == 0) {
				if (parse_int(val, 0, 10000, &config->sync_threshold_updates) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sync_prehash") == 0) {
				if (parse_int(val, 0, 1, &config->sync_prehash) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sync_force_zero") == 0) {
				if (parse_int(val, 0, 1, &config->sync_force_zero) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_differences") == 0) {
				if (parse_int(val, 0, 1, &config->notify_differences) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "scrub_percentage") == 0) {
				if (parse_int(val, 0, 100, &config->scrub_percentage) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "scrub_older_than") == 0) {
				if (parse_int(val, 0, 1000, &config->scrub_older_than) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "script_pre_run") == 0) {
				sncpy(config->script_pre_run, sizeof(config->script_pre_run), val);
			} else if (strcmp(key, "script_post_run") == 0) {
				sncpy(config->script_post_run, sizeof(config->script_post_run), val);
			} else if (strcmp(key, "log_directory") == 0) {
				sncpy(config->log_directory, sizeof(config->log_directory), val);
			} else if (strcmp(key, "log_retention_days") == 0) {
				if (parse_int(val, 0, 10000, &config->log_retention_days) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_syslog_enabled") == 0) {
				config->notify_syslog_enabled = atoi(val);
				if (parse_int(val, 0, 1, &config->notify_syslog_enabled) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_syslog_level") == 0) {
				if (config_parse_level(val, &config->notify_syslog_level) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_heartbeat") == 0) {
				sncpy(config->notify_heartbeat, sizeof(config->notify_heartbeat), val);
			} else if (strcmp(key, "notify_result") == 0) {
				sncpy(config->notify_result, sizeof(config->notify_result), val);
			} else if (strcmp(key, "notify_result_level") == 0) {
				if (config_parse_level(val, &config->notify_result_level) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_email_recipient") == 0) {
				sncpy(config->notify_email_recipient, sizeof(config->notify_email_recipient), val);
			} else if (strcmp(key, "notify_email_level") == 0) {
				if (config_parse_level(val, &config->notify_email_level) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else {
				log_msg(LVL_ERROR, "unknown config option %s=%s", key, val);
			}
		} else {
			log_msg(LVL_ERROR, "unrecognized config line '%s'", buffer);
		}
	}
	if (ferror(fp)) {
		log_msg(LVL_ERROR, "failed to load config in read, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		log_msg(LVL_ERROR, "failed to load config in close, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	log_msg(LVL_INFO, "config loaded successfully from %s", config->conf);

	return 0;
}

int config_reload(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	int net_enabled;
	char net_port[CONFIG_MAX];
	char net_acl[CONFIG_MAX];

	net_enabled = config->net_enabled;
	sncpy(net_port, sizeof(net_port), config->net_port);
	sncpy(net_acl, sizeof(net_acl), config->net_acl);

	if (config_load(state) != 0)
		return -1;

	/* restart web server */
	if (net_enabled != config->net_enabled
		|| (net_enabled && (strcmp(net_acl, config->net_acl) != 0 || strcmp(net_port, config->net_port) != 0))) {
		if (net_enabled) {
			log_msg(LVL_INFO, "deinitializing the web server due to different configuration");
			rest_done(state);
		}
		if (config->net_enabled) {
			log_msg(LVL_INFO, "initializing the web server due to different configuration");
			if (rest_init(state) != 0) {
				log_msg(LVL_ERROR, "failed to restart web server");
			}
		}
	}

	return 0;
}

/**
 * Checks if a line matches a specific configuration key.
 * Handles: "  key =", " # key =", "key=", etc.
 */
static int line_matches_key(const char* line, const char* key)
{
	size_t key_len;
	const char* p = line;

	/* skip leading whitespace */
	while (isspace((unsigned char)*p))
		++p;

	// if it's a comment, skip the '#' and any following space
	if (*p == '#') {
		++p;
		while (isspace((unsigned char)*p))
			++p;
	}

	/* check if the key matches */
	key_len = strlen(key);
	if (strncmp(p, key, key_len) == 0) {
		p += key_len;

		/* ensure the next character is '=' or whitespace followed by '=' */
		while (isspace((unsigned char)*p))
			++p;

		if (*p == '=')
			return 1;
	}

	return 0;
}

static void config_set(struct snapraid_config* config, const char* key, const char* value)
{
	tommy_node* i;
	struct snapraid_config_line* line;

	line = 0;
	i = tommy_list_head(&config->line_list);
	while (i) {
		line = i->data;
		if (line_matches_key(line->text, key)) {
			/* create the new formatted line */
			if (*value == 0)
				snprintf(line->text, sizeof(line->text), "#%s =\n", key);
			else
				snprintf(line->text, sizeof(line->text), "%s = %s\n", key, value);
			return;
		}
		i = i->next;
	}

	/* do not clear if already missing */
	if (*value == 0) {
		return;
	}

	line = malloc_nofail(sizeof(struct snapraid_config_line));
	snprintf(line->text, sizeof(line->text), "%s = %s\n", key, value);
	tommy_list_insert_tail(&config->line_list, &line->node, line);
}

void config_set_string(struct snapraid_config* config, const char* key, char* value)
{
	strtrim(value);
	config_set(config, key, value);
}

void config_set_int(struct snapraid_config* config, const char* key, int value)
{
	if (value == 0) {
		config_set(config, key, "");
	} else {
		char buf[32];
		snprintf(buf, sizeof(buf), "%d", value);
		config_set(config, key, buf);
	}
}

int config_save(struct snapraid_config* config)
{
	tommy_node* i;
	struct snapraid_config_line* line;

	FILE *fp = fopen(config->conf, "wte");
	if (!fp) {
		log_msg(LVL_ERROR, "failed to save config in open, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	i = tommy_list_head(&config->line_list);
	while (i) {
		line = i->data;
		if (fputs(line->text, fp) == EOF) {
			log_msg(LVL_ERROR, "failed to save config in write, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
			fclose(fp);
			return -1;
		}
		i = i->next;
	}

	if (fflush(fp) != 0) {
		log_msg(LVL_ERROR, "failed to save config in flush, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		log_msg(LVL_ERROR, "failed to save config in close, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	log_msg(LVL_INFO, "config saved successfully");

	return 0;
}

void config_init(struct snapraid_config* config, const char* argv0)
{
	(void)argv0;

	memset(config, 0, sizeof(*config));

	/* set default */
	config->net_enabled = 0;
	sncpy(config->net_port, sizeof(config->net_port), "127.0.0.1:8080");
	sncpy(config->net_acl, sizeof(config->net_acl), "+127.0.0.1");
	config->schedule_run = RUN_DISABLED;
	config->schedule_hour = 0;
	config->schedule_minute = 0;
	config->schedule_day_of_week = 0;
	config->sync_threshold_deletes = 0;
	config->sync_threshold_updates = 0;
	config->sync_prehash = 0;
	config->sync_force_zero = 0;
	config->notify_differences = 0;
	config->scrub_percentage = 0;
	config->scrub_older_than = 0;
	config->probe_interval_minutes = 0;
	config->spindown_idle_minutes = 0;
	config->script_pre_run[0] = 0;
	config->script_post_run[0] = 0;
	config->script_run_as_user[0] = 0;
	config->log_directory[0] = 0;
	config->log_retention_days = 0;
	config->notify_syslog_enabled = 0;
	config->notify_syslog_level = LVL_CRITICAL;
	config->notify_heartbeat[0] = 0;
	config->notify_result[0] = 0;
	config->notify_result_level = LVL_CRITICAL;
	config->notify_email_recipient[0] = 0;
	config->notify_email_level = LVL_CRITICAL;
	config->notify_run_as_user[0] = 0;

#ifdef SYSCONFDIR
	/* if it exists, give precedence to sysconfdir, usually /usr/local/etc */
	if (access(SYSCONFDIR "/snapraidd.conf", F_OK) == 0)
		sncpy(config->conf, sizeof(config->conf), SYSCONFDIR "/snapraidd.conf");
	else /* otherwise fallback to plain /etc */
#endif
	sncpy(config->conf, sizeof(config->conf), "/etc/snapraidd.conf");
}

