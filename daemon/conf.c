// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "support.h"
#include "daemon.h"
#include "log.h"
#include "rest.h"
#include "elem.h"
#include "conf.h"

struct snapraid_config_line* config_line_alloc(void)
{
	struct snapraid_config_line* line = malloc_nofail(sizeof(struct snapraid_config_line));
	return line;
}

void config_line_free(void* void_line)
{
	free(void_line);
}

static int parse_int(const char* input, int low, int high, int* out)
{
	int v;

	if (strint(&v, input) != 0)
		return -1;

	if (v < low || v > high)
		return -1;

	*out = v;
	return 0;
}

static int parse_double(const char* input, int low, int high, double* out)
{
	double v;

	if (strdouble(&v, input) != 0)
		return -1;

	if (v < low || v > high)
		return -1;

	*out = v;
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

	return "-";
}

void config_schedule_str(struct snapraid_config* config, char* buf, size_t size)
{
	const char* days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

	size_t len = 0;
	buf[len] = 0;

	for (tommy_node* i = tommy_list_head(&config->maintenance_list); i; i = i->next) {
		struct snapraid_run* run = i->data;

		const char* sep = len != 0 ? ", " : "";

		int ret;
		if (run->day_of_week == -1)
			ret = snprintf(buf + len, size - len, "%s%02d:%02d", sep, run->hour, run->minute);
		else
			ret = snprintf(buf + len, size - len, "%s%s %02d:%02d", sep, days[run->day_of_week], run->hour, run->minute);
		if (ret < 0)
			return;

		len += ret;
		if (len >= size)
			return;
	}
}

/*
 * Convert the day of the week to a number (0-6)
 * Return -1 if not valid
 */
static int get_day_index(const char* input)
{
	const char* days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

	for (int i = 0; i < 7; i++) {
		if (strncasecmp(input, days[i], 3) == 0)
			return i;
	}

	return -1;
}

int config_parse_maintenance_schedule(const char* input, struct snapraid_config* config)
{
	const char* p = input;
	tommy_list list;

	tommy_list_init(&list);

	/* skip leading spaces to accept and empty string */
	while (isspace((unsigned char)*p))
		++p;

	while (*p) {
		long hour = -1;
		long minute = -1;
		long day_of_week = -1;

		if (!isdigit((unsigned char)*p)) {
			day_of_week = get_day_index(p);
			if (day_of_week == -1)
				goto bail;

			/* skip day */
			p += 3;

			/* a space is required after the day */
			if (!isspace((unsigned char)*p))
				goto bail;

			/* strtol skips spaces by itself */
		}

		char* e;
		hour = strtol(p, &e, 10);
		if (p == e || *e != ':') /* if no digit is processed -> p==e */
			goto bail;
		p = e + 1;
		minute = strtol(p, &e, 10);
		if (p == e)
			goto bail;
		p = e;

		if (hour < 0 || hour > 23 || minute < 0 || minute > 59)
			goto bail;

		struct snapraid_run* run = run_alloc(day_of_week, hour, minute);
		tommy_list_insert_tail(&list, &run->node, run);

		/* skip trailing spaces */
		while (isspace((unsigned char)*p))
			++p;

		if (*p == ',') {
			++p;

			/* skip leading spaces after comma */
			while (isspace((unsigned char)*p))
				++p;

			if (*p == 0)
				goto bail; /* don't accept a trailing comma */
		} else {
			/* only comma and 0 can end an entry */
			if (*p != 0)
				goto bail;
		}
	}

	/* accept the final list */
	tommy_list_foreach(&config->maintenance_list, run_free);
	config->maintenance_list = list;

	return 0;

bail:
	/* cleanup partial list creation */
	tommy_list_foreach(&list, run_free);
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

int config_load_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	char buffer[CONFIG_LINE_MAX];
	FILE* fp;

	/* restore the configuration to the default state */
	config_default_locked(state);

	fp = fopen(config->conf, "r" FOPEN_TEXT FOPEN_CLOEXEC);
	if (!fp) {
		log_msg(LVL_ERROR, "failed to load config in open, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	pulse(state, PULSE_CONFIG);

	/* free the existing line list */
	tommy_list_foreach(&config->line_list, config_line_free);
	tommy_list_init(&config->line_list);

	while (fgets(buffer, sizeof(buffer), fp)) {
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

		/* skip key */
		char* key = s;
		while (*s != 0 && !isspace((unsigned char)*s) && *s != '=')
			++s;

		/* skip space */
		while (*s != 0 && isspace((unsigned char)*s))
			++s;

		if (*s == '=') {
			/* clear and skip equal sign */
			*s++ = 0;

			/* skip space (avoid strtrim to move memory) */
			while (*s != 0 && isspace((unsigned char)*s))
				++s;

			char* val = s;

			strtrim(key);
			strtrim(val);

			if (strcmp(key, "sys_engine") == 0) {
				sncpy(config->sys_engine, sizeof(config->sys_engine), val);
			} else if (strcmp(key, "sys_log_directory") == 0) {
				sncpy(config->sys_log_directory, sizeof(config->sys_log_directory), val);
			} else if (strcmp(key, "sys_log_retention_days") == 0) {
				if (parse_int(val, 0, 10000, &config->sys_log_retention_days) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "net_enabled") == 0) {
				if (parse_int(val, 0, 1, &config->net_enabled) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "net_port") == 0) {
				sncpy(config->net_port, sizeof(config->net_port), val);
			} else if (strcmp(key, "net_acl") == 0) {
				sncpy(config->net_acl, sizeof(config->net_acl), val);
			} else if (strcmp(key, "net_security_headers") == 0) {
				if (parse_int(val, 0, 1, &config->net_security_headers) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "net_allowed_origin") == 0) {
				sncpy(config->net_allowed_origin, sizeof(config->net_allowed_origin), val);
			} else if (strcmp(key, "net_config_full_access") == 0) {
				if (parse_int(val, 0, 1, &config->net_config_full_access) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "net_web_root") == 0) {
				sncpy(config->net_web_root, sizeof(config->net_web_root), val);
			} else if (strcmp(key, "maintenance_schedule") == 0) {
				if (config_parse_maintenance_schedule(val, config) == 0) {
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
			} else if (strcmp(key, "sync_prevent_truncations") == 0) {
				if (parse_int(val, 0, 1, &config->sync_prevent_truncations) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "scrub_percentage") == 0) {
				if (parse_double(val, 0, 100, &config->scrub_percentage) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "scrub_older_than") == 0) {
				if (parse_int(val, 0, 1000, &config->scrub_older_than) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "touch_zero_subseconds") == 0) {
				if (parse_int(val, 0, 1, &config->touch_zero_subseconds) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "hook_run_as_user") == 0) {
				sncpy(config->hook_run_as_user, sizeof(config->hook_run_as_user), val);
			} else if (strcmp(key, "hook_script") == 0) {
				sncpy(config->hook_script, sizeof(config->hook_script), val);
			} else if (strcmp(key, "notify_syslog_enabled") == 0) {
				int syslog;
				if (parse_int(val, 0, 1, &syslog) == 0) {
					log_lock();
					state->log.syslog = syslog;
					log_unlock();
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_syslog_level") == 0) {
				int level;
				if (config_parse_level(val, &level) == 0) {
					log_lock();
					state->log.syslog_level = level;
					log_unlock();
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_run_as_user") == 0) {
				sncpy(config->notify_run_as_user, sizeof(config->notify_run_as_user), val);
			} else if (strcmp(key, "notify_heartbeat") == 0) {
				sncpy(config->notify_heartbeat, sizeof(config->notify_heartbeat), val);
			} else if (strcmp(key, "notify_result") == 0) {
				sncpy(config->notify_result, sizeof(config->notify_result), val);
			} else if (strcmp(key, "notify_result_level") == 0) {
				if (config_parse_level(val, &config->notify_result_level) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_differences") == 0) {
				if (parse_int(val, 0, 1, &config->notify_differences) == 0) {
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

int config_reload_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	int net_enabled;
	char net_port[CONFIG_MAX];
	char net_acl[CONFIG_MAX];

	net_enabled = config->net_enabled;
	sncpy(net_port, sizeof(net_port), config->net_port);
	sncpy(net_acl, sizeof(net_acl), config->net_acl);

	if (config_load_locked(state) != 0)
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
static int line_matches_key(const char* line, const char* key, int allow_comment)
{
	size_t key_len;
	const char* p = line;

	/* skip leading whitespace */
	while (isspace((unsigned char)*p))
		++p;

	/* if it's a comment, skip the '#' and any following space */
	if (*p == '#') {
		if (!allow_comment)
			return 0;
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
	struct snapraid_config_line* found = 0;

	/* first try searching the effective option */
	i = tommy_list_head(&config->line_list);
	while (i) {
		struct snapraid_config_line* line = i->data;
		if (line_matches_key(line->text, key, 0)) {
			found = line; /* if multiple options are found, change the latest */
		}
		i = i->next;
	}

	if (!found) {
		/* retry accepting also commented options */
		i = tommy_list_head(&config->line_list);
		while (i) {
			struct snapraid_config_line* line = i->data;
			if (line_matches_key(line->text, key, 1)) {
				found = line; /* if multiple options are found, change the latest */
			}
			i = i->next;
		}
	}

	/* create the new formatted line */
	if (found) {
		if (*value == 0)
			snprintf(found->text, sizeof(found->text), "#%s =\n", key);
		else
			snprintf(found->text, sizeof(found->text), "%s = %s\n", key, value);
		return;
	}

	/* do not clear if already missing */
	if (*value == 0) {
		return;
	}

	/* create a new line at the end */
	struct snapraid_config_line* line = malloc_nofail(sizeof(struct snapraid_config_line));
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

void config_set_double(struct snapraid_config* config, const char* key, double value)
{
	if (value == 0) {
		config_set(config, key, "");
	} else {
		char buf[32];
		snprintf(buf, sizeof(buf), "%.2g", value);
		config_set(config, key, buf);
	}
}

int config_save_locked(struct snapraid_config* config)
{
	tommy_node* i;
	struct snapraid_config_line* line;

	FILE* fp = fopen(config->conf, "w" FOPEN_TEXT FOPEN_CLOEXEC);
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

void config_default_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;

	/* free any previous content */
	tommy_list_foreach(&state->config.maintenance_list, run_free);

	/* set default */
	config->sys_engine[0] = 0;
	os_default_log(config->sys_log_directory, sizeof(config->sys_log_directory));
	config->sys_log_retention_days = 0;
	config->net_enabled = 0;
	sncpy(config->net_port, sizeof(config->net_port), "");
	sncpy(config->net_acl, sizeof(config->net_acl), "");
	config->net_security_headers = 1;
	sncpy(config->net_allowed_origin, sizeof(config->net_allowed_origin), "self");
	config->net_config_full_access = 0;
	config->net_web_root[0] = 0;
	tommy_list_init(&config->maintenance_list);
	config->sync_threshold_deletes = 0;
	config->sync_threshold_updates = 0;
	config->sync_prehash = 0;
	config->sync_prevent_truncations = 0;
	config->scrub_percentage = 0;
	config->scrub_older_than = 0;
	config->touch_zero_subseconds = 0;
	config->probe_interval_minutes = 0;
	config->spindown_idle_minutes = 0;
	config->hook_run_as_user[0] = 0;
	config->hook_script[0] = 0;
	log_lock();
	state->log.syslog = 0;
	state->log.syslog_level = LVL_ERROR;
	log_unlock();
	config->notify_run_as_user[0] = 0;
	config->notify_heartbeat[0] = 0;
	config->notify_result[0] = 0;
	config->notify_result_level = LVL_ERROR;
	config->notify_differences = 0;

	/* intentionally don't set the config->conf as it should never change */
}

void config_init(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;

	memset(config, 0, sizeof(*config));

	/* set the default configuration file */
	os_default_conf(config->conf, sizeof(config->conf));

	config_default_locked(state);
}

void config_done(struct snapraid_state* state)
{
	tommy_list_foreach(&state->config.maintenance_list, run_free);
}

