// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#include "app.h"
#include "state.h"
#include "support.h"
#include "log.h"
#include "rest.h"
#include "elem.h"
#include "conf.h"

int config_shutdown_on(const char* sys_shutdown_on, const char* event)
{
	if (!sys_shutdown_on || !sys_shutdown_on[0])
		return 0;

	char copy[CONFIG_MAX];
	sncpy(copy, sizeof(copy), sys_shutdown_on);

	char* tokens[16];
	unsigned n = strsplit(tokens, 16, copy, ",", " \t\r\n");

	for (unsigned i = 0; i < n; ++i) {
		if (strcmp(tokens[i], event) == 0)
			return 1;
	}

	return 0;
}

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

static int parse_shutdown_on(const char* val, char* dst, size_t dst_size)
{
	char copy[CONFIG_MAX];
	sncpy(copy, sizeof(copy), val);

	char* tokens[16];
	unsigned n = strsplit(tokens, 16, copy, ",", " \t\r\n");

	for (unsigned i = 0; i < n; ++i) {
		if (strcmp(tokens[i], "maintenance") != 0
			&& strcmp(tokens[i], "prefail") != 0
			&& strcmp(tokens[i], "failing") != 0) {
			return -1;
		}
	}

	sncpy(dst, dst_size, val);
	return 0;
}

int config_parse_spindown_idle_minutes(const char* val, int* data, int* parity)
{
	char copy[CONFIG_MAX];
	sncpy(copy, sizeof(copy), val);

	char* tokens[4];
	unsigned n = strsplit(tokens, 4, copy, ",", " \t\r\n");

	if (n == 1) {
		int v;
		if (parse_int(tokens[0], 0, 1440, &v) != 0)
			return -1;
		*data = v;
		*parity = v;
		return 0;
	} else if (n == 2) {
		int v_data, v_parity;
		if (parse_int(tokens[0], 0, 1440, &v_data) != 0)
			return -1;
		if (parse_int(tokens[1], 0, 1440, &v_parity) != 0)
			return -1;
		*data = v_data;
		*parity = v_parity;
		return 0;
	}

	return -1;
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

	if (config) {
		/* accept the final list */
		tommy_list_foreach(&config->maintenance_list, run_free);
		config->maintenance_list = list;
	} else {
		/* otherwise free it */
		tommy_list_foreach(&list, run_free);
	}

	return 0;

bail:
	/* cleanup partial list creation */
	tommy_list_foreach(&list, run_free);
	return -1;
}

int config_parse_smart_ignore(const char* input, struct snapraid_config* config)
{
	char* tokens[64];
	char copy[CONFIG_MAX];
	sncpy(copy, sizeof(copy), input);

	unsigned n = strsplit(tokens, 64, copy, " \t", " \t\r\n");
	if (n < 2) {
		return -1;
	}

	/*
	 * Reject "0" as an attribute index since 0 is reserved as the sentinel value
	 * indicating a name-based rule in smartignore_match.
	 */
	for (unsigned i = 1; i < n; ++i) {
		int val;
		if (strint(&val, tokens[i]) == 0 && val == 0) {
			return -1;
		}
	}

	for (unsigned i = 1; i < n; ++i) {
		struct snapraid_smartignore* smartignore = smartignore_alloc(tokens[0], tokens[i]);
		tommy_list_insert_tail(&config->smartignore_list, &smartignore->node, smartignore);
	}

	return 0;
}

static const char* config_level(int level)
{
	switch (level) {
	case LVL_CRITICAL : return "critical";
	case LVL_ERROR : return "error";
	case LVL_WARNING : return "warning";
	case LVL_INFO : return "info";
	}

	return "-";
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

static void config_refresh_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;

	/* apply to the runtime */
	log_lock();
	state->log.syslog = config->notify_syslog;
	state->log.syslog_level = config->notify_syslog_level;
	log_unlock();
}

int config_load_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	int f;

	os_privileges_acquire();
	f = open(config->conf, O_RDONLY | O_BINARY | O_CLOEXEC);
	os_privileges_release();
	if (f == -1) {
		log_msg(LVL_ERROR, "failed to load config in open, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		return -1;
	}

	struct stat st;
	if (fstat(f, &st) != 0) {
		log_msg(LVL_ERROR, "failed to load config in stat, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		close(f);
		return -1;
	}

	size_t buffer_len = st.st_size;
	char* buffer = malloc_nofail(buffer_len + 1);

	ssize_t ret = read(f, buffer, buffer_len);
	if (ret < 0 || (size_t)ret != buffer_len) {
		log_msg(LVL_ERROR, "failed to load config in read, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		close(f);
		free(buffer);
		return -1;
	}

	if (close(f) != 0) {
		log_msg(LVL_ERROR, "failed to load config in close, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		free(buffer);
		return -1;
	}

	buffer[buffer_len] = 0;

	/* free the existing lists */
	tommy_list_foreach(&config->line_list, config_line_free);
	tommy_list_init(&config->line_list);

	/* restore the configuration to the default state */
	config_default_locked(state);

	pulse(state, PULSE_CONFIG);

	char* next = buffer;
	while (*next) {
		char* begin = next;
		char* end = next;

		/* find the end of the line */
		while (*end && *end != '\n')
			++end;

		/* set the next line */
		if (*end) {
			next = end + 1;
		} else {
			next = end;
		}

		/* trim spaces at the end, this also handle Windows CRLF */
		while (begin < end && isspace((unsigned char)end[-1]))
			--end;

		/* set end of line marker */
		*end = 0;

		struct snapraid_config_line* line = malloc_nofail(sizeof(struct snapraid_config_line));
		sncpy(line->text, sizeof(line->text), begin);
		tommy_list_insert_tail(&config->line_list, &line->node, line);

		/* skip initial spaces */
		char* s = begin;
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
		char* key_end = s;
		while (*s != 0 && isspace((unsigned char)*s))
			++s;

		if (*s == '=') {
			/* skip equal sign */
			++s;

			/* skip space */
			while (*s != 0 && isspace((unsigned char)*s))
				++s;

			char* val = s;

			/* trim key, val is already trimmed */
			*key_end = 0;

			if (strcmp(key, "sys_engine") == 0) {
				sncpy(config->sys_engine, sizeof(config->sys_engine), val);
			} else if (strcmp(key, "sys_log_directory") == 0) {
				sncpy(config->sys_log_directory, sizeof(config->sys_log_directory), val);
			} else if (strcmp(key, "sys_log_retention_days") == 0) {
				if (parse_int(val, 0, 10000, &config->sys_log_retention_days) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sys_log_compression") == 0) {
				if (*val == 0) {
					config->sys_log_compression = 0;
				} else if (parse_int(val, 0, 1, &config->sys_log_compression) == 0) {
#ifndef HAVE_ZLIB
					if (config->sys_log_compression == 1) {
						log_msg(LVL_ERROR, "invalid config option %s=%s, gzip compression is not supported by this build", key, val);
						config->sys_log_compression = 0;
					}
#endif
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "sys_shutdown_on") == 0) {
				if (parse_shutdown_on(val, config->sys_shutdown_on, sizeof(config->sys_shutdown_on)) == 0) {
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
			} else if (strcmp(key, "net_auth_credential") == 0) {
				sncpy(config->net_auth_credential, sizeof(config->net_auth_credential), val);

				/* clear the credential cache */
				state->rest_auth_cache[0] = 0;
			} else if (strcmp(key, "check_updates") == 0) {
				if (parse_int(val, 0, 1, &config->check_updates) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "maintenance_schedule") == 0) {
				if (config_parse_maintenance_schedule(val, config) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "smartignore") == 0) {
				if (config_parse_smart_ignore(val, config) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "probe_interval_minutes") == 0) {
				if (parse_int(val, 0, 1440, &config->probe_interval_minutes) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "spindown_idle_minutes") == 0) {
				if (config_parse_spindown_idle_minutes(val, &config->spindown_idle_minutes_data, &config->spindown_idle_minutes_parity) == 0) {
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
			} else if (strcmp(key, "hook_docker_pause") == 0) {
				sncpy(config->hook_docker_pause, sizeof(config->hook_docker_pause), val);
			} else if (strcmp(key, "notify_syslog_enabled") == 0) {
				if (parse_int(val, 0, 1, &config->notify_syslog) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_syslog_level") == 0) {
				if (config_parse_level(val, &config->notify_syslog_level) == 0) {
				} else {
					log_msg(LVL_ERROR, "invalid config option %s=%s", key, val);
				}
			} else if (strcmp(key, "notify_run_as_user") == 0) {
				sncpy(config->notify_run_as_user, sizeof(config->notify_run_as_user), val);
			} else if (strcmp(key, "notify_heartbeat") == 0) {
				sncpy(config->notify_heartbeat, sizeof(config->notify_heartbeat), val);
			} else if (strcmp(key, "notify_start") == 0) {
				sncpy(config->notify_start, sizeof(config->notify_start), val);
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
			log_msg(LVL_ERROR, "unrecognized config line '%s'", begin);
		}
	}

	config_refresh_locked(state);

	free(buffer);

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

	/* return 1 if web server configuration changed and rest_reload is needed */
	if (net_enabled != config->net_enabled
		|| (net_enabled && (strcmp(net_acl, config->net_acl) != 0 || strcmp(net_port, config->net_port) != 0))) {
		return 1;
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
			snprintf(found->text, sizeof(found->text), "#%s =", key);
		else
			snprintf(found->text, sizeof(found->text), "%s = %s", key, value);
		return;
	}

	/* do not clear if already missing */
	if (*value == 0) {
		return;
	}

	/* create a new line at the end */
	struct snapraid_config_line* line = malloc_nofail(sizeof(struct snapraid_config_line));
	snprintf(line->text, sizeof(line->text), "%s = %s", key, value);
	tommy_list_insert_tail(&config->line_list, &line->node, line);
}

static void config_set_string(struct snapraid_config* config, const char* key, const char* value)
{
	char buf[CONFIG_MAX];
	size_t len = 0;
	size_t trailing_whitespace_pos = 0;

	/* skip leading whitespace */
	while (*value && isspace((unsigned char)*value))
		++value;

	/* copy, tracking where trailing whitespace begins */
	while (*value && len + 1 < sizeof(buf)) {
		buf[len] = *value;
		++len;
		if (!isspace((unsigned char)*value))
			trailing_whitespace_pos = len;
		++value;
	}

	buf[trailing_whitespace_pos] = 0;

	config_set(config, key, buf);
}

static void config_set_int(struct snapraid_config* config, const char* key, int value)
{
	if (value == 0) {
		config_set(config, key, "");
	} else {
		char buf[32];
		snprintf(buf, sizeof(buf), "%d", value);
		config_set(config, key, buf);
	}
}

static void config_set_double(struct snapraid_config* config, const char* key, double value)
{
	if (value == 0) {
		config_set(config, key, "");
	} else {
		char buf[32];
		snprintf(buf, sizeof(buf), "%.2g", value);
		config_set(config, key, buf);
	}
}

int config_save_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;
	char conf_tmp[PATH_MAX + 4];
	ss_t ss;

	ss_init(&ss, 48 * 1024);
	tommy_node* i = tommy_list_head(&config->line_list);
	while (i) {
		struct snapraid_config_line* line = i->data;

		ss_write(&ss, line->text, strlen(line->text));
#ifdef _WIN32
		ss_write(&ss, "\r\n", 2); /* Windows CRLF */
#else
		ss_write(&ss, "\n", 1);
#endif
		i = i->next;
	}

	snprintf(conf_tmp, sizeof(conf_tmp), "%s.tmp", config->conf);

	os_privileges_acquire();
	int f = open(conf_tmp, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_CLOEXEC, 0644);
	if (f == -1) {
		os_privileges_release();
		log_msg(LVL_ERROR, "failed to save config in open, path=%s, errno=%s(%d)", conf_tmp, strerror(errno), errno);
		ss_done(&ss);
		return -1;
	}

	ssize_t ret = write(f, ss_ptr(&ss), ss_len(&ss));
	if (ret < 0 || ret != ss_len(&ss)) {
		log_msg(LVL_ERROR, "failed to save config in write, path=%s, errno=%s(%d)", conf_tmp, strerror(errno), errno);
		close(f);
		ss_done(&ss);
		remove(conf_tmp);
		os_privileges_release();
		return -1;
	}

	ss_done(&ss);

#if HAVE_FSYNC
	if (fsync(f) != 0) {
		log_msg(LVL_ERROR, "failed to save config in fsync, path=%s, errno=%s(%d)", conf_tmp, strerror(errno), errno);
		close(f);
		remove(conf_tmp);
		os_privileges_release();
		return -1;
	}
#endif

	if (close(f) != 0) {
		log_msg(LVL_ERROR, "failed to save config in close, path=%s, errno=%s(%d)", conf_tmp, strerror(errno), errno);
		remove(conf_tmp);
		os_privileges_release();
		return -1;
	}

	if (rename(conf_tmp, config->conf) != 0) {
		log_msg(LVL_ERROR, "failed to save config in rename, path=%s, errno=%s(%d)", config->conf, strerror(errno), errno);
		remove(conf_tmp);
		os_privileges_release();
		return -1;
	}

	os_privileges_release();

	log_msg(LVL_INFO, "config saved successfully");

	return 0;
}

void config_default_locked(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;

	/* set default */
	config->sys_engine[0] = 0;
	app_default_log(config->sys_log_directory, sizeof(config->sys_log_directory));
	config->sys_log_retention_days = 0;
	config->sys_log_compression = 0;
	sncpy(config->sys_shutdown_on, sizeof(config->sys_shutdown_on), "");
	config->net_enabled = 0;
	sncpy(config->net_port, sizeof(config->net_port), "");
	sncpy(config->net_acl, sizeof(config->net_acl), "");
	config->net_security_headers = 1;
	sncpy(config->net_allowed_origin, sizeof(config->net_allowed_origin), "self");
	config->net_config_full_access = 0;
	config->net_web_root[0] = 0;
	config->net_auth_credential[0] = 0;

	/* clear the credential cache */
	state->rest_auth_cache[0] = 0;

	config->check_updates = 0;
	tommy_list_foreach(&config->maintenance_list, run_free);
	tommy_list_init(&config->maintenance_list);
	tommy_list_foreach(&config->smartignore_list, smartignore_free);
	tommy_list_init(&config->smartignore_list);
	config->sync_threshold_deletes = 0;
	config->sync_threshold_updates = 0;
	config->sync_prehash = 0;
	config->sync_prevent_truncations = 0;
	config->scrub_percentage = 0;
	config->scrub_older_than = 0;
	config->touch_zero_subseconds = 0;
	config->probe_interval_minutes = 0;
	config->spindown_idle_minutes_data = 0;
	config->spindown_idle_minutes_parity = 0;
	config->hook_run_as_user[0] = 0;
	config->hook_script[0] = 0;
	config->hook_docker_pause[0] = 0;
	config->notify_syslog = 0;
	config->notify_syslog_level = LVL_ERROR;
	config->notify_run_as_user[0] = 0;
	config->notify_heartbeat[0] = 0;
	config->notify_start[0] = 0;
	config->notify_result[0] = 0;
	config->notify_result_level = LVL_ERROR;
	config->notify_differences = 0;
}

void config_dup_locked(struct snapraid_state* state, struct snapraid_config* transient)
{
	struct snapraid_config* config = &state->config;

	/* preset to zero to clear also private part */
	memset(transient, 0, sizeof(*transient));

	sncpy(transient->sys_engine, sizeof(transient->sys_engine), config->sys_engine);
	sncpy(transient->sys_log_directory, sizeof(transient->sys_log_directory), config->sys_log_directory);
	transient->sys_log_retention_days = config->sys_log_retention_days;
	transient->sys_log_compression = config->sys_log_compression;
	sncpy(transient->sys_shutdown_on, sizeof(transient->sys_shutdown_on), config->sys_shutdown_on);
	transient->net_enabled = config->net_enabled;
	sncpy(transient->net_port, sizeof(transient->net_port), config->net_port);
	sncpy(transient->net_acl, sizeof(transient->net_acl), config->net_acl);
	transient->net_security_headers = config->net_security_headers;
	sncpy(transient->net_allowed_origin, sizeof(transient->net_allowed_origin), config->net_allowed_origin);
	transient->net_config_full_access = config->net_config_full_access;
	sncpy(transient->net_web_root, sizeof(transient->net_web_root), config->net_web_root);
	sncpy(transient->net_auth_credential, sizeof(transient->net_auth_credential), config->net_auth_credential);

	transient->check_updates = config->check_updates;
	tommy_list_init(&transient->maintenance_list);
	for (tommy_node* i = tommy_list_head(&config->maintenance_list); i != 0; i = i->next) {
		struct snapraid_run* run = run_dup(i->data);
		tommy_list_insert_tail(&transient->maintenance_list, &run->node, run);
	}
	tommy_list_init(&transient->smartignore_list);
	for (tommy_node* i = tommy_list_head(&config->smartignore_list); i != 0; i = i->next) {
		struct snapraid_smartignore* smartignore = smartignore_dup(i->data);
		tommy_list_insert_tail(&transient->smartignore_list, &smartignore->node, smartignore);
	}
	transient->sync_threshold_deletes = config->sync_threshold_deletes;
	transient->sync_threshold_updates = config->sync_threshold_updates;
	transient->sync_prehash = config->sync_prehash;
	transient->sync_prevent_truncations = config->sync_prevent_truncations;
	transient->scrub_percentage = config->scrub_percentage;
	transient->scrub_older_than = config->scrub_older_than;
	transient->touch_zero_subseconds = config->touch_zero_subseconds;
	transient->probe_interval_minutes = config->probe_interval_minutes;
	transient->spindown_idle_minutes_data = config->spindown_idle_minutes_data;
	transient->spindown_idle_minutes_parity = config->spindown_idle_minutes_parity;
	sncpy(transient->hook_run_as_user, sizeof(transient->hook_run_as_user), config->hook_run_as_user);
	sncpy(transient->hook_script, sizeof(transient->hook_script), config->hook_script);
	sncpy(transient->hook_docker_pause, sizeof(transient->hook_docker_pause), config->hook_docker_pause);
	transient->notify_syslog = config->notify_syslog;
	transient->notify_syslog_level = config->notify_syslog_level;
	sncpy(transient->notify_run_as_user, sizeof(transient->notify_run_as_user), config->notify_run_as_user);
	sncpy(transient->notify_heartbeat, sizeof(transient->notify_heartbeat), config->notify_heartbeat);
	sncpy(transient->notify_start, sizeof(transient->notify_start), config->notify_start);
	sncpy(transient->notify_result, sizeof(transient->notify_result), config->notify_result);
	transient->notify_result_level = config->notify_result_level;
	transient->notify_differences = config->notify_differences;
}

void config_free(struct snapraid_config* config)
{
	tommy_list_foreach(&config->maintenance_list, run_free);
	tommy_list_foreach(&config->smartignore_list, smartignore_free);
}

int config_apply_locked(struct snapraid_state* state, struct snapraid_config* transient)
{
	struct snapraid_config* config = &state->config;

	/* copy fields */
	sncpy(config->sys_engine, sizeof(config->sys_engine), transient->sys_engine);
	sncpy(config->sys_log_directory, sizeof(config->sys_log_directory), transient->sys_log_directory);
	config->sys_log_retention_days = transient->sys_log_retention_days;
	config->sys_log_compression = transient->sys_log_compression;
	sncpy(config->sys_shutdown_on, sizeof(config->sys_shutdown_on), transient->sys_shutdown_on);
	config->net_enabled = transient->net_enabled;
	sncpy(config->net_port, sizeof(config->net_port), transient->net_port);
	sncpy(config->net_acl, sizeof(config->net_acl), transient->net_acl);
	config->net_security_headers = transient->net_security_headers;
	sncpy(config->net_allowed_origin, sizeof(config->net_allowed_origin), transient->net_allowed_origin);
	config->net_config_full_access = transient->net_config_full_access;
	sncpy(config->net_web_root, sizeof(config->net_web_root), transient->net_web_root);
	sncpy(config->net_auth_credential, sizeof(config->net_auth_credential), transient->net_auth_credential);

	/* clear the credential cache */
	state->rest_auth_cache[0] = 0;

	config->check_updates = transient->check_updates;
	tommy_list_foreach(&config->maintenance_list, run_free);
	config->maintenance_list = transient->maintenance_list;
	tommy_list_init(&transient->maintenance_list);

	tommy_list_foreach(&config->smartignore_list, smartignore_free);
	config->smartignore_list = transient->smartignore_list;
	tommy_list_init(&transient->smartignore_list);

	config->sync_threshold_deletes = transient->sync_threshold_deletes;
	config->sync_threshold_updates = transient->sync_threshold_updates;
	config->sync_prehash = transient->sync_prehash;
	config->sync_prevent_truncations = transient->sync_prevent_truncations;
	config->scrub_percentage = transient->scrub_percentage;
	config->scrub_older_than = transient->scrub_older_than;
	config->touch_zero_subseconds = transient->touch_zero_subseconds;
	config->probe_interval_minutes = transient->probe_interval_minutes;
	config->spindown_idle_minutes_data = transient->spindown_idle_minutes_data;
	config->spindown_idle_minutes_parity = transient->spindown_idle_minutes_parity;
	sncpy(config->hook_run_as_user, sizeof(config->hook_run_as_user), transient->hook_run_as_user);
	sncpy(config->hook_script, sizeof(config->hook_script), transient->hook_script);
	sncpy(config->hook_docker_pause, sizeof(config->hook_docker_pause), transient->hook_docker_pause);
	config->notify_syslog = transient->notify_syslog;
	config->notify_syslog_level = transient->notify_syslog_level;
	sncpy(config->notify_run_as_user, sizeof(config->notify_run_as_user), transient->notify_run_as_user);
	sncpy(config->notify_heartbeat, sizeof(config->notify_heartbeat), transient->notify_heartbeat);
	sncpy(config->notify_start, sizeof(config->notify_start), transient->notify_start);
	sncpy(config->notify_result, sizeof(config->notify_result), transient->notify_result);
	config->notify_result_level = transient->notify_result_level;
	config->notify_differences = transient->notify_differences;

	config_set_int(config, "check_updates", config->check_updates);

	/* apply to the text copy */
	char maintenance_schedule[CONFIG_MAX];
	config_schedule_str(config, maintenance_schedule, sizeof(maintenance_schedule));
	config_set_string(config, "maintenance_schedule", maintenance_schedule);

	config_set_int(config, "sync_threshold_deletes", config->sync_threshold_deletes);
	config_set_int(config, "sync_threshold_updates", config->sync_threshold_updates);
	config_set_int(config, "sync_prehash", config->sync_prehash);
	config_set_int(config, "sync_prevent_truncations", config->sync_prevent_truncations);
	config_set_double(config, "scrub_percentage", config->scrub_percentage);
	config_set_int(config, "scrub_older_than", config->scrub_older_than);
	config_set_int(config, "touch_zero_subseconds", config->touch_zero_subseconds);
	config_set_int(config, "probe_interval_minutes", config->probe_interval_minutes);
	if (config->spindown_idle_minutes_data == config->spindown_idle_minutes_parity) {
		config_set_int(config, "spindown_idle_minutes", config->spindown_idle_minutes_data);
	} else {
		char buf[64];
		snprintf(buf, sizeof(buf), "%d, %d", config->spindown_idle_minutes_data, config->spindown_idle_minutes_parity);
		config_set_string(config, "spindown_idle_minutes", buf);
	}
	config_set_string(config, "hook_run_as_user", config->hook_run_as_user);
	config_set_string(config, "hook_script", config->hook_script);
	config_set_string(config, "hook_docker_pause", config->hook_docker_pause);
	config_set_int(config, "notify_syslog_enabled", config->notify_syslog);
	config_set(config, "notify_syslog_level", config_level(config->notify_syslog_level));
	config_set_string(config, "notify_run_as_user", config->notify_run_as_user);
	config_set_string(config, "notify_heartbeat", config->notify_heartbeat);
	config_set_string(config, "notify_start", config->notify_start);
	config_set_string(config, "notify_result", config->notify_result);
	config_set(config, "notify_result_level", config_level(config->notify_result_level));
	config_set_int(config, "notify_differences", config->notify_differences);

	config_refresh_locked(state);

	return 0;
}

void config_init(struct snapraid_state* state)
{
	struct snapraid_config* config = &state->config;

	/* set private configuration */
	app_default_conf(config->conf, sizeof(config->conf));
	config->pidfile_arg = 0;
	tommy_list_init(&config->line_list);

	/* set the public configuration */
	tommy_list_init(&config->maintenance_list);
	config_default_locked(state);

	/* refresh it */
	config_refresh_locked(state);
}

void config_done(struct snapraid_state* state)
{
	tommy_list_foreach(&state->config.line_list, config_line_free);
	tommy_list_foreach(&state->config.maintenance_list, run_free);
	tommy_list_foreach(&state->config.smartignore_list, smartignore_free);
}

