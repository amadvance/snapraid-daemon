// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "support.h"
#include "conf.h"
#include "daemon.h"
#include "elem.h"
#include "log.h"
#include "notify.h"

/****************************************************************************/
/* notify */

#include <string.h>
#include <ctype.h>
#include <stddef.h>

/*
 * Looks for option (with spaces around) in cmdline.
 * If found, extracts the following argument into dest.
 * Supports quoted arguments: "hello world" or 'hello world'
 * @return 0 if found, -1 otherwise
 */
int extract_argument(const char* cmdline, const char* option, char* dest, ssize_t dest_size)
{
	ssize_t opt_len = strlen(option);
	const char* p = cmdline;
	int match_found = 0;

	while (*p) {
		/* skip spaces */
		while (*p && isspace((unsigned char)*p))
			++p;

		/* the next token */
		const char* begin = p;
		const char* end;

		/* quoted token */
		if (*p == '"' || *p == '\'') {
			++p;
			while (*p && *p != *begin)
				++p;
			if (!*p)
				return -1; /* unterminated quote */
			++begin;
			end = p;
			++p; /* skip closing quote */
		} else {
			/* go to the end of the token */
			while (*p && !isspace((unsigned char)*p))
				++p;
			end = p;
		}

		/* check for option match */
		if (end - begin == opt_len && memcmp(begin, option, opt_len) == 0) {
			match_found = 1;
		} else if (match_found) {
			if (end - begin + 1 > dest_size)
				return -1;
			memcpy(dest, begin, end - begin);
			dest[end - begin] = 0;
			return 0;
		}
	}

	return -1;
}

int replace_argument(const char* cmdline, const char* placeholder[], const char* value[], char* dest, ssize_t dest_size)
{
	const char* src = cmdline;
	char* out = dest;
	ssize_t remaining = dest_size;

	while (*src) {
		int matched = 0;

		/* try to match any placeholder at current position */
		for (int i = 0; placeholder[i]; ++i) {
			if (src[0] == placeholder[i][0]) {
				size_t ph_len = strlen(placeholder[i]);
				if (strncmp(src, placeholder[i], ph_len) == 0) {
					/* found a match — write the corresponding value */
					ssize_t val_len = strlen(value[i]);
					if (val_len >= remaining)
						return -1;

					memcpy(out, value[i], val_len);
					out += val_len;
					remaining -= val_len;
					src += ph_len;

					matched = 1;
					break;
				}
			}
		}

		if (!matched) {
			if (remaining <= 1)
				return -1;
			*out++ = *src++;
			remaining--;
		}
	}

	*out = 0;
	return 0;
}

static int result_locked(struct snapraid_state* state, int high_cmd, int report_level, const char* report_text)
{
	char cmd[1024];
	char template[CONFIG_MAX];
	char run_as_user[CONFIG_MAX];
	char command[32];
	char subject[MSG_MAX];
	char level[32];
	const char* ntfy_priority;
	const char* ntfy_tag;
	char from[KEYWORD_MAX];
	char to[KEYWORD_MAX];
	int email_format = 0;
	ss_t ss;

	sncpy(command, sizeof(command), command_name(high_cmd));
	command[0] = toupper((unsigned char)command[0]);
	sncpy(run_as_user, sizeof(run_as_user), state->config.notify_run_as_user);
	sncpy(template, sizeof(template), state->config.notify_result);
	sncpy(level, sizeof(level), config_level_str(report_level));
	strupr(level);
	snprintf(subject, sizeof(subject), "[%s] SnapRAID %s", level, command);

	switch (report_level) {
	case LVL_CRITICAL : /* hardware problem */
		ntfy_priority = "urgent";
		ntfy_tag = "rotating_light";
		break;
	case LVL_ERROR : /* task terminated with error, like too many files missing */
		ntfy_priority = "high";
		ntfy_tag = "warning";
		break;
	case LVL_WARNING : /* task canceled, interrupted, diff detected */
		ntfy_priority = "default";
		ntfy_tag = "-1";
		break;
	case LVL_INFO : /* normal termination */
		ntfy_priority = "low";
		ntfy_tag = "+1";
		break;
	default :
	case LVL_DEBUG : /* never happens */
		ntfy_priority = "min";
		ntfy_tag = "heavy_check_mark";
		break;
	}

#define PLACEHOLDERS 7
	const char* placeholders[PLACEHOLDERS] = {
		"%s",
		"%l",
		"%n",
		"%t",
		"--wide",
		"--narrow",
		0
	};
	const char* values[PLACEHOLDERS] = {
		subject,
		config_level_str(report_level),
		ntfy_priority,
		ntfy_tag,
		"", /* --wide */
		"", /* --narrow */
		0
	};

	/* release the lock to call the command */
	state_unlock();

	ss_init(&ss, strlen(report_text) + 128);

	if (replace_argument(template, placeholders, values, cmd, sizeof(cmd)) != 0) {
		log_task(LVL_ERROR, "command string overflow, notification not sent");
		goto bail;
	}

	/* prepend a minimal email header if pertinent */
	if (extract_argument(cmd, "--mail-from", from, sizeof(from)) == 0) {
		ss_printf(&ss, "From: SnapRAID <%s>\n", from);
		email_format = 1;
	}
	if (extract_argument(cmd, "--mail-rcpt", to, sizeof(to)) == 0) {
		ss_printf(&ss, "To: %s\n", to);
		email_format = 1;
	}
	if (email_format) {
		ss_printf(&ss, "Subject: %s\n", subject);
		ss_prints(&ss, "\n");
	}

	/* report text */
	ss_prints(&ss, report_text);

	int ret = os_command(cmd, run_as_user, ss_extract(&ss));
	if (ret != 0) {
		report_level = level_mix(report_level, LVL_ERROR); /* mix the levels, if it's CRITICAL, log as CRITICAL */
		log_task(report_level, "failed to send %s report", config_level_str(report_level));
		goto bail;
	}

	log_task(LVL_INFO, "sent %s report", config_level_str(report_level));

	ss_done(&ss);
	state_lock();
	return 0;

bail:
	ss_done(&ss);
	state_lock();
	return -1;
}

static int heartbeat_locked(struct snapraid_state* state)
{
	char cmd[1024];
	char template[CONFIG_MAX];
	char run_as_user[CONFIG_MAX];

	sncpy(run_as_user, sizeof(run_as_user), state->config.notify_run_as_user);
	sncpy(template, sizeof(template), state->config.notify_heartbeat);

	/* release the lock to call the command */
	state_unlock();

	sncpy(cmd, sizeof(cmd), template);

	int ret = os_command(cmd, run_as_user, 0);
	if (ret != 0) {
		log_task(LVL_ERROR, "failed to hearbeat");
		goto bail;
	}

	log_task(LVL_INFO, "sent hearbeat");

	state_lock();
	return 0;

bail:
	state_lock();
	return -1;
}

int notify_locked(struct snapraid_state* state, int high_cmd, int report_level, const char* report_text)
{
	int ret = 0;

	if (!high_cmd)
		high_cmd = CMD_REPORT;

	/* result is notified on ALL reports */
	if (state->config.notify_result[0] != 0
		&& report_level <= state->config.notify_result_level) {
		if (result_locked(state, high_cmd, report_level, report_text) != 0)
			ret = -1;
	}

	/* heartbeat is notified only on MAINTENANCE reports */
	if (state->config.notify_heartbeat[0] != 0
		&& high_cmd == CMD_MAINTENANCE
		&& report_level >= LVL_WARNING) {
		if (heartbeat_locked(state) != 0)
			ret = -1;
	}

	return ret;
}

