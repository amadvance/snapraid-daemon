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

	*out = '\0';
	return 0;
}

static void result_locked(struct snapraid_state* state, int high_cmd, int report_level, const char* report_text)
{
	char cmd[1024];
	char template[CONFIG_MAX];
	char run_as_user[CONFIG_MAX];
	char command[32];
	char subject[128];
	char level[32];
	const char* ntfy_priority;
	const char* ntfy_tag;
	char from[128];
	char to[128];
	int email_format = 0;
	const char* placeholders[7] = {
		"%s",
		"%l",
		"%n",
		"%t",
		"--wide",
		"--narrow",
		0
	};
	const char* values[6];
	ss_t ss;

	sncpy(command, sizeof(command), command_name(high_cmd));
	command[0] = toupper((int)command[0]);
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

	values[0] = subject;
	values[1] = config_level_str(report_level);
	values[2] = ntfy_priority;
	values[3] = ntfy_tag;
	values[4] = ""; /* --wide */
	values[5] = ""; /* --narrow */

	/* release the lock to call the command */
	state_unlock();

	ss_init(&ss, strlen(report_text) + 128);

	if (replace_argument(template, placeholders, values, cmd, sizeof(cmd)) != 0) {
		log_msg_locked(LVL_ERROR, "command string overflow, notification not sent");
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

	int ret = daemon_command(cmd, run_as_user, ss_extract(&ss));
	if (ret != 0) {
		report_level = level_mix(report_level, LVL_ERROR); /* mix the levels, if it's CRITICAL, log as CRITICAL */
		log_msg(report_level, "failed to send %s report", config_level_str(report_level));
		goto bail;
	}

	log_msg(LVL_INFO, "sent %s report", config_level_str(report_level));

bail:
	ss_done(&ss);
	state_lock();
}

static void heartbeat_locked(struct snapraid_state* state)
{
	char cmd[1024];
	char template[CONFIG_MAX];
	char run_as_user[CONFIG_MAX];

	sncpy(run_as_user, sizeof(run_as_user), state->config.notify_run_as_user);
	sncpy(template, sizeof(template), state->config.notify_heartbeat);

	/* release the lock to call the command */
	state_unlock();

	sncpy(cmd, sizeof(cmd), template);

	int ret = daemon_command(cmd, run_as_user, 0);
	if (ret != 0) {
		log_msg(LVL_ERROR, "failed to hearbeat");
		goto bail;
	}

	log_msg(LVL_INFO, "sent hearbeat");

bail:
	state_lock();
}

void notify_locked(struct snapraid_state* state, int high_cmd, int report_level, const char* report_text)
{
	if (!high_cmd)
		high_cmd = CMD_REPORT;

	if (state->config.notify_result[0] != 0
		&& report_level <= state->config.notify_result_level)
		result_locked(state, high_cmd, report_level, report_text);

	if (state->config.notify_heartbeat[0] != 0
		&& high_cmd == CMD_MAINTENANCE
		&& report_level == LVL_INFO)
		heartbeat_locked(state);
}

