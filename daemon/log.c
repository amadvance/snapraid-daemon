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
#include "log.h"

/****************************************************************************/
/* log */

static int level_map[] = {
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_INFO
};

int log_init(const char* ident)
{
	openlog(ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	return 0;
}


static void log_out(int level, int syslog, int termlog, const char* fmt, va_list ap)
{
	va_list ap2;

	va_copy(ap2, ap);

	if (syslog)
		vsyslog(level_map[level], fmt, ap);

	if (termlog) {
		char buf[2048];
		vsnprintf(buf, sizeof(buf), fmt, ap2);
		switch (level) {
		case LVL_CRITICAL :
			fprintf(stderr, PACKAGE "[%" PRIu64 "]:critical: %s\n", (uint64_t)getpid(), buf);
			break;
		case LVL_ERROR :
			fprintf(stderr, PACKAGE "[%" PRIu64 "]:error: %s\n", (uint64_t)getpid(), buf);
			break;
		case LVL_WARNING :
			fprintf(stdout, PACKAGE "[%" PRIu64 "]:warning: %s\n", (uint64_t)getpid(), buf);
			fflush(stdout);
			break;
		case LVL_INFO :
			fprintf(stdout, PACKAGE "[%" PRIu64 "]:info: %s\n", (uint64_t)getpid(), buf);
			fflush(stdout);
			break;
		}
	}

	va_end(ap2);
}

void log_msg(int level, const char *fmt, ...)
{
	int syslog;
	int termlog;
	va_list ap;

	va_start(ap, fmt);

	state_lock();
	struct snapraid_state* state = state_ptr();
	syslog = state->config.notify_syslog_enabled && level <= state->config.notify_syslog_level;
	termlog = state->foreground;
	state_unlock();

	log_out(level, syslog, termlog, fmt, ap);

	va_end(ap);
}

void log_msg_locked(int level, const char *fmt, ...)
{
	int syslog;
	int termlog;
	va_list ap;

	va_start(ap, fmt);

	struct snapraid_state* state = state_ptr();
	syslog = state->config.notify_syslog_enabled && level <= state->config.notify_syslog_level;
	termlog = state->foreground;

	log_out(level, syslog, termlog, fmt, ap);

	va_end(ap);
}

void log_done(void)
{
	closelog();
}

const char* signal_name(int sig)
{
	switch (sig) {
	case SIGHUP : return "SIGHUP";
	case SIGINT : return "SIGINT";
	case SIGQUIT : return "SIGQUIT";
	case SIGILL : return "SIGILL";
	case SIGTRAP : return "SIGTRAP";
	case SIGABRT : return "SIGABRT";
	case SIGBUS : return "SIGBUS";
	case SIGFPE : return "SIGFPE";
	case SIGKILL : return "SIGKILL";
	case SIGUSR1 : return "SIGUSR1";
	case SIGSEGV : return "SIGSEGV";
	case SIGUSR2 : return "SIGUSR2";
	case SIGPIPE : return "SIGPIPE";
	case SIGALRM : return "SIGALRM";
	case SIGTERM : return "SIGTERM";
	}

	return "UNKNOWN";
}

