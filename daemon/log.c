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
	LOG_INFO,
	LOG_DEBUG
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
		vfprintf(stdout, fmt, ap2);
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	va_end(ap2);
}

void log_msg(int level, const char* fmt, ...)
{
	int syslog;
	int termlog;
	int verboselog;
	va_list ap;

	log_lock();
	struct snapraid_state* state = state_ptr();
	syslog = state->log.syslog && level <= state->log.syslog_level;
	termlog = state->log.foreground;
	verboselog = state->log.verbose;
	log_unlock();

	if (level == LVL_DEBUG && !verboselog)
		return;

	va_start(ap, fmt);
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

