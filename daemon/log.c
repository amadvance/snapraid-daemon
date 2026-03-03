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

#ifndef _WIN32
static int level_map[] = {
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG
};
#endif

int log_init(const char* ident)
{
#ifndef _WIN32
	openlog(ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
#else
	(void)ident;
#endif
	return 0;
}

#ifndef _WIN32
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
#else
static void log_out(int level, int syslog, int termlog, const char* fmt, va_list ap)
{
	(void)level;
	(void)syslog;

	if (syslog) {
		char buf[1024];
		vsnprintf(buf, sizeof(buf), fmt, ap);
		windows_eventlog(level, buf);
	}

	if (termlog) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}
#endif

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
#ifndef _WIN32
	closelog();
#endif
}

const char* signal_name(int sig)
{
	switch (sig) {
#ifdef SIGHUP
	case SIGHUP : return "SIGHUP";
#endif
#ifdef SIGINT
	case SIGINT : return "SIGINT";
#endif
#ifdef SIGQUIT
	case SIGQUIT : return "SIGQUIT";
#endif
#ifdef SIGILL
	case SIGILL : return "SIGILL";
#endif
#ifdef SIGTRAP
	case SIGTRAP : return "SIGTRAP";
#endif
#ifdef SIGABRT
	case SIGABRT : return "SIGABRT";
#endif
#ifdef SIGBUS
	case SIGBUS : return "SIGBUS";
#endif
#ifdef SIGFPE
	case SIGFPE : return "SIGFPE";
#endif
#ifdef SIGKILL
	case SIGKILL : return "SIGKILL";
#endif
#ifdef SIGUSR1
	case SIGUSR1 : return "SIGUSR1";
#endif
#ifdef SIGSEGV
	case SIGSEGV : return "SIGSEGV";
#endif
#ifdef SIGUSR2
	case SIGUSR2 : return "SIGUSR2";
#endif
#ifdef SIGPIPE
	case SIGPIPE : return "SIGPIPE";
#endif
#ifdef SIGALRM
	case SIGALRM : return "SIGALRM";
#endif
#ifdef SIGTERM
	case SIGTERM : return "SIGTERM";
#endif
	}

	return "UNKNOWN";
}

