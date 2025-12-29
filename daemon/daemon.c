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
#include "rest.h"
#include "runner.h"
#include "scheduler.h"
#include "conf.h"

#define PID_FILE "/var/run/snapraidd.pid"

/****************************************************************************/

static void version(void)
{
	printf(PACKAGE " v" VERSION " by Andrea Mazzoleni, " PACKAGE_URL "\n");
}

static void usage(const char* conf)
{
	version();

	printf("Usage: " PACKAGE " [options]\n");
	printf("\n");
	printf("Options:\n");
	printf("  " SWITCH_GETOPT_LONG("-c, --conf FILE       ", "-c") "  Configuration file\n");
	printf("  " SWITCH_GETOPT_LONG("-f, --foreground      ", "-f") "  Run in foreground (do not daemonize)\n");	
	printf("\n");
	printf("Configuration file: %s\n", conf);
	printf("\n");
}

/****************************************************************************/
/* daemon */

static void signal_handler_term(int sig)
{
	(void)sig;
	state_ptr()->daemon_running = DAEMON_QUIT;
}

void signal_handler_hup(int sig) 
{
	(void)sig;
	state_ptr()->daemon_running = DAEMON_RELOAD;
}

void signal_set(int enable)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGHUP);

	pthread_sigmask(enable ? SIG_UNBLOCK : SIG_BLOCK, &set, 0);
}

void signal_init(void)
{
#if HAVE_SIGACTION
	struct sigaction sa;

	sa.sa_handler = signal_handler_term;
	sigemptyset(&sa.sa_mask);  
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGQUIT, &sa, 0);

	sa.sa_handler = signal_handler_hup;
	sigemptyset(&sa.sa_mask);  
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGHUP, &sa, 0);

	sa.sa_handler = SIG_IGN; /* ignore the signal */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, 0);
#else
	signal(SIGTERM, signal_handler_term);
	signal(SIGINT, signal_handler_term);
	signal(SIGQUIT, signal_handler_term);
	signal(SIGHUP, signal_handler_hup);
	signal(SIGPIPE, SIG_IGN);
#endif
}

static int daemonize(void)
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
		return -1;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);
	chdir("/");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	int fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}

	return 0;
}

static void run(struct snapraid_state* state)
{
	printf("Running...\n");

	while (state->daemon_running) {
		if (state->daemon_running == DAEMON_RELOAD) {
			state->daemon_running = DAEMON_RUNNING;

			printf("Reload...\n");

			state_lock();
			config_load(&state->config);
			state_unlock();
		}

		scheduler(state);

		/*
		 * The sleep call is interrupted by signals even with SA_RESTART.
		 * See "man 7 signal".
		 */
		sleep(10);
	}

	printf("Stopping...\n");
}

/****************************************************************************/
/* config */

void config(struct snapraid_state* state, const char* argv0)
{
	(void)argv0;

#ifdef SYSCONFDIR
	/* if it exists, give precedence at sysconfdir, usually /usr/local/etc */
	if (access(SYSCONFDIR "/snapraidd.conf", F_OK) == 0)
		sncpy(state->config.conf, sizeof(state->config.conf), SYSCONFDIR "/snapraidd.conf");
	else /* otherwise fallback to plain /etc */
#endif
		sncpy(state->config.conf, sizeof(state->config.conf), "/etc/snapraidd.conf");
}

/****************************************************************************/
/* main */

#if HAVE_GETOPT_LONG
struct option long_options[] = {
	{ "foreground", 0, 0, 'f' },
	{ "conf", 1, 0, 'c' },
	{ "help", 0, 0, 'H' },
	{ "version", 0, 0, 'V' },

	{ 0, 0, 0, 0 }
};
#endif

#define OPTIONS "fc:HV"

int main(int argc, char *argv[])
{
	int c;
	int foreground = 1; // TODO

	state_init();

	/* defaults */
	config(state_ptr(), argv[0]);
	
	static const char* options[] = {
		"listening_ports", "8080",
		"num_threads", "50",
		NULL
	};

	while ((c =
#if HAVE_GETOPT_LONG
		getopt_long(argc, argv, OPTIONS, long_options, 0))
#else
		getopt(argc, argv, OPTIONS))
#endif
		!= EOF) {
		switch (c) {
		case 'f':
			foreground = 1;
			break;
		case 'c' :
			sncpy(state_ptr()->config.conf, sizeof(state_ptr()->config.conf), optarg);
			break;
		case 'H' :
			usage(state_ptr()->config.conf);
			exit(EXIT_SUCCESS);
		case 'V' :
			version();
			exit(EXIT_SUCCESS);
		default:
			usage(state_ptr()->config.conf);
			exit(EXIT_FAILURE);
		}
	}

	if (config_load(&state_ptr()->config) != 0) {
		// TODO log/fail
		exit(EXIT_FAILURE);
	}

	if (!foreground) {
		if (daemonize() < 0) {
			// TODO log/fail
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * Install signal handlers
	 */
	signal_init();

	/*
	 * Block signals in the main thread
	 */
	signal_set(0);

	/**
	 * Create worker threads while signals are still BLOCKED
	 */
	runner_init(state_ptr());

	/*
	 * Load initial info into the state
	 */
	runner(state_ptr(), CMD_PROBE, 0, 0);

	scheduler_init(state_ptr());
	rest_init(state_ptr(), options);

	/*
	 * Unblock signals ONLY in main thread
	 * Worker threads keep them blocked forever.
	 */
	signal_set(1);

	/*
	 * Main loop
	 *
	 * It's stopped by signals
	 */
	run(state_ptr());

	rest_done(state_ptr());
	scheduler_done(state_ptr());
	runner_done(state_ptr());

	if (!foreground)
		unlink(PID_FILE);

	state_done();

	return 0;
}

/*
curl -X POST http://localhost:8080/api/v1/sync
curl -X POST http://localhost:8080/api/v1/sync -d '{"args": ["--force-zero", "--force-empty"]}'
curl -X POST http://localhost:8080/api/v1/probe
curl -X POST http://localhost:8080/api/v1/up
curl -X POST http://localhost:8080/api/v1/down
curl -X POST http://localhost:8080/api/v1/smart
curl -X GET http://localhost:8080/api/v1/disks
curl -X GET http://localhost:8080/api/v1/progress
curl -X GET http://localhost:8080/api/v1/config
*/

