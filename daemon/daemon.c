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
#include "log.h"
#include "parser.h"
#include "daemon.h"

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

static void run(struct snapraid_state* state)
{
	log_msg(LVL_INFO, "daemon ready");

	while (state->daemon_running) {
		if (state->daemon_running == DAEMON_RELOAD) {
			state->daemon_running = DAEMON_RUNNING;

			log_msg(LVL_INFO, "reload requested");

			state_lock();

			if (config_reload(state) != 0) {
				log_msg(LVL_ERROR, "failed to reload config from %s", state->config.conf);
			}

			state_unlock();


		}

		scheduler(state);

		/*
		 * The sleep call is interrupted by signals even with SA_RESTART.
		 * See "man 7 signal".
		 */
		sleep(10);
	}

	if (state->daemon_sig)
		log_msg(LVL_INFO, "shutdown requested signal=%s(%d)", log_signame(state->daemon_sig), state->daemon_sig);

	log_msg(LVL_INFO, "daemon exiting cleanly");
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
	char msg[128];
	int status;

	state_init();

	config_init(&state_ptr()->config, argv[0]);

	while ((c =
#if HAVE_GETOPT_LONG
		getopt_long(argc, argv, OPTIONS, long_options, 0))
#else
		getopt(argc, argv, OPTIONS))
#endif
		!= EOF) {
		switch (c) {
		case 'f' :
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
		default :
			usage(state_ptr()->config.conf);
			exit(EXIT_FAILURE);
		}
	}

	log_init(PACKAGE);

	log_msg(LVL_INFO, "daemon starting");

	if (!foreground) {
		if (os_daemonize() < 0) {
			log_msg(LVL_ERROR, "failed to daemonize");
			exit(EXIT_FAILURE);
		}
	}

	log_msg(LVL_INFO, "version=%s", VERSION);
	log_msg(LVL_INFO, "uid=%d gid=%d euid=%d egid=%d", getuid(), getgid(), geteuid(), getegid());

	if (config_load(state_ptr()) != 0) {
		log_msg(LVL_ERROR, "failed to load config from %s", state_ptr()->config.conf);
		exit(EXIT_FAILURE);
	}

	/*
	 * Install signal handlers
	 */
	os_signal_init();

	/*
	 * Block signals in the main thread
	 */
	os_signal_set(0);

	/**
	 * Create worker threads while signals are still BLOCKED
	 */
	runner_init(state_ptr());

	/**
	 * Parse existing log files
	 */
	parse_past_log(state_ptr());

	/*
	 * Load initial info into the state
	 */
	if (runner(state_ptr(), CMD_PROBE, 0, msg, sizeof(msg), &status) != 0) {
		log_msg(LVL_ERROR, "failed to run the first probe command");
		exit(EXIT_FAILURE);
	}

	scheduler_init(state_ptr());

	if (rest_init(state_ptr()) != 0) {
		log_msg(LVL_ERROR, "failed to start the web server");
		exit(EXIT_FAILURE);
	}

	/*
	 * Unblock signals ONLY in main thread
	 * Worker threads keep them blocked forever.
	 */
	os_signal_set(1);

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

	log_msg(LVL_INFO, "daemon stopped");

	log_done();
	state_done();

	return 0;
}

