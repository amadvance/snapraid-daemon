// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "support.h"
#include "rest.h"
#include "runner.h"
#include "scheduler.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "web.h"
#include "daemon.h"

/****************************************************************************/

static void version(void)
{
	printf(PACKAGE_NAME " v" VERSION " by Andrea Mazzoleni, " PACKAGE_URL "\n");
}

static void usage(const char* conf)
{
	version();

	printf("Usage: " DAEMON " [options]\n");
	printf("\n");
	printf("Options:\n");
	printf("  " SWITCH_GETOPT_LONG("-c, --conf FILE       ", "-c") "  Configuration file\n");
	printf("  " SWITCH_GETOPT_LONG("-f, --foreground      ", "-f") "  Run in foreground (do not daemonize)\n");
	printf("  " SWITCH_GETOPT_LONG("-N, --no-cache        ", "-N") "  Load web pages at runtime without caching them\n");
	printf("  " SWITCH_GETOPT_LONG("-p, --pidfile FILE    ", "-p") "  Override the default PID file location\n");
	printf("  " SWITCH_GETOPT_LONG("-v, --verbose         ", "-v") "  Verbose output\n");
	printf("  " SWITCH_GETOPT_LONG("-H, --help            ", "-H") "  Show this help message\n");
	printf("  " SWITCH_GETOPT_LONG("-V, --version         ", "-V") "  Show version and exit\n");

	printf("\n");
	printf("Configuration file: %s\n", conf);
	printf("\n");
}

/****************************************************************************/
/* main */

#if HAVE_GETOPT_LONG
struct option long_options[] = {
	{ "foreground", 0, 0, 'f' },
	{ "conf", 1, 0, 'c' },
	{ "no-cache", 0, 0, 'N' },
	{ "pidfile", 1, 0, 'p' },
	{ "verbose", 0, 0, 'v' },
	{ "help", 0, 0, 'H' },
	{ "version", 0, 0, 'V' },

	{ 0, 0, 0, 0 }
};
#endif

#define OPTIONS "fc:Np:vHV"

void daemon_options(struct snapraid_state* state, int argc, char* argv[])
{
	int c;

	config_init(state);

	while ((c =
#if HAVE_GETOPT_LONG
		getopt_long(argc, argv, OPTIONS, long_options, 0))
#else
		getopt(argc, argv, OPTIONS))
#endif
		!= EOF) {
		switch (c) {
		case 'f' :
			state->log.foreground = 1;
			break;
		case 'c' :
			sncpy(state->config.conf, sizeof(state->config.conf), optarg);
			break;
		case 'N' :
			state->web.page_nocache = 1;
			break;
		case 'p' :
			state->config.pidfile_arg = optarg;
			break;
		case 'v' :
			state->log.verbose = 1;
			break;
		case 'H' :
			usage(state->config.conf);
			exit(EXIT_SUCCESS);
		case 'V' :
			version();
			exit(EXIT_SUCCESS);
		default :
			usage(state->config.conf);
			exit(EXIT_FAILURE);
		}
	}
}

int daemon_init(struct snapraid_state* state)
{
	char msg[MSG_MAX];
	int status;

	log_init(DAEMON);
	log_msg(LVL_INFO, "daemon starting");
	log_msg(LVL_INFO, "version=%s", VERSION);
#ifndef _WIN32
	log_msg(LVL_INFO, "uid=%d gid=%d euid=%d egid=%d", getuid(), getgid(), geteuid(), getegid());
#endif

	if (config_load_locked(state) != 0) {
		log_msg(LVL_ERROR, "failed to load config from %s", state->config.conf);
		return -1;
	}

	/**
	 * Load system information
	 */
	os_system(&state->system);

	/**
	 * Create runner worker threads while signals are still BLOCKED
	 */
	runner_init(state);

	/**
	 * Parse existing log files
	 */
	parse_past_log(state);

	/**
	 * Log loaded
	 */
	state->daemon_running = DAEMON_STARTING;

	/*
	 * Trigger initial probe to load info into the state
	 */
	if (runner(state, CMD_STARTUP, CMD_PROBE, 0, 0, msg, sizeof(msg), &status) != 0) {
		log_msg(LVL_ERROR, "failed to run the startup probe command");
		/* continue anyway to provide an interface */
	}

	/**
	 * Create scheduler worker threads while signals are still BLOCKED
	 */
	scheduler_init(state);

	if (rest_init(state) != 0) {
		log_msg(LVL_ERROR, "failed to start the rest api");
		return -1;
	}

	/**
	 * Create web worker threads while signals are still BLOCKED
	 */
	if (web_init(state) != 0) {
		log_msg(LVL_ERROR, "failed to start the web server");
		return -1;
	}

	return 0;
}

void daemon_run(struct snapraid_state* state)
{
	log_msg(LVL_INFO, "daemon ready");

	state_lock();

	state->daemon_running = DAEMON_RUNNING;

	while (state->daemon_running) { /* stopped by signals */
		if (state->daemon_running == DAEMON_RELOAD) {
			state->daemon_running = DAEMON_RUNNING;

			log_msg(LVL_INFO, "reload requested");

			if (config_reload_locked(state) != 0) {
				log_msg(LVL_ERROR, "failed to reload config from %s", state->config.conf);
			}

			char net_web_root[PATH_MAX];
			sncpy(net_web_root, sizeof(net_web_root), state->config.net_web_root);

			state_unlock();

			if (web_reload(state, net_web_root) != 0) {
				log_msg(LVL_ERROR, "failed to reload web pages from %s", net_web_root);
			}

			state_lock();
		}

		scheduler_pulse(state);

		/*
		 * The sleep call is interrupted by signals even with SA_RESTART.
		 * See "man 7 signal".
		 */
		state_unlock();
		sleep(5);
		state_lock();
	}

	if (state->daemon_sig)
		log_msg(LVL_INFO, "shutdown requested signal=%s(%d)", signal_name(state->daemon_sig), state->daemon_sig);

	state_unlock();

	log_msg(LVL_INFO, "daemon exiting cleanly");
}

void daemon_done(struct snapraid_state* state)
{
	web_done(state);
	rest_done(state);
	scheduler_done(state);
	runner_done(state);
	config_done(state);

	log_msg(LVL_INFO, "daemon stopped");

	log_done();
}

