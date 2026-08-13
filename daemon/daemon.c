// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#include "app.h"
#include "state.h"
#include "support.h"
#include "rest.h"
#include "runner.h"
#include "scheduler.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "web.h"

/****************************************************************************/
/* helpers */

static void gen_auth(const char* arg)
{
	char* colon = strchr(arg, ':');
	if (colon == 0) {
		fprintf(stderr, "Error: Invalid argument format. Expected USERNAME:PASSWORD\n");
		exit(EXIT_FAILURE);
	}

	size_t user_len = colon - arg;
	char* username = malloc_nofail(user_len + 1);
	memcpy(username, arg, user_len);
	username[user_len] = 0;

	const char* password = colon + 1;
	if (username[0] == 0 || password[0] == 0) {
		fprintf(stderr, "Error: Username and password must not be empty\n");
		free(username);
		exit(EXIT_FAILURE);
	}

	uint8_t salt[16];
	if (os_randomize(salt, sizeof(salt)) != 0) {
		fprintf(stderr, "Error: Failed to generate random salt\n");
		free(username);
		exit(EXIT_FAILURE);
	}

	void* work_area = malloc_nofail(AUTH_NB_BLOCKS * 1024);

	uint8_t hash[32];
	crypto_argon2_config config;
	config.algorithm = CRYPTO_ARGON2_ID;
	config.nb_blocks = AUTH_NB_BLOCKS;
	config.nb_passes = AUTH_NB_PASSES;
	config.nb_lanes = AUTH_NB_LANES;

	crypto_argon2_inputs inputs;
	inputs.pass = (const uint8_t*)password;
	inputs.pass_size = strlen(password);
	inputs.salt = salt;
	inputs.salt_size = sizeof(salt);

	crypto_argon2(hash, sizeof(hash), work_area, config, inputs, crypto_argon2_no_extras);

	free(work_area);

	char salt_b64[64];
	size_t salt_b64_len = sizeof(salt_b64);
	if (mg_base64_encode(salt, sizeof(salt), salt_b64, &salt_b64_len) != -1) {
		fprintf(stderr, "Error: Failed to base64 encode salt\n");
		free(username);
		exit(EXIT_FAILURE);
	}

	char hash_b64[128];
	size_t hash_b64_len = sizeof(hash_b64);
	if (mg_base64_encode(hash, sizeof(hash), hash_b64, &hash_b64_len) != -1) {
		fprintf(stderr, "Error: Failed to base64 encode hash\n");
		free(username);
		exit(EXIT_FAILURE);
	}

	printf("Generated credential line for snapraidd.conf:\n\n");
	printf("net_auth_credential = %s:$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s\n\n", username, AUTH_NB_BLOCKS, AUTH_NB_PASSES, AUTH_NB_LANES, salt_b64, hash_b64);
	printf("Copy the 'net_auth_credential' line above and paste it into your snapraidd.conf file.\n");

	free(username);
	exit(EXIT_SUCCESS);
}

static void version(void)
{
	printf(PACKAGE_NAME " v" VERSION " by Andrea Mazzoleni, " PACKAGE_URL "\n");
}

static void usage(const char* conf)
{
	version();

	printf("Usage: " DAEMON_NAME " [options]\n");
	printf("\n");
	printf("Options:\n");
	printf("  " SWITCH_GETOPT_LONG("-c, --conf FILE       ", "-c") "  Configuration file\n");
	printf("  " SWITCH_GETOPT_LONG("-C, --engine-conf FILE", "-C") "  Override the default SnapRAID configuration file path\n");
	printf("  " SWITCH_GETOPT_LONG("-i, --instance NAME   ", "-i") "  Specify the daemon instance name\n");
	printf("  " SWITCH_GETOPT_LONG("-f, --foreground      ", "-f") "  Run in foreground (do not daemonize)\n");
	printf("  " SWITCH_GETOPT_LONG("-N, --no-cache        ", "-N") "  Load web pages at runtime without caching them\n");
	printf("  " SWITCH_GETOPT_LONG("-p, --pidfile FILE    ", "-p") "  Override the default PID file location\n");
	printf("  " SWITCH_GETOPT_LONG("-v, --verbose         ", "-v") "  Verbose output\n");
	printf("  " SWITCH_GETOPT_LONG("-g, --gen-auth U:P    ", "-g") "  Generate Argon2id credential line\n");
#ifdef __MINGW32__
#if HAVE_GETOPT_LONG
	printf("  " "    --service-install   " "  Install the current configuration as a Windows service\n");
	printf("  " "    --service-remove    " "  Remove the Windows service of the current configuration\n");
	printf("  " "    --service-start-all " "  Start all Windows services associated with the daemon\n");
	printf("  " "    --service-stop-all  " "  Stop all Windows services associated with the daemon\n");
	printf("  " "    --service-remove-all" "  Stop and remove all Windows services associated with the daemon\n");
	printf("  " "    --service-list      " "  List all Windows services associated with the daemon\n");
#endif
#endif
	printf("  " SWITCH_GETOPT_LONG("-H, --help            ", "-H") "  Show this help message\n");
	printf("  " SWITCH_GETOPT_LONG("-V, --version         ", "-V") "  Show version and exit\n");

	printf("\n");
	printf("Configuration file: %s\n", conf);
	printf("\n");
}

/****************************************************************************/
/* main */

#define OPT_SERVICE_INSTALL 256
#define OPT_SERVICE_REMOVE 257
#define OPT_SERVICE_START_ALL 258
#define OPT_SERVICE_STOP_ALL 259
#define OPT_SERVICE_REMOVE_ALL 260
#define OPT_SERVICE_LIST 261

#if HAVE_GETOPT_LONG
struct option long_options[] = {
	{ "foreground", 0, 0, 'f' },
	{ "conf", 1, 0, 'c' },
	{ "engine-conf", 1, 0, 'C' },
	{ "instance", 1, 0, 'i' },
	{ "no-cache", 0, 0, 'N' },
	{ "pidfile", 1, 0, 'p' },
	{ "verbose", 0, 0, 'v' },
	{ "gen-auth", 1, 0, 'g' },
	{ "help", 0, 0, 'H' },
	{ "version", 0, 0, 'V' },
#ifdef __MINGW32__
	{ "service-install", 0, 0, OPT_SERVICE_INSTALL },
	{ "service-remove", 0, 0, OPT_SERVICE_REMOVE },
	{ "service-start-all", 0, 0, OPT_SERVICE_START_ALL },
	{ "service-stop-all", 0, 0, OPT_SERVICE_STOP_ALL },
	{ "service-remove-all", 0, 0, OPT_SERVICE_REMOVE_ALL },
	{ "service-list", 0, 0, OPT_SERVICE_LIST },
#endif
	{ 0, 0, 0, 0 }
};
#endif

#define OPTIONS "fc:C:i:Np:vg:HV"

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
		case 'C' :
			sncpy(state->array.engine_conf, sizeof(state->array.engine_conf), optarg);
			break;
		case 'i' : {
			if (optarg[0] == 0) {
				fprintf(stderr, "Error: Instance name cannot be empty\n");
				exit(EXIT_FAILURE);
			}
			size_t len = strspn(optarg, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-");
			if (optarg[len] != 0) {
				fprintf(stderr, "Error: Invalid character '%c' in instance name. Only [a-zA-Z0-9_-] are allowed.\n", optarg[len]);
				exit(EXIT_FAILURE);
			}
			sncpy(state->instance, sizeof(state->instance), optarg);
			app_instance(state->instance);
			break;
		}
		case 'N' :
			state->web.page_nocache = 1;
			break;
		case 'p' :
			state->config.pidfile_arg = optarg;
			break;
		case 'v' :
			state->log.verbose = 1;
			break;
		case 'g' :
			gen_auth(optarg);
			break;
		case 'H' :
			usage(state->config.conf);
			exit(EXIT_SUCCESS);
		case 'V' :
			version();
			exit(EXIT_SUCCESS);
#ifdef __MINGW32__
		case OPT_SERVICE_INSTALL :
			state->service_install = 1;
			break;
		case OPT_SERVICE_REMOVE :
			state->service_remove = 1;
			break;
		case OPT_SERVICE_START_ALL :
			state->service_start_all = 1;
			break;
		case OPT_SERVICE_STOP_ALL :
			state->service_stop_all = 1;
			break;
		case OPT_SERVICE_REMOVE_ALL :
			state->service_remove_all = 1;
			break;
		case OPT_SERVICE_LIST :
			state->service_list = 1;
			break;
#endif
		default :
			usage(state->config.conf);
			exit(EXIT_FAILURE);
		}
	}

#ifdef __MINGW32__
	if (state->service_install + state->service_remove
		+ state->service_start_all + state->service_stop_all
		+ state->service_remove_all + state->service_list > 1) {
		fprintf(stderr, "Error: Service options are mutually exclusive.\n");
		exit(EXIT_FAILURE);
	}
#endif
}

int daemon_init(struct snapraid_state* state)
{
	char msg[MSG_MAX];
	int status;

	if (state->instance[0]) {
		snprintf(state->log_ident, sizeof(state->log_ident), "%s-%s", DAEMON_NAME, state->instance);
		log_init(state->log_ident);
	} else {
		log_init(DAEMON_NAME);
	}
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
	app_system_info(&state->system);

	/**
	 * Create runner worker threads while signals are still BLOCKED
	 */
	runner_init(state);

	/**
	 * Parse existing log files before starting the REST and web servers.
	 * This reconstructs the history available at startup and is complete
	 * before the daemon accepts network requests.
	 */
	parse_past_log(state);

	/**
	 * Log loaded
	 */
	state->daemon_loading = 0;

	/**
	 * Trigger the initial probe asynchronously through the normal runner queue.
	 * It runs ahead of work subsequently submitted to the queue, but does not
	 * define daemon readiness: the control plane must remain usable with a
	 * degraded array or incomplete disk information. Idle disks can
	 * legitimately have no current telemetry even after a successful probe.
	 */
	if (runner(state, CMD_STARTUP, CMD_PROBE, 0, 0, 0, msg, sizeof(msg), &status) != 0) {
		log_msg(LVL_ERROR, "failed to run the startup probe command");
		/* continue anyway to provide an interface */
	}

	/**
	 * Create scheduler worker threads while signals are still BLOCKED
	 */
	scheduler_init(state);

	if (rest_init(state, state->config.net_enabled, state->config.net_port, state->config.net_acl) != 0) {
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

	os_privileges_drop();

	return 0;
}

void daemon_run(struct snapraid_state* state)
{
	state_lock();

	if (state->daemon_running)
		log_msg(LVL_INFO, "daemon ready");

	while (state->daemon_running) { /* stopped by signals */
		if (state->daemon_reloading) {
			/*
			 * Clear before reloading. A SIGHUP received while reloading sets
			 * the flag again and requests one additional pass.
			 */
			state->daemon_reloading = 0;

			log_msg(LVL_INFO, "reload requested");

			int prev_net_enabled = state->config.net_enabled;
			int reload_rest = 0;
			int ret = config_reload_locked(state);
			if (ret < 0) {
				log_msg(LVL_ERROR, "failed to reload config from %s", state->config.conf);
			} else if (ret > 0) {
				reload_rest = 1;
			}

			int net_enabled = state->config.net_enabled;
			char net_port[CONFIG_MAX];
			char net_acl[CONFIG_MAX];
			char net_web_root[PATH_MAX];

			sncpy(net_port, sizeof(net_port), state->config.net_port);
			sncpy(net_acl, sizeof(net_acl), state->config.net_acl);
			sncpy(net_web_root, sizeof(net_web_root), state->config.net_web_root);

			state_unlock();

			if (state->daemon_running && reload_rest) {
				if (rest_reload(state, prev_net_enabled, net_enabled, net_port, net_acl) != 0) {
					log_msg(LVL_CRITICAL, "failed to reload web server");
					os_exit();
				}
			}

			if (state->daemon_running && web_reload(state, net_web_root) != 0) {
				log_msg(LVL_CRITICAL, "failed to reload web pages from %s", net_web_root);
				os_exit();
			}

			state_lock();

			if (!state->daemon_running)
				break;
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
		log_msg(LVL_INFO, "shutdown requested signal=%s(%d)", os_signal_name(state->daemon_sig), state->daemon_sig);

	state_unlock();

	log_msg(LVL_INFO, "daemon exiting cleanly");
}

void daemon_done(struct snapraid_state* state)
{
	web_done(state);
	rest_done(state, state->config.net_enabled);
	scheduler_done(state);
	runner_done(state);
	config_done(state);

	log_msg(LVL_INFO, "daemon stopped");

	log_done();
}

