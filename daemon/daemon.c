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

#define PID_FILE "/var/run/snapraidd.pid"


static void handle_signal(int sig)
{
	(void)sig;
	state_ptr()->daemon_running = 0;
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"Options:\n"
		"  -f, --foreground   Run in foreground (do not daemonize)\n",
		prog);
}

int main(int argc, char *argv[])
{
	int foreground = 1; // TODO

	state_init();

	static const struct option long_opts[] = {
		{ "foreground", no_argument, 0, 'f' },
		{ 0, 0, 0, 0 }
	};
	
	static const char* options[] = {
		"listening_ports", "8080",
		"num_threads", "50",
		NULL
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "f", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			foreground = 1;
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (!foreground) {
		if (daemonize() < 0)
			exit(EXIT_FAILURE);
	}

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	runner_init(state_ptr());
	rest_init(state_ptr(), options);

	/* load initial info into the state */
	runner(state_ptr(), CMD_PROBE);

	rest_run(state_ptr());

	rest_done(state_ptr());
	runner_done(state_ptr());

	if (!foreground)
		unlink(PID_FILE);

	state_done();

	return 0;
}

/*
curl -X POST http://localhost:8080/api/v1/sync
curl -X POST http://localhost:8080/api/v1/probe
curl -X POST http://localhost:8080/api/v1/up
curl -X POST http://localhost:8080/api/v1/down
curl -X POST http://localhost:8080/api/v1/smart
curl -X GET http://localhost:8080/api/v1/disks
curl -X GET http://localhost:8080/api/v1/progress
*/
