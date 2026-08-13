// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "os/portable.h"

#ifndef __MINGW32__ /* Only for Unix */

#include "app.h"
#include "state.h"
#include "log.h"
#include "support.h"
#include "conf.h"

/****************************************************************************/
/* signal */

static void app_signal_handler_term(int sig)
{
	struct snapraid_state* state = state_ptr();

	state->daemon_sig = sig;
	state->daemon_running = 0;
}

static void app_signal_handler_hup(int sig)
{
	(void)sig;

	if (state_ptr()->daemon_running)
		state_ptr()->daemon_reloading = 1;
}

/****************************************************************************/
/* app */

static const char* snapraid_paths[] = {
#ifdef SNAPRAID_PATH
	/* Path configured at build time (e.g. on NixOS). */
	SNAPRAID_PATH,
#else
	/* Linux & BSD */
	"/usr/bin/snapraid",
	"/usr/local/bin/snapraid",
#ifdef __APPLE__
	/* macOS (Intel & Apple Silicon) */
	"/opt/homebrew/bin/snapraid",
#endif
#endif
	0
};

const char* app_find_engine(const char* sys_engine)
{
	/* check for existence every time in case it's installed at later time */
	if (sys_engine != 0 && sys_engine[0] != 0) {
		if (eaccess(sys_engine, X_OK) == 0)
			return sys_engine;
	} else {
		for (int i = 0; snapraid_paths[i]; ++i) {
			if (eaccess(snapraid_paths[i], X_OK) == 0)
				return snapraid_paths[i];
		}
	}

	return 0;
}

static const char* curl_paths[] = {
#ifdef CURL_PATH
	/* Path configured at build time (e.g. on NixOS). */
	CURL_PATH,
#else
	/* Linux & BSD */
	"/usr/bin/curl",
	"/bin/curl",
	"/usr/local/bin/curl",
#endif
	0
};

const char* app_find_curl(void)
{
	for (int i = 0; curl_paths[i]; ++i) {
		if (eaccess(curl_paths[i], X_OK) == 0)
			return curl_paths[i];
	}

	return 0;
}

static const char* docker_paths[] = {
#ifdef DOCKER_PATH
	/* Path configured at build time. */
	DOCKER_PATH,
#else
	/* Linux & BSD */
	"/usr/bin/docker",
	"/bin/docker",
	"/usr/local/bin/docker",
#endif
	0
};

const char* app_find_docker(void)
{
	for (int i = 0; docker_paths[i]; ++i) {
		if (eaccess(docker_paths[i], X_OK) == 0)
			return docker_paths[i];
	}

	return 0;
}

static const char* poweroff_paths[] = {
	"/sbin/poweroff",
	"/usr/sbin/poweroff",
	"/bin/poweroff",
	"/usr/bin/poweroff",
	0
};

const char* app_find_poweroff(void)
{
	for (int i = 0; poweroff_paths[i]; ++i) {
		if (eaccess(poweroff_paths[i], X_OK) == 0)
			return poweroff_paths[i];
	}

	return 0;
}

void app_default_log(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, "/var/log/snapraid");
}

void app_default_conf(char* dst, size_t dst_size)
{
#ifdef SYSCONFDIR
	/* if it exists, give precedence to sysconfdir, usually /usr/local/etc (note that PACKAGE is snapraid-daemon) */
	sncpy(dst, dst_size, SYSCONFDIR "/" DAEMON_NAME ".conf");
	if (eaccess(dst, F_OK) == 0)
		return;
#endif
	sncpy(dst, dst_size, "/etc/" DAEMON_NAME ".conf");
}

void app_default_data(char* dst, size_t dst_size, const char* root)
{
#ifdef DATADIR
	snprintf(dst, dst_size, DATADIR "/%s", root);
	if (eaccess(dst, F_OK) == 0)
		return;
#endif
	/* otherwise use  /usr/share/snapraidd */
	snprintf(dst, dst_size, "/usr/share/" DAEMON_NAME "/%s", root);
}

/**
 * @brief Parses a system attribute file.
 * @param path The filesystem path (e.g., "/proc/cpuinfo").
 * @param tag The tag to search for (e.g., "model name"). If NULL, matches the first line.
 * @param separator The separator char (e.g., ':').
 * @param position The token position to return. If -1, returns all content after the tag/separator.
 *                 When 'tag' is provided, the tag itself is considered token position 0,
 *                 making position 1 the first whitespace-separated argument after the separator/tag.
 *                 When 'tag' is NULL, position 0 is the first token of the line.
 * @param out The output buffer.
 * @param out_size Size of the output buffer.
 * @return char* Pointer to 'out' on success, NULL on failure.
 */
static char* sysattr(const char* path, const char* tag, char separator, int position, char* out, size_t out_size)
{
	FILE* fp = fopen(path, "re");
	if (!fp)
		return 0;

	char line[1024];
	char* result = 0;

	while (fgets(line, sizeof(line), fp)) {
		int match = 0;
		char* content = line;

		if (!tag) {
			/* if no tag is specified, assume the first row matches */
			match = 1;
		} else {
			size_t tag_len = strlen(tag);

			/* check if the line starts with the specified tag */
			if (strncmp(line, tag, tag_len) == 0) {
				char* p = line + tag_len;

				/* skip optional spaces before the separator */
				while (*p == ' ' || *p == '\t')
					++p;

				if (separator == 0) {
					match = 1;
					content = p;
				} else if (*p == separator) {
					match = 1;
					content = p + 1; /* data starts after the separator */
				}

				/* skip spaces */
				while (*content == ' ' || *content == '\t')
					++content;
			}
		}

		if (match && position < 0) {
			char* tokptr;
			char* token = strtok_r(content, "\n\r", &tokptr);
			if (token) {
				sncpy(out, out_size, token);
				result = out;
			}
			break;
		}

		if (match && position >= 0) {
			/* tokenize the line content to find the argument at 'position' */
			char* tokptr;
			char* token = strtok_r(content, " \t\n\r", &tokptr);
			int i = 0;

			if (tag)
				++i; /* skip the tag already processed */

			while (token != NULL) {
				if (i == position) {
					sncpy(out, out_size, token);
					result = out;
					break;
				}

				token = strtok_r(NULL, " \t\n\r", &tokptr);
				++i;
			}

			/* break because we found our match and (or failed the position check) */
			break;
		}
	}

	fclose(fp);
	return result;
}

void app_system_info(struct snapraid_system* system)
{
	char buf[MSG_MAX];
	struct utsname un;

	memset(system, 0, sizeof(struct snapraid_system));

	if (uname(&un) == 0) {
		sncpy(system->hostname, sizeof(system->hostname), un.nodename);
		sncpy(system->kernel_version, sizeof(system->kernel_version), un.release);
	}

	if (sysattr("/etc/os-release", "PRETTY_NAME", '=', -1, buf, sizeof(buf))) {
		ssize_t len = strlen(buf);
		if (len >= 2 && buf[0] == '"' && buf[len - 1] == '"') {
			buf[len - 1] = 0;
			sncpy(system->os_distribution, sizeof(system->os_distribution), buf + 1);
		} else {
			sncpy(system->os_distribution, sizeof(system->os_distribution), buf);
		}
	}

	if (sysattr("/proc/cpuinfo", "model name", ':', -1, buf, sizeof(buf))) {
		sncpy(system->cpu_model, sizeof(system->cpu_model), buf);
	}

	char board_vendor[KEYWORD_MAX];
	char board_name[KEYWORD_MAX];
	if (sysattr("/sys/class/dmi/id/board_vendor", 0, 0, -1, board_vendor, sizeof(board_vendor)) == 0)
		board_vendor[0] = 0;
	if (sysattr("/sys/class/dmi/id/board_name", 0, 0, -1, board_name, sizeof(board_name)) == 0)
		board_name[0] = 0;
	if (board_vendor[0] && board_name[0]) {
		snprintf(system->motherboard, sizeof(system->motherboard), "%s %s", board_vendor, board_name);
	} else {
		if (board_vendor[0])
			sncpy(system->motherboard, sizeof(system->motherboard), board_vendor);
		if (board_name[0])
			sncpy(system->motherboard, sizeof(system->motherboard), board_name);
	}

	if (eaccess("/sys/devices/system/edac/mc/mc0/size_mb", F_OK) == 0)
		system->is_ecc = 1;
	else
		system->is_ecc = 0;

	app_system_refresh(system);
}

void app_system_refresh(struct snapraid_system* system)
{
	char buf[KEYWORD_MAX];
	struct sysinfo si;

	if (sysinfo(&si) == 0) {
		system->uptime_seconds = (uint64_t)si.uptime;
		system->memory_total_bytes = ((uint64_t)si.totalram * si.mem_unit);
	}

	if (sysattr("/proc/meminfo", "MemAvailable", ':', 1, buf, sizeof(buf))) {
		stru64(&system->memory_free_bytes, buf);
		system->memory_free_bytes *= 1024;
	}
}

void app_instance(const char* instance)
{
	(void)instance;
}

int os_shutdown(void)
{
	const char* poweroff_path = app_find_poweroff();
	if (!poweroff_path) {
		log_task(LVL_ERROR, "poweroff binary not found");
		return -1;
	}

	char* argv[2];
	argv[0] = (char*)poweroff_path;
	argv[1] = 0;

	log_task(LVL_INFO, "spawning poweroff to shut down system");
	os_privileges_acquire();
	pid_t pid = os_spawn(argv, 0, 0, 0);
	os_privileges_release();
	if (pid < 0) {
		log_task(LVL_ERROR, "failed to spawn poweroff, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	int status;
	if (os_wait(pid, &status) == -1) {
		log_task(LVL_ERROR, "failed to wait for poweroff, errno=%s(%d)", strerror(errno), errno);
		return -1;
	}

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0)
			return 0;
		log_task(LVL_ERROR, "poweroff terminated with exit code %d", exit_code);
	} else if (WIFSIGNALED(status)) {
		log_task(LVL_ERROR, "poweroff terminated with signal %d", WTERMSIG(status));
	} else {
		log_task(LVL_ERROR, "poweroff terminated for unknown reason");
	}

	return -1;
}

/****************************************************************************/
/* daemon */

static int os_pidfile(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg, const char* instance)
{
	char name[128];
	if (instance && instance[0]) {
		snprintf(name, sizeof(name), "%s-%s", DAEMON_NAME, instance);
	} else {
		sncpy(name, sizeof(name), DAEMON_NAME);
	}

	/* determine the path if not explicitly provided */
	if (pidfile_arg && pidfile_arg[0]) {
		sncpy(pidfile_path, pidfile_size, pidfile_arg);
	} else {
		if (geteuid() == 0) {
			/* standard for root-level daemons */
			snprintf(pidfile_path, pidfile_size, "/run/%s.pid", name);
		} else {
			/* standard for user-level processes */
			snprintf(pidfile_path, pidfile_size, "/tmp/%s.pid", name);
		}
	}

	/*
	 * Open the file, create if missing, open for reading/writing
	 *
	 * O_NOFOLLOW Prevents attacks about making a dangling link pointing
	 * to another file that will be created with the daemon ownership.
	 */
	int fd = open(pidfile_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (fd == -1) {
		fprintf(stderr, "Error: Could not open PID file %s: %s\n", pidfile_path, strerror(errno));
		return -1;
	}

	/*
	 * Apply a lock to the file (Mandatory for reliability)
	 * This ensures that even if a stale PID file exists,
	 * a second instance cannot start if the first one holds the lock.
	 */
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		if (errno == EACCES || errno == EAGAIN) {
			fprintf(stderr, "%s is already running.\n", name);
		} else {
			fprintf(stderr, "Error locking PID file: %s\n", strerror(errno));
		}
		close(fd);
		return -1;
	}

	/* clear any previous content, but after obtaining the lock */
	if (ftruncate(fd, 0) == -1) {
		fprintf(stderr, "Error truncating PID file: %s\n", strerror(errno));
		unlink(pidfile_path);
		close(fd);
		return -1;
	}

	/* write the current PID to the file */
	char buf[32];
	int buf_len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
	if (write(fd, buf, buf_len) != buf_len) {
		fprintf(stderr, "Error writing to PID file: %s\n", strerror(errno));
		unlink(pidfile_path);
		close(fd);
		return -1;
	}

	return fd;
}

/**
 * Daemonize the current process.
 * @return The PID file descriptor on success, -1 on error
 */
static int os_daemonize(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg, const char* instance)
{
	/* clear the parent and allow the child to call setsid() */
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* create a new session and become the session leader */
	if (setsid() < 0)
		return -1;

	/* ensures the child doesn't die when the session leader exits */
	signal(SIGHUP, SIG_IGN);

	/* ensures the daemon is not a session leader and cannot acquire a controlling terminal again */
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/*
	 * PID File Management
	 * We do this BEFORE closing I/O so we can still report errors to stderr
	 * if another instance is already running.
	 */
	int pidfd = os_pidfile(pidfile_path, pidfile_size, pidfile_arg, instance);
	if (pidfd < 0)
		return -1;

	/* allow daemon total control over its files */
	umask(0);

	/* ensure the daemon doesn't block any filesystem unmounting */
	if (chdir("/") != 0) {
		unlink(pidfile_path);
		close(pidfd);
		return -1;
	}

	/* redirect Standard I/O to /dev/null */
	int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (fd == -1) {
		unlink(pidfile_path);
		close(pidfd);
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0
		|| dup2(fd, STDOUT_FILENO) < 0
		|| dup2(fd, STDERR_FILENO) < 0) {
		close(fd);
		unlink(pidfile_path);
		close(pidfd);
		return -1;
	}

	if (fd > STDERR_FILENO)
		close(fd);

	return pidfd;
}

int main(int argc, char* argv[])
{
	char pidfile[PATH_MAX] = { 0 }; /**< PID file. */

	struct snapraid_state* state = state_init();

	daemon_options(state, argc, argv);

	int pidfd = -1;
	if (!state->log.foreground) {
		pidfd = os_daemonize(pidfile, sizeof(pidfile), state->config.pidfile_arg, state->instance);
		if (pidfd == -1)
			exit(EXIT_FAILURE);
	}

	/*
	 * Install signal handlers
	 */
	os_signal_init(app_signal_handler_term, app_signal_handler_hup);

	/*
	 * Block signals in the main thread
	 */
	os_signal_set(0);

	if (daemon_init(state) != 0)
		exit(EXIT_FAILURE);

	/*
	 * Unblock signals ONLY in main thread
	 * Worker threads keep them blocked forever.
	 */
	os_signal_set(1);

	daemon_run(state);

	daemon_done(state);

	state_done(state);

	if (pidfd != -1) {
		/* first delete then close */
		os_privileges_acquire();
		unlink(pidfile);
		os_privileges_release();
		close(pidfd);
	}

	return 0;
}
#endif

