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
#include "log.h"
#include "daemon.h"
#include "runner.h"

/*
 * Scrubbed environment
 * Only provide the bare essentials.
 */
static char *const envp_scrubbed[] = {
	"PATH="
#ifdef __APPLE__
	"/opt/homebrew/bin:"
#endif
	"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"TERM=dumb",
	"LANG=C",
	"IFS= \t\n",
	NULL
};

/*
 * Enforce a strict 128-byte shebang limit to match the actual Linux kernel behavior
 * and prevent security risks from truncation.
 *
 * The Linux kernel reads exactly 128 bytes (BINPRM_BUF_SIZE internal = 128) to parse
 * the shebang line. Longer lines are silently truncated, which can cause the kernel
 * to execute an unintended or malformed interpreter path.
 *
 * Although the UAPI header exposes 256 and other platforms (macOS, BSD) allow longer
 * lines, we deliberately enforce the conservative 128-byte limit on *all* platforms
 * to eliminate any possibility of a mismatch between our validation and runtime
 * execution on Linux, and to avoid subtle truncation-based attacks.
 *
 * Effective maximum shebang line length: ~126 characters (accounting for "#!", whitespace,
 * interpreter path, optional argument, and newline).
 */
#define SHEBANG_MAX (128 + 2) /* extra space for end-of-line and final 0 */

/**
 * Verifies that the shebang interpreter is in an allowed list of paths.
 * This prevents attacks where a malicious script uses an attacker-controlled interpreter.
 */
static int verify_shebang_interpreter(int fd, const char* script_path)
{
	char shebang[SHEBANG_MAX];
	ssize_t bytes_read;
	char* interpreter;
	char* args;
	struct stat st;

	/* list of allowed interpreter paths */
	const char* allowed_interpreters[] = {
		/* shells - system */
		"/bin/sh",
		"/usr/bin/sh",
		"/bin/bash",
		"/usr/bin/bash",
		"/bin/zsh",
		"/usr/bin/zsh",
		"/bin/dash",
		"/usr/bin/dash",

		/* shells - homebrew (Apple Silicon) */
#ifdef __APPLE__
		"/opt/homebrew/bin/sh",
		"/opt/homebrew/bin/bash",
		"/opt/homebrew/bin/zsh",
		"/opt/homebrew/bin/dash",
#endif

		/* shells - homebrew (Intel macOS legacy) */
		"/usr/local/bin/bash",
		"/usr/local/bin/zsh",
		"/usr/local/bin/dash",

		/* python - system */
		"/usr/bin/python3",
		"/usr/bin/python",

		/* python - Homebrew */
#ifdef __APPLE__
		"/opt/homebrew/bin/python3",
		"/opt/homebrew/bin/python",
#endif
		"/usr/local/bin/python3",
		"/usr/local/bin/python",

		/* perl */
		"/usr/bin/perl",
#ifdef __APPLE__
		"/opt/homebrew/bin/perl",
#endif
		"/usr/local/bin/perl",

		/* ruby */
		"/usr/bin/ruby",
#ifdef __APPLE__
		"/opt/homebrew/bin/ruby",
#endif
		"/usr/local/bin/ruby",

		/* node.js */
		"/usr/bin/node",
#ifdef __APPLE__
		"/opt/homebrew/bin/node",
#endif
		"/usr/local/bin/node",
		0
	};

	bytes_read = pread(fd, shebang, sizeof(shebang) - 1, 0); /* reserve space for the terminating 0 */
	if (bytes_read < 0) {
		log_msg(LVL_ERROR, "failed to read script shebang, path=%s, errno=%s(%d)", script_path, strerror(errno), errno);
		return -1;
	}
	if (bytes_read < 4) {
		log_msg(LVL_ERROR, "script %s too small or missing shebang", script_path);
		return -1;
	}
	shebang[bytes_read] = 0;

	/* check for shebang */
	if (shebang[0] != '#' || shebang[1] != '!') {
		log_msg(LVL_ERROR, "script %s missing shebang (#!)", script_path);
		return -1;
	}

	char* end_of_line = strchr(shebang, '\n');
	if (!end_of_line || end_of_line - shebang > 128) {
		log_msg(LVL_ERROR, "script %s has invalid or overlong shebang (#!), exceeds 126 characters", script_path);
		return -1;
	}
	*end_of_line = 0;

	/* skip "#!" and whitespace */
	interpreter = shebang + 2;
	while (*interpreter && isspace((unsigned char)*interpreter))
		++interpreter;

	if (*interpreter == 0) {
		log_msg(LVL_ERROR, "script %s has empty shebang", script_path);
		return -1;
	}

	/* separate interpreter from arguments */
	args = interpreter;
	while (*args && !isspace((unsigned char)*args))
		++args;
	if (*args)
		*args++ = 0; /* terminate interpreter */

	/* check if interpreter is in allowed list */
	int found = 0;
	for (int i = 0; allowed_interpreters[i] != 0; ++i) {
		if (strcmp(interpreter, allowed_interpreters[i]) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		log_msg(LVL_ERROR, "script %s uses disallowed interpreter %s", script_path, interpreter);
		return -1;
	}

	/* verify interpreter exists and is safe */
	if (stat(interpreter, &st) != 0) {
		log_msg(LVL_ERROR, "interpreter %s does not exist, errno=%s(%d)", interpreter, strerror(errno), errno);
		return -1;
	}

	/* interpreter must be a regular file */
	if (!S_ISREG(st.st_mode)) {
		log_msg(LVL_ERROR, "interpreter %s must be a regular file", interpreter);
		return -1;
	}

	/* interpreter must be owned by root */
	if (st.st_uid != 0) {
		log_msg(LVL_ERROR, "interpreter %s not owned by root", interpreter);
		return -1;
	}

	/* interpreter must not be world-writable */
	if (st.st_mode & S_IWOTH) {
		log_msg(LVL_ERROR, "interpreter %s is world-writable", interpreter);
		return -1;
	}

	/* interpreter must not be group-writable (unless group is root) */
	if ((st.st_mode & S_IWGRP) && st.st_gid != 0) {
		log_msg(LVL_ERROR, "interpreter %s is group-writable by non-root group", interpreter);
		return -1;
	}

	/* interpreter must be executable */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_msg(LVL_ERROR, "interpreter %s is not executable", interpreter);
		return -1;
	}

	/* interpreter must not be setuid / setgid */
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		log_msg(LVL_ERROR, "file %s has setuid/setgid bits set", interpreter);
		return -1;
	}

	/* all checks passed */
	return 0;
}

/**
 * Executes a script directly via its file descriptor.
 */
int runner_script(const char* script_path)
{
	int fd;
	struct stat st;
	pid_t pid;
	char resolved_path[PATH_MAX];
	char dir_path[PATH_MAX];
	int status;
	uid_t daemon_uid, daemon_euid;
	gid_t daemon_gid, daemon_egid;
	struct timespec start_ts, stop_ts;

	daemon_uid = getuid();
	daemon_euid = geteuid();
	daemon_gid = getgid();
	daemon_egid = getegid();

	/* verify script path is absolute */
	if (script_path[0] != '/') {
		log_msg(LVL_ERROR, "script path %s must be absolute", script_path);
		return -1;
	}

	/* resolve the script path to prevent symlink attacks */
	if (!realpath(script_path, resolved_path)) {
		log_msg(LVL_ERROR, "failed to resolve script, path=%s, errno=%s(%d)", script_path, strerror(errno), errno);
		return -1;
	}

	char* last_slash = strrchr(resolved_path, '/');
	if (last_slash && last_slash != resolved_path) {
		size_t dir_len = last_slash - resolved_path;
		memcpy(dir_path, resolved_path, dir_len);
		dir_path[dir_len] = '\0';

		if (stat(dir_path, &st) == 0) {
			/* script directory must be owned by root or the daemon's real user */
			if (st.st_uid != daemon_uid && st.st_uid != daemon_euid && st.st_uid != 0) {
				log_msg(LVL_ERROR, "script directory %s owner must match the daemon owner or be root", dir_path);
				return -1;
			}

			/* script directory must not be group-writable unless group matches daemon */
			if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
				log_msg(LVL_ERROR, "script directory %s must not be group-writable unless group matches daemon owner or root", dir_path);
				return -1;
			}

			/* script directory must not be world-writable */
			if (st.st_mode & S_IWOTH) {
				log_msg(LVL_ERROR, "script directory %s must be not world-writable", dir_path);
				return -1;
			}
		}
	}

	/*
	 * Open the script
	 * O_NOFOLLOW prevents following symlinks to mitigate redirection attacks
	 */
	fd = open(resolved_path, O_RDONLY | O_NOFOLLOW
#if !HAVE_FEXECVE
	| O_CLOEXEC /* with fexecve cannot use O_CLOEXEC (Close on Exec) */
#endif
	);
	if (fd < 0) {
		log_msg(LVL_ERROR, "failed to open script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		return -1;
	}

	/* get the file handle (TOCTOU Protection) */
	if (fstat(fd, &st) == -1) {
		log_msg(LVL_ERROR, "failed to stat script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(fd);
		return -1;
	}

	/* ensure it's a regular file */
	if (!S_ISREG(st.st_mode)) {
		log_msg(LVL_ERROR, "script %s is not a regular file", resolved_path);
		close(fd);
		return -1;
	}

	/* ensure it has execute permissions */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_msg(LVL_ERROR, "script %s is not an executable", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be owned by root or the daemon's real user */
	if (st.st_uid != daemon_uid && st.st_uid != daemon_euid && st.st_uid != 0) {
		log_msg(LVL_ERROR, "script %s owner must match the daemon owner or be root", resolved_path);
		close(fd);
		return -1;
	}

	/* script must not be group-writable unless group matches daemon */
	if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
		log_msg(LVL_ERROR, "script %s must not be group-writable unless group matches daemon owner or root", resolved_path);
		close(fd);
		return -1;
	}

	/* script must not be world-writable */
	if (st.st_mode & S_IWOTH) {
		log_msg(LVL_ERROR, "script %s must be not world-writable", resolved_path);
		close(fd);
		return -1;
	}

	/* script must not be setuid / setgid */
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		log_msg(LVL_ERROR, "file %s has setuid/setgid bits set", resolved_path);
		return -1;
	}

	/* verify the file has not been hardlinked multiple times */
	if (st.st_nlink > 1) {
		log_msg(LVL_ERROR, "script %s has multiple hard links", resolved_path);
		close(fd);
		return -1;
	}

	if (verify_shebang_interpreter(fd, resolved_path) != 0) {
		close(fd);
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	pid = fork();
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to fork script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(fd);
		return -1;
	}

	if (pid == 0) {
		/* child process */

		int null_fd = open("/dev/null", O_RDWR);
		if (null_fd != -1) {
			/* redirect stdin/out(err to /dev/null */
			dup2(null_fd, STDIN_FILENO);
			dup2(null_fd, STDOUT_FILENO);
			dup2(null_fd, STDERR_FILENO);
			if (null_fd > 2)
				close(null_fd);
		}

#if defined(CLOSE_RANGE_CLOEXEC) && defined(HAVE_CLOSE_RANGE)
		/*
		 * Set all fd to be closed on exec as extra safety measure
		 *
		 * fallback: if it fails, we assume to be still safe, as all fds and
		 * sockets should be already created with CLOEXEC.
		 */
		close_range(3, fd - 1, CLOSE_RANGE_CLOEXEC);
		close_range(fd + 1, ~0U, CLOSE_RANGE_CLOEXEC);
#endif

		/* restore and unblock signals */
		signal_restore_after_fork();

		/* child will receive SIGALRM in 300 seconds as a timeout */
		alarm(300);

		/*
		 * Direct Execution via File Descriptor
		 * The kernel uses the shebang in the FD to find the interpreter.
		 */
		char* const argv[] = { (char *)script_path, 0 };

#if HAVE_FEXECVE
		fexecve(fd, argv, envp_scrubbed);
#else
		/* fallback: unfortunately must use the path */
		execve(resolved_path, argv, envp_scrubbed);
#endif
		/* if fexecve returns, it failed (e.g., no shebang or /proc not mounted) */

		log_msg(LVL_ERROR, "failed fexecve for script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		_exit(EXIT_FAILURE);
	}

	/* parent process */
	close(fd);

	if (waitpid(pid, &status, 0) == -1) {
		log_msg(LVL_ERROR, "failed waitpid for script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &stop_ts);
	long long execution_time = (stop_ts.tv_sec - start_ts.tv_sec);
	if (execution_time > 30)
		log_msg(LVL_WARNING, "script %s took %lld seconds", resolved_path, execution_time);

	if (WIFEXITED(status)) {
		/* child's exit(code) or return from main */
		log_msg(LVL_INFO, "script %s terminated in %lld seconds with code %d", resolved_path, execution_time, WEXITSTATUS(status));
		return WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		log_msg(LVL_INFO, "script %s terminated in %lld seconds with signal %s(%d)", resolved_path, execution_time, log_signame(WTERMSIG(status)), WTERMSIG(status));
		return 128 + WTERMSIG(status);
	} else {
		/* it should never happen */
		log_msg(LVL_INFO, "script %s terminated in %lld seconds for unknown reason, status=%d", resolved_path, execution_time, status);
		return -1;
	}
}

static int pipe_cloexec(int pipefd[2])
{
#ifdef HAVE_PIPE2
	return pipe2(pipefd, O_CLOEXEC);
#else
	if (pipe(pipefd) < 0)
		return -1;

	for (int i = 0; i < 2; i++) {
		int flags = fcntl(pipefd[i], F_GETFD);
		if (flags < 0)
			goto bail;

		if (fcntl(pipefd[i], F_SETFD, flags | FD_CLOEXEC) < 0)
			goto bail;
	}

	return 0;

bail:
	close(pipefd[0]);
	close(pipefd[1]);
	return -1;
#endif
}

pid_t runner_spawn(char** argv, int* stderr_fd)
{
	int err_pipe[2];
	int devnull;
	pid_t pid;

	if (pipe_cloexec(err_pipe) < 0)
		return -1;

	devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (devnull < 0) {
		close(err_pipe[0]);
		close(err_pipe[1]);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(err_pipe[0]);
		close(err_pipe[1]);
		close(devnull);
		return -1;
	}

	if (pid == 0) {
		/* child */

		/* stdin -> /dev/null */
		/* stdout -> /dev/null */
		/* stderr -> pipe */
		if (dup2(devnull, STDIN_FILENO) < 0
			|| dup2(devnull, STDOUT_FILENO) < 0
			|| dup2(err_pipe[1], STDERR_FILENO) < 0)
			_exit(127);

		close(err_pipe[0]);
		close(err_pipe[1]);
		close(devnull);

		/* restore and unblock signals */
		signal_restore_after_fork();

		execve(argv[0], (char* const*)argv, envp_scrubbed);
		_exit(127);
	}

	/* parent */
	close(err_pipe[1]);
	close(devnull);

	*stderr_fd = err_pipe[0];
	return pid;
}

/**
 * Check if the passed name is a parity
 * Split parities are NOT recognized.
 */
int is_parity(const char* s)
{
	if (isdigit((unsigned char)s[0]) && s[1] == '-')
		s += 2;

	return strcmp(s, "parity") == 0;
}

/**
 * Check if the passed name is a parity, and extract the split index
 * The name is truncated to remove the split index.
 */
int is_split_parity(char* s, int* index)
{
	if (isdigit((unsigned char)s[0]) && s[1] == '-')
		s += 2;

	if (strncmp(s, "parity", 6) != 0)
		return 0;

	s += 6;

	if (s[0] == 0) {
		*index = 0;
		return 1;
	}

	if (s[0] == '/') {
		*s = 0;
		if (strint(index, s + 1) == 0)
			return 1;
	}

	return 0;
}

struct snapraid_data* find_data(tommy_list* list, const char* name)
{
	struct snapraid_data* data;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		data = i->data;
		if (strcmp(name, data->name) == 0)
			return data;
		i = i->next;
	}

	data = calloc_nofail(1, sizeof(struct snapraid_data));
	data->content_size = SMART_UNASSIGNED;
	data->content_free = SMART_UNASSIGNED;
	sncpy(data->name, sizeof(data->name), name);
	tommy_list_insert_tail(list, &data->node, data);

	return data;
}

struct snapraid_parity* find_parity(tommy_list* list, const char* name)
{
	struct snapraid_parity* parity;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		parity = i->data;
		if (strcmp(name, parity->name) == 0)
			return parity;
		i = i->next;
	}

	parity = calloc_nofail(1, sizeof(struct snapraid_parity));
	parity->content_size = SMART_UNASSIGNED;
	parity->content_free = SMART_UNASSIGNED;
	sncpy(parity->name, sizeof(parity->name), name);
	tommy_list_insert_tail(list, &parity->node, parity);

	return parity;
}

struct snapraid_split* find_split(tommy_list* list, int index)
{
	struct snapraid_split* split;
	tommy_node* i;

	i = tommy_list_head(list);
	while (i) {
		split = i->data;
		if (index == split->index)
			return split;
		i = i->next;
	}

	split = calloc_nofail(1, sizeof(struct snapraid_split));
	split->index = index;
	tommy_list_insert_tail(list, &split->node, split);

	return split;
}

struct snapraid_device* find_device_from_file(tommy_list* list, const char* file)
{
	struct snapraid_device* device;
	tommy_node* i;
	int j;

	i = tommy_list_head(list);
	while (i) {
		device = i->data;
		if (strcmp(file, device->file) == 0)
			return device;
		i = i->next;
	}

	device = calloc_nofail(1, sizeof(struct snapraid_device));
	for (j = 0; j < SMART_COUNT; ++j)
		device->smart[j] = SMART_UNASSIGNED;
	device->error = SMART_UNASSIGNED;
	device->size = SMART_UNASSIGNED;
	device->rotational = SMART_UNASSIGNED;
	device->error = SMART_UNASSIGNED;
	device->flags = SMART_UNASSIGNED;
	device->power = SMART_UNASSIGNED;
	device->health = SMART_UNASSIGNED;
	sncpy(device->file, sizeof(device->file), file);
	tommy_list_insert_tail(list, &device->node, device);

	return device;
}

struct snapraid_device* find_device(struct snapraid_state* state, char* name, const char* file)
{
	int index;

	if (is_split_parity(name, &index)) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, name);
		struct snapraid_split* split = find_split(&parity->split_list, index);
		return find_device_from_file(&split->device_list, file);
	} else {
		struct snapraid_data* data = find_data(&state->data_list, name);
		return find_device_from_file(&data->device_list, file);
	}
}

void process_stat(struct snapraid_state* state, char** map, size_t mac)
{
	uint64_t access_count;

	if (mac < 3)
		return;

	if (stru64(&access_count, map[2]) != 0)
		return;

	if (is_parity(map[1])) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (parity->access_count != access_count) {
			parity->access_count = access_count;
			parity->access_count_initial_time = state->global.unixtime;
		}
		parity->access_count_latest_time = state->global.unixtime;
	} else {
		struct snapraid_data* data = find_data(&state->data_list, map[1]);
		/* if the value is the same, doesn't update the first time */
		if (data->access_count != access_count) {
			data->access_count = access_count;
			data->access_count_initial_time = state->global.unixtime;
		}
		data->access_count_latest_time = state->global.unixtime;
	}
}

void process_data(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_data* data;

	if (mac < 4)
		return;

	data = find_data(&state->data_list, map[1]);

	sncpy(data->dir, sizeof(data->dir), map[2]);
	sncpy(data->uuid, sizeof(data->uuid), map[3]);
}

void process_content_data(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_data* data;

	if (mac < 3)
		return;

	data = find_data(&state->data_list, map[1]);

	sncpy(data->content_uuid, sizeof(data->content_uuid), map[2]);
}

void process_parity(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_parity* parity;
	struct snapraid_split* split;
	int index;

	if (mac < 3)
		return;
	if (!is_split_parity(map[0], &index))
		return;

	parity = find_parity(&state->parity_list, map[0]);
	split = find_split(&parity->split_list, index);

	sncpy(split->path, sizeof(split->path), map[1]);
	sncpy(split->uuid, sizeof(split->uuid), map[2]);
}

void process_content_parity(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_parity* parity;
	struct snapraid_split* split;
	int index;

	if (mac < 4)
		return;
	if (!is_split_parity(map[0], &index))
		return;

	parity = find_parity(&state->parity_list, map[0]);
	split = find_split(&parity->split_list, index);

	sncpy(split->content_uuid, sizeof(split->content_uuid), map[1]);
	sncpy(split->content_path, sizeof(split->content_path), map[2]);
	stru64(&split->content_size, map[3]);
}

void process_content_allocation(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	if (is_parity(map[0])) {
		struct snapraid_parity* parity = find_parity(&state->parity_list, map[0]);
		stru64(&parity->content_size, map[1]);
		stru64(&parity->content_free, map[2]);
	} else {
		struct snapraid_data* data = find_data(&state->data_list, map[0]);
		stru64(&data->content_size, map[1]);
		stru64(&data->content_free, map[2]);
	}
}

void process_attr(struct snapraid_state* state, char** map, size_t mac)
{
	const char* tag;
	const char* val;
	struct snapraid_device* device;

	if (mac < 5)
		return;
	if (map[2][0] == 0) /* ignore if no disk name is provided */
		return;

	device = find_device(state, map[2], map[1]);

	tag = map[3];
	val = map[4];

	if (strcmp(tag, "serial") == 0)
		sncpy(device->serial, sizeof(device->serial), val);
	else if (strcmp(tag, "model") == 0)
		sncpy(device->model, sizeof(device->model), val);
	else if (strcmp(tag, "family") == 0)
		sncpy(device->family, sizeof(device->family), val);
	else if (strcmp(tag, "size") == 0)
		stru64(&device->size, val);
	else if (strcmp(tag, "rotationrate") == 0)
		stru64(&device->rotational, val);
//	else if (strcmp(tag, "afr") == 0)
	//device->info[ROTATION_RATE] = si64(val);
	else if (strcmp(tag, "error") == 0)
		stru64(&device->error, val);
	else if (strcmp(tag, "power") == 0) {
		device->power = SMART_UNASSIGNED;
		if (strcmp(val, "standby") == 0 || strcmp(val, "down") == 0)
			device->power = POWER_STANDBY;
		else if (strcmp(val, "active") == 0 || strcmp(val, "up") == 0)
			device->power = POWER_ACTIVE;
	} else if (strcmp(tag, "flags") == 0) {
		device->health = SMART_UNASSIGNED;
		if (stru64(&device->flags, val) == 0) {
			if (device->flags & (SMARTCTL_FLAG_FAIL | SMARTCTL_FLAG_PREFAIL))
				device->health = HEALTH_FAILING;
			else
				device->health = HEALTH_PASSED;
		}
	} else {
		int index;
		if (strint(&index, tag) == 0) {
			if (index >= 0 && index < 256)
				stru64(&device->smart[index], val);
		}
	}
}

void process_run(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 2)
		return;

	if (strcmp(map[1], "begin") == 0) {
		if (mac < 5)
			return;

		task->state = PROCESS_STATE_BEGIN;
		struint(&task->block_begin, map[2]);
		struint(&task->block_end, map[3]);
		struint(&task->block_count, map[4]);
	} else if (strcmp(map[1], "pos") == 0) {
		if (mac < 10)
			return;

		task->state = PROCESS_STATE_POS;
		struint(&task->block_idx, map[2]);
		struint(&task->block_done, map[3]);
		stru64(&task->size_done, map[4]);
		struint(&task->progress, map[5]);
		struint(&task->eta_seconds, map[6]);
		struint(&task->speed_mbs, map[7]);
		struint(&task->cpu_usage, map[8]);
		struint(&task->elapsed_seconds, map[9]);
	} else if (strcmp(map[1], "end") == 0) {
		/* if interrupting, ignore the end, and it's reported anyway */
		if (task->state != PROCESS_STATE_SIGINT) {
			task->state = PROCESS_STATE_END;
			task->progress = 100;
			task->eta_seconds = 0;
			task->speed_mbs = 0;
			task->cpu_usage = 0;
		}
	}
}

void process_sigint(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 2)
		return;

	task->state = PROCESS_STATE_SIGINT;
	struint(&task->block_idx, map[1]);
}

void process_msg(struct snapraid_state* state, char** map, size_t mac)
{
	struct snapraid_task* task = state->runner.latest;

	if (!task)
		return;
	if (mac < 3)
		return;

	if (strcmp(map[1], "progress") == 0 || strcmp(map[1], "status") == 0) {
		struct snapraid_message* message = malloc_nofail(sizeof(struct snapraid_message));
		const char* msg = map[2];

		/* skip initial spaces */
		while (*msg != 0 && isspace((unsigned char)*msg))
			++msg;

		sncpy(message->str, sizeof(message->str), msg);
		tommy_list_insert_tail(&task->message_list, &message->node, message);
	}
}

void process_conf(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 3)
		return;

	if (strcmp(map[1], "file") == 0)
		sncpy(state->global.conf, sizeof(state->global.conf), map[2]);
}

void process_content(struct snapraid_state* state, char** map, size_t mac)
{
	if (mac < 2)
		return;

	sncpy(state->global.content, sizeof(state->global.content), map[1]);
}

void process_version(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int major;
	int minor;

	if (mac < 2)
		return;

	s = map[1];

	/* parse major */
	if (!isdigit((unsigned char)*s))
		return;

	major = strtol(s, &e, 10);
	if (e == s || *e != '.')
		return;

	s = e + 1;

	/* parse minor */
	if (!isdigit((unsigned char)*s))
		return;

	minor = strtol(s, &e, 10);

	/* anything after minor is ignored */
	state->global.version_major = major;
	state->global.version_minor = minor;
}

void process_blocksize(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int blocksize;

	if (mac < 2)
		return;

	s = map[1];

	if (!isdigit((unsigned char)*s))
		return;

	blocksize = strtol(s, &e, 10);
	if (e == s || *e != 0)
		return;

	state->global.blocksize = blocksize;
}

void process_unixtime(struct snapraid_state* state, char** map, size_t mac)
{
	const char* s;
	char* e;
	int64_t unixtime;

	if (mac < 2)
		return;

	s = map[1];

	if (!isdigit((unsigned char)*s))
		return;

	unixtime = strtoll(s, &e, 10);
	if (e == s || *e != 0)
		return;

	state->global.unixtime = unixtime;
}

void process_line(struct snapraid_state* state, char** map, size_t mac)
{
	const char* cmd;

	if (mac == 0)
		return;

	cmd = map[0];

	if (strcmp(cmd, "data") == 0) {
		process_data(state, map, mac);
	} else if (is_parity(cmd)) {
		process_parity(state, map, mac);
//	} else if (strcmp(cmd, "device") == 0) {
		//process_device(state, map, mac);
	} else if (strcmp(cmd, "attr") == 0) {
		process_attr(state, map, mac);
	} else if (strcmp(cmd, "run") == 0) {
		process_run(state, map, mac);
	} else if (strcmp(cmd, "sigint") == 0) {
		process_sigint(state, map, mac);
	} else if (strcmp(cmd, "msg") == 0) {
		process_msg(state, map, mac);
	} else if (strcmp(cmd, "stat") == 0) {
		process_stat(state, map, mac);
	} else if (strcmp(cmd, "conf") == 0) {
		process_conf(state, map, mac);
	} else if (strcmp(cmd, "content") == 0) {
		process_content(state, map, mac);
	} else if (strcmp(cmd, "version") == 0) {
		process_version(state, map, mac);
	} else if (strcmp(cmd, "blocksize") == 0) {
		process_blocksize(state, map, mac);
	} else if (strcmp(cmd, "unixtime") == 0) {
		process_unixtime(state, map, mac);
	} else if (strcmp(cmd, "content_disk") == 0) {
		process_content_data(state, map, mac);
	} else if (strcmp(cmd, "content_parity") == 0) {
		process_content_parity(state, map, mac);
	} else if (strcmp(cmd, "content_allocation") == 0) {
		process_content_allocation(state, map, mac);
	}
}

#define RUN_INPUT_MAX 4096
#define RUN_FIELD_MAX 64

void process_stderr(struct snapraid_state* state, int f, const char* log_path)
{
	char buf[RUN_INPUT_MAX];
	char line[RUN_INPUT_MAX];
	char* map[RUN_FIELD_MAX];
	size_t len = 0;
	size_t mac = 0;
	int escape = 0;
	FILE* log_f = 0;

	if (log_path[0] != 0) {
		log_f = fopen(log_path, "wte");
		if (log_f == 0) {
			log_msg(LVL_WARNING, "failed to create log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}

	map[mac++] = line;

	while (1) {
		ssize_t n = read(f, buf, sizeof(buf));
		if (n > 0) {
			ssize_t i;

			if (log_f) {
				if (fwrite(buf, n, 1, log_f) != 1) {
					log_msg(LVL_WARNING, "failed to write log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
				}
			}

			for (i = 0; i < n; i++) {
				char c = buf[i];

				if (escape) {
					if (len + 1 < RUN_INPUT_MAX) { /* ignore if too long */
						switch (c) {
						case '\\' : line[len++] = '\\'; break;
						case 'n' :  line[len++] = '\n'; break;
						case 'd' : line[len++] = ':'; break;
						default : /* ignore if unknown */
						}
					}
					escape = 0;
					continue;
				}

				if (c == '\\') {
					escape = 1;
					continue;
				}

				if (c == ':') {
					if (mac + 1 < RUN_FIELD_MAX) {
						line[len++] = '\0';
						map[mac++] = &line[len];
						continue;
					}
					/* do not split if too many fields */
				}

				if (c == '\n') {
					line[len] = '\0';
					map[mac] = 0;

					process_line(state, map, mac);

					len = 0;
					mac = 0;
					escape = 0;
					map[mac++] = line;
					continue;
				}

				if (len + 1 < RUN_INPUT_MAX) /* ignore if too long */
					line[len++] = c;
			}
		} else if (n == 0) {
			/* EOF, discard partial read not ending with \n */
			break;
		} else { /* n < 0 */
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}
	}


	if (log_f) {
		if (fclose(log_f) != 0) {
			log_msg(LVL_WARNING, "failed to close log file %s, errno=%s(%d)", log_path, strerror(errno), errno);
		}
	}
}

const char* runner_cmd(int cmd)
{
	switch (cmd) {
	case CMD_NONE : return "none";
	case CMD_PROBE : return "probe";
	case CMD_UP : return "up";
	case CMD_DOWN : return "down";
	case CMD_SMART : return "smart";
	case CMD_STATUS : return "status";
	case CMD_LIST : return "list";
	case CMD_DIFF : return "diff";
	case CMD_SYNC : return "sync";
	case CMD_SCRUB : return "scrub";
	case CMD_FIX : return "fix";
	case CMD_CHECK : return "check";
	}

	return 0;
}

static int runner_need_script(int cmd)
{
	switch (cmd) {
	case CMD_SYNC : return 1;
	case CMD_SCRUB : return 1;
	case CMD_FIX : return 1;
	}

	return 0;
}

struct snapraid_task* task_alloc(void)
{
	struct snapraid_task* task = calloc_nofail(1, sizeof(struct snapraid_task));
	tommy_list_init(&task->message_list);
	return task;
}

void task_free(struct snapraid_task* task)
{
	if (!task)
		return;
	for(int i = 0;i < task->argc; ++i)
		free(task->argv[i]);
	free(task->argv);
	tommy_list_foreach(&task->message_list, free);
	free(task);
}

void task_cancel(void* void_task)
{
	struct snapraid_task* task = void_task;
	log_msg_lock(LVL_WARNING, "cancelling task %d %s", task->number, runner_cmd(task->cmd));
	task_free(task);
}

void task_list_cancel(tommy_list* list)
{
	tommy_list_foreach(list, task_cancel);
	tommy_list_init(list);
}

static void runner_go(struct snapraid_state* state)
{
	char pre_run_script[CONFIG_MAX];
	char post_run_script[CONFIG_MAX];
	int f;
	pid_t pid;
	int cmd;
	int status;
	pid_t ret;
	char** argv;

	sncpy(pre_run_script, sizeof(pre_run_script), state->config.pre_run_script);
	sncpy(post_run_script, sizeof(post_run_script), state->config.post_run_script);
	cmd = state->runner.latest->cmd;
	argv = state->runner.latest->argv;

	state_unlock();

	f = -1;

	if (pre_run_script[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "run %s", pre_run_script);
		script_ret = runner_script(pre_run_script);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "end %s with failed run", pre_run_script);
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "end %s", pre_run_script);
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "end %s with return code %d", pre_run_script, script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "end %s with signal %s(%d)", pre_run_script, log_signame(script_ret - 128), script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

	pid = runner_spawn(argv, &f);
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to start runner %s for a failed spawn, errno=%s(%d)", runner_cmd(cmd), strerror(errno), errno);
		ret = -1;
		/* continue to run the post_run_script */
	} else {
		char log_path[PATH_MAX];

		log_path[0] = 0;

		if (state->config.log_directory[0] != 0) {
			time_t now = time(0);
			struct tm* local = localtime(&now);
			if (local) {
				snprintf(log_path, sizeof(log_path), "%s/%04d%02d%02d-%02d%02d%02d-%s.log", state->config.log_directory,
					local->tm_year + 1900,
					local->tm_mon + 1,
					local->tm_mday,
					local->tm_hour,
					local->tm_min,
					local->tm_sec,
					runner_cmd(cmd)
				);
			} else {
				snprintf(log_path, sizeof(log_path), "%s/%s.log", state->config.log_directory, runner_cmd(cmd));
			}
		}

		if (log_path[0])
			log_msg(LVL_INFO, "run %s (pid %" PRIu64 ") with log %s", runner_cmd(cmd), (uint64_t)pid, log_path);
		else
			log_msg(LVL_INFO, "run %s (pid %" PRIu64 ")", runner_cmd(cmd), (uint64_t)pid);

		process_stderr(state, f, log_path);

		/* wait for the child process to terminate */
		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			log_msg(LVL_INFO, "end %s (pid %" PRIu64 ") with failed run", runner_cmd(cmd), (uint64_t)pid);
		} else {
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0)
					log_msg(LVL_INFO, "end %s (pid %" PRIu64 ")", runner_cmd(cmd), (uint64_t)pid);
				else
					log_msg(LVL_INFO, "end %s (pid %" PRIu64 ") with exit code %d", runner_cmd(cmd), (uint64_t)pid, WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				log_msg(LVL_INFO, "end %s (pid %" PRIu64 ") with signal %s(%d)", runner_cmd(cmd), (uint64_t)pid, log_signame(WTERMSIG(status)), WTERMSIG(status));
			}
		}
	}

	if (post_run_script[0] != 0 && runner_need_script(cmd)) {
		int script_ret;
		log_msg(LVL_INFO, "run %s", post_run_script);
		script_ret = runner_script(post_run_script);
		if (script_ret < 0) {
			log_msg(LVL_INFO, "end %s with failed run", post_run_script);
			ret = -1;
			goto bail;
		} else if (script_ret == 0) {
			log_msg(LVL_INFO, "end %s", post_run_script);
		} else if (script_ret < 128) {
			log_msg(LVL_INFO, "end %s with exit code %d", post_run_script, script_ret);
			ret = -1;
			goto bail;
		} else {
			log_msg(LVL_INFO, "end %s with signal %s(%d)", post_run_script, log_signame(script_ret - 128), script_ret - 128);
			ret = -1;
			goto bail;
		}
	}

bail:
	if (f != -1)
		close(f);

	state_lock();

	struct snapraid_task* task = state->runner.latest;
	task->running = 0;
	if (ret == -1) {
		task->exit_code = -1;
	} else {
		if (WIFEXITED(status)) {
			/* child's exit(code) or return from main */
			task->exit_code = WEXITSTATUS(status);

			/* cancel all queued tasks on failure */
			if (task->exit_code != 0)
				task_list_cancel(&state->runner.task_list);
		} else if (WIFSIGNALED(status)) {
			/* child died from a signal */
			task->exit_sig = WTERMSIG(status);
			task->state = PROCESS_STATE_SIGINT;

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.task_list);
		} else {
			/* it should never happen */
			task->exit_code = -1;

			/* cancel all queued tasks */
			task_list_cancel(&state->runner.task_list);
		}
	}
}

static void* runner_thread(void* arg)
{
	struct snapraid_state* state = arg;

	state_lock();

	while (1) {
		while (state->daemon_running /* daemon is still running */
			&& (state->runner.latest == 0 || !state->runner.latest->running) /* no task is running */
			&& !tommy_list_empty(&state->runner.task_list)) /* there is something to run */
		{
			/* cleanup the latest task */
			task_free(state->runner.latest);

			/* setup a new task to run */
			state->runner.latest = tommy_list_remove_existing(&state->runner.task_list, tommy_list_head(&state->runner.task_list));
			state->runner.latest->running = 1;

			runner_go(state);
		}

		if (!state->daemon_running)
			break;

		thread_cond_wait(&state->runner.cond, &state->lock);
	}

	state_unlock();

	return 0;
}

void runner_init(struct snapraid_state* state)
{
	thread_cond_init(&state->runner.cond);

	/* start the runner thread */
	thread_create(&state->runner.thread_id, runner_thread, state);
}

void runner_done(struct snapraid_state* state)
{
	void* retval;

	/* signal the condition to allow the thread to stop */
	thread_cond_signal(&state->runner.cond);

	/* wait for the thread termination */
	thread_join(state->runner.thread_id, &retval);

	thread_cond_destroy(&state->runner.cond);
}

static const char* snapraid_paths[] = {
	/* Linux & BSD */
	"/usr/bin/snapraid",
	"/usr/local/bin/snapraid",
	/* macOS (Intel & Apple Silicon) */
	"/opt/homebrew/bin/snapraid",
	0
};

const char* find_snapraid(void)
{
	for (int i = 0; snapraid_paths[i]; ++i) {
		if (access(snapraid_paths[i], X_OK) == 0)
			return snapraid_paths[i];
	}

	return 0;
}

int runner(struct snapraid_state* state, int cmd, int cmd_argc, char** cmd_argv, char* msg, size_t msg_size)
{
	struct snapraid_task* task;
	const char* snapraid;
	int i;

	snapraid = find_snapraid();
	if (!snapraid) {
		log_msg(LVL_ERROR, "snapraid executable not found");
		sncpy(msg, msg_size, "SnapRAID executable not found");
		return 503;
	}

	task = task_alloc();

	task->cmd = cmd;
	task->argc = 0;
	task->argv = calloc_nofail(5 + cmd_argc + 1, sizeof(char*));
	task->argv[task->argc++] = strdup_nofail(snapraid);
	task->argv[task->argc++] = strdup_nofail(runner_cmd(cmd));
	task->argv[task->argc++] = strdup_nofail("--gui");
	task->argv[task->argc++] = strdup_nofail("--log");
	task->argv[task->argc++] = strdup_nofail(">&2");
	for (i = 0; i < cmd_argc; ++i)
		task->argv[task->argc++] = strdup_nofail(cmd_argv[i]);
	task->argv[task->argc++] = 0;

	state_lock();

	if (!state->daemon_running) {
		state_unlock();
		task_free(task);
		log_msg(LVL_ERROR, "failed to start runner %s for daemon terminating", runner_cmd(cmd));
		sncpy(msg, msg_size, "Daemon is terminating");
		return 409;
	}

	/* insert the task in the queue */
	task->number = ++state->runner.number_allocator;
	tommy_list_insert_tail(&state->runner.task_list, &task->node, task);

	/* signal the runner thread that there is a task to execute */
	thread_cond_signal(&state->runner.cond);

	state_unlock();

	return 202;
}

int runner_spindown_inactive(struct snapraid_state* state, char* msg, size_t msg_size)
{
	char* argv[RUNNER_ARG_MAX];
	int argc;
	int ret;

	argc = 0;

	state_lock();

	int spindown_idle_minutes = state->config.spindown_idle_minutes;

	for (tommy_node* i = tommy_list_head(&state->data_list); i; i = i->next) {
		struct snapraid_data* data = i->data;
		int active = 0;

		for (tommy_node* k = tommy_list_head(&data->device_list); k; k = k->next) {
			struct snapraid_device* device = k->data;
			if (device->power != SMART_UNASSIGNED && device->power != POWER_STANDBY)
				active = 1;
		}

		if (argc + 2 < RUNNER_ARG_MAX
			&& active
			&& (data->access_count_latest_time - data->access_count_initial_time) / 60 >= spindown_idle_minutes) {
			argv[argc++] = strdup_nofail("-d");
			argv[argc++] = strdup_nofail(data->name);
		}
	}

	for (tommy_node* i = tommy_list_head(&state->parity_list); i; i = i->next) {
		struct snapraid_parity* parity = i->data;
		int active = 0;

		for (tommy_node* j = tommy_list_head(&parity->split_list); j; j = j->next) {
			struct snapraid_split* split = j->data;

			for (tommy_node* k = tommy_list_head(&split->device_list); k; k = k->next) {
				struct snapraid_device* device = k->data;
				if (device->power != SMART_UNASSIGNED && device->power != POWER_STANDBY)
					active = 1;
			}
		}

		if (argc + 2 < RUNNER_ARG_MAX
			&& active
			&& (parity->access_count_latest_time - parity->access_count_initial_time) / 60 >= spindown_idle_minutes) {
			argv[argc++] = strdup_nofail("-d");
			argv[argc++] = strdup_nofail(parity->name);
		}
	}

	state_unlock();

	if (argc == 0) {
		sncpy(msg, msg_size, "Nothing to do");
		ret = 200;
	} else {
		ret = runner(state, CMD_DOWN, argc, argv, msg, msg_size);
	}

	for (int i = 0; i < argc; ++i)
		free(argv[i]);

	return ret;
}

/**
 * Deletes all **regular files** in the specified directory (non-recursively)
 * that have a modification time older than N days.
 *
 * Note:
 * - This function does **not** recurse into subdirectories.
 * - It skips "." and ".." entries.
 * - It only deletes regular files (not directories, symlinks, etc.).
 * - Uses modification time (st_mtime) for comparison.
 * - Errors are printed to stderr for visibility.
 */
static int delete_old_files(const char* dir_path, int days)
{
	DIR* dir;
	struct dirent* entry;
	struct stat statbuf;
	time_t now;
	int64_t age_seconds;

	dir = opendir(dir_path);
	if (dir == NULL) {
		log_msg(LVL_ERROR, "failed to open directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	time(&now);

	age_seconds = days * (int64_t)24 * 60 * 60;

	while ((entry = readdir(dir)) != NULL) {
		char full_path[PATH_MAX];

		/* skip . and .. */
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		/* construct full path */
		snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

		if (stat(full_path, &statbuf) == -1) {
			log_msg(LVL_ERROR, "failed to stat file %s, errno=%s(%d)", full_path, strerror(errno), errno);
			continue; /* skip this entry on error */
		}

		/* delete only regular files */
		if (!S_ISREG(statbuf.st_mode))
			continue;

		/* delete only files that are old enough */
		if (now - statbuf.st_mtime < age_seconds)
			continue;

		if (unlink(full_path) == -1) {
			log_msg(LVL_ERROR, "failed to delete file %s, errno=%s(%d)", full_path, strerror(errno), errno);
			/* continue trying to delete others */
		}
	}

	if (closedir(dir) == -1) {
		log_msg(LVL_ERROR, "failed to close directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	return 0;
}

int runner_delete_old_log(struct snapraid_state* state, char* msg, size_t msg_size)
{
	if (delete_old_files(state->config.log_directory, state->config.log_retention_days) != 0) {
		sncpy(msg, msg_size, "Failed deleting old log files");
		return 503;
	}

	return 200;
}
