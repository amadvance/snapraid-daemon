// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#ifndef __MINGW32__ /* Only for Unix */

#include "state.h"
#include "log.h"
#include "support.h"
#include "daemon.h"
#include "conf.h"

/****************************************************************************/
/* access */

#if !HAVE_EACCESS
/**
 * Check effective user's permissions for a file.
 * Conceptually identical to access(), but uses the effective UID/GID.
 */
int eaccess(const char* pathname, int mode)
{
	return faccessat(AT_FDCWD, pathname, mode, AT_EACCESS);
}
#endif

/****************************************************************************/
/* signal */

static void signal_handler_term(int sig)
{
	state_ptr()->daemon_running = DAEMON_QUIT;
	state_ptr()->daemon_sig = sig;
}

static void signal_handler_hup(int sig)
{
	(void)sig;
	state_ptr()->daemon_running = DAEMON_RELOAD;
}

/**
 * Restore signal handlers after fork in child process.
 * This resets signals to default handling for the daemon.
 */
static void os_signal_restore_after_fork(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGHUP, &sa, 0);
	/* do not restore SIGPIPE */

	/* ensure signals are unblocked */
	sigset_t mask;
	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL); /* cannot use pthread_sigmask after fork */
}

/**
 * Enable or disable signal handling.
 * @param enable 1 to enable signals, 0 to disable
 */
static void os_signal_set(int enable)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);

	pthread_sigmask(enable ? SIG_UNBLOCK : SIG_BLOCK, &set, 0);
}

/**
 * Initialize signal handling for the daemon.
 */
static void os_signal_init(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler_term;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	sa.sa_handler = signal_handler_hup;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGHUP, &sa, 0);

	sa.sa_handler = SIG_IGN; /* ignore the signal */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, 0);
}

/****************************************************************************/
/* exec */

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

const char* os_find_engine(void)
{
	for (int i = 0; snapraid_paths[i]; ++i) {
		if (eaccess(snapraid_paths[i], X_OK) == 0)
			return snapraid_paths[i];
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

const char* os_find_curl(void)
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

const char* os_find_docker(void)
{
	for (int i = 0; docker_paths[i]; ++i) {
		if (eaccess(docker_paths[i], X_OK) == 0)
			return docker_paths[i];
	}

	return 0;
}

void os_default_log(char* dst, size_t dst_size)
{
	sncpy(dst, dst_size, "/var/log/snapraid");
}

void os_default_conf(char* dst, size_t dst_size)
{
#ifdef SYSCONFDIR
	/* if it exists, give precedence to sysconfdir, usually /usr/local/etc (note that PACKAGE is snapraid-daemon) */
	sncpy(dst, dst_size, SYSCONFDIR "/" DAEMON ".conf");
	if (eaccess(dst, F_OK) == 0)
		return;
#endif
	sncpy(dst, dst_size, "/etc/" DAEMON ".conf");
}

void os_default_data(char* dst, size_t dst_size, const char* root)
{
#ifdef DATADIR
	snprintf(dst, dst_size, DATADIR "/%s", root);
	if (eaccess(dst, F_OK) == 0)
		return;
#endif
	/* otherwise use  /usr/share/snapraidd */
	snprintf(dst, dst_size, "/usr/share/" DAEMON "/%s", root);
}

/*
 * Scrubbed environment
 * Only provide the bare essentials.
 */
static char* const envp_scrubbed[] = {
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
		log_task(LVL_ERROR, "failed to read script shebang, path=%s, errno=%s(%d)", script_path, strerror(errno), errno);
		return -1;
	}
	if (bytes_read < 4) {
		log_task(LVL_ERROR, "script %s is too small or missing a shebang", script_path);
		return -1;
	}
	shebang[bytes_read] = 0;

	/* check for shebang */
	if (shebang[0] != '#' || shebang[1] != '!') {
		log_task(LVL_ERROR, "script %s is missing shebang (#!)", script_path);
		return -1;
	}

	char* end_of_line = strchr(shebang, '\n');
	if (!end_of_line || end_of_line - shebang > 128) {
		log_task(LVL_ERROR, "script %s has invalid or overlong shebang (#!), exceeds 126 characters", script_path);
		return -1;
	}
	*end_of_line = 0;

	/* skip "#!" and whitespace */
	interpreter = shebang + 2;
	while (*interpreter && isspace((unsigned char)*interpreter))
		++interpreter;

	if (*interpreter == 0) {
		log_task(LVL_ERROR, "script %s has empty shebang", script_path);
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
		log_task(LVL_ERROR, "script %s uses disallowed interpreter %s", script_path, interpreter);
		return -1;
	}

	/* verify interpreter exists and is safe */
	if (stat(interpreter, &st) != 0) {
		log_task(LVL_ERROR, "interpreter %s does not exist, errno=%s(%d)", interpreter, strerror(errno), errno);
		return -1;
	}

	/* interpreter must be a regular file */
	if (!S_ISREG(st.st_mode)) {
		log_task(LVL_ERROR, "interpreter %s must be a regular file", interpreter);
		return -1;
	}

	/* interpreter must be owned by root */
	if (st.st_uid != 0) {
		log_task(LVL_ERROR, "interpreter %s not owned by root", interpreter);
		return -1;
	}

	/* interpreter must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_task(LVL_ERROR, "interpreter %s is world-writable", interpreter);
		return -1;
	}

	/* interpreter must be not group-writable (unless group is root) */
	if ((st.st_mode & S_IWGRP) && st.st_gid != 0) {
		log_task(LVL_ERROR, "interpreter %s is group-writable by non-root group", interpreter);
		return -1;
	}

	/* interpreter must be executable */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_task(LVL_ERROR, "interpreter %s is not executable", interpreter);
		return -1;
	}

	/* interpreter must be not setuid / setgid */
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		log_task(LVL_ERROR, "file %s has setuid/setgid bits set", interpreter);
		return -1;
	}

	/* all checks passed */
	return 0;
}

/*
 * Securely verify and open an executable file.
 *
 * Performs a series of security checks on the file at @exec_path before
 * returning an open file descriptor suitable for use with fexecve(2), or
 * falling back to execve(2) on systems that lack it.
 *
 * Security model:
 *   - @exec_path must be absolute.
 *   - The path is resolved via realpath(3) to canonicalize it and eliminate
 *     symlinks before any further checks are performed.
 *   - The parent directory is opened with O_PATH | O_NOFOLLOW to pin its
 *     inode, and the file is opened with openat(2) relative to that pinned
 *     descriptor. This closes the TOCTOU window between path resolution
 *     and file open.
 *   - Both the parent directory and the file must be owned by root or the
 *     daemon's real/effective UID, must not be world-writable, and must not
 *     be group-writable by a group other than the daemon's real/effective GID.
 *   - The file must be a regular file with at least one execute bit set.
 *   - The setuid and setgid bits must not be set.
 *   - The file must not have more than one hard link, to prevent an attacker
 *     from linking a controlled file into a trusted directory.
 *   - On systems with fexecve(2) support, the returned fd is opened without
 *     O_CLOEXEC so it can be passed directly to fexecve(2). On other systems
 *     O_CLOEXEC is set and execve(2) must be used with @resolved_path.
 *
 * @exec_path     Absolute path to the executable to verify.
 * @resolved_path Caller-allocated buffer of at least PATH_MAX bytes. On
 *                success, filled with the canonicalized path from realpath(3).
 *
 * Returns an open file descriptor (>= 0) on success. The caller is
 * responsible for closing it. Returns -1 on any verification failure;
 * the specific reason is emitted via log_task(LVL_ERROR, ...).
 */
static int verify_executable(const char* exec_path, char* resolved_path)
{
	struct stat st;
	uid_t process_uid, process_euid;
	gid_t process_gid, process_egid;

	process_uid = getuid();
	process_euid = geteuid();
	process_gid = getgid();
	process_egid = getegid();

	/* verify path is absolute */
	if (exec_path[0] != '/') {
		log_task(LVL_ERROR, "path %s must be absolute", exec_path);
		return -1;
	}

	/* resolve the path to prevent symlink attacks */
	if (!realpath(exec_path, resolved_path)) {
		log_task(LVL_ERROR, "failed to resolve %s, errno=%s(%d)", exec_path, strerror(errno), errno);
		return -1;
	}

	char* last_slash = strrchr(resolved_path, '/');
	if (last_slash == 0) {
		log_task(LVL_ERROR, "relative execution of %s not allowed", resolved_path);
		return -1;
	}
	if (last_slash == resolved_path) {
		log_task(LVL_ERROR, "root dir execution of %s not allowed", resolved_path);
		return -1;
	}

	const char* exec_name = last_slash + 1;
	if (exec_name[0] == 0) {
		log_task(LVL_ERROR, "no executable name in %s", exec_path);
		return -1;
	}

	char dir_path[PATH_MAX];
	size_t dir_len = last_slash - resolved_path;
	memcpy(dir_path, resolved_path, dir_len);
	dir_path[dir_len] = 0;

	int dir_fd = open(dir_path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dir_fd < 0) {
		log_task(LVL_ERROR, "failed to open directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		return -1;
	}

	if (fstat(dir_fd, &st) != 0) {
		log_task(LVL_ERROR, "failed to stat directory %s, errno=%s(%d)", dir_path, strerror(errno), errno);
		close(dir_fd);
		return -1;
	}

	/* directory must be owned by root or the daemon's real user */
	if (st.st_uid != process_uid && st.st_uid != process_euid && st.st_uid != 0) {
		log_task(LVL_ERROR, "directory %s owner must match the daemon owner or be root", dir_path);
		close(dir_fd);
		return -1;
	}

	/* directory must be not group-writable unless group matches daemon */
	if ((st.st_mode & S_IWGRP) && st.st_gid != process_gid && st.st_gid != process_egid && st.st_gid != 0) {
		log_task(LVL_ERROR, "directory %s must be not group-writable unless group matches daemon owner or root", dir_path);
		close(dir_fd);
		return -1;
	}

	/* directory must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_task(LVL_ERROR, "directory %s must be not world-writable", dir_path);
		close(dir_fd);
		return -1;
	}

	/*
	 * Open the executable
	 * O_NOFOLLOW prevents following symlinks to mitigate redirection attacks
	 */
	int fd = openat(dir_fd, exec_name, O_RDONLY | O_NOFOLLOW
#if !HAVE_FEXECVE
		| O_CLOEXEC /* with fexecve cannot use O_CLOEXEC (Close on Exec) */
#endif
	);
	if (fd < 0) {
		log_task(LVL_ERROR, "failed to open %s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(dir_fd);
		return -1;
	}

	close(dir_fd);

	/* get the file handle (TOCTOU Protection) */
	if (fstat(fd, &st) == -1) {
		log_task(LVL_ERROR, "failed to stat %s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(fd);
		return -1;
	}

	/* ensure it's a regular file */
	if (!S_ISREG(st.st_mode)) {
		log_task(LVL_ERROR, "file %s is not a regular file", resolved_path);
		close(fd);
		return -1;
	}

	/* ensure it has execute permissions */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_task(LVL_ERROR, "file %s is not an executable", resolved_path);
		close(fd);
		return -1;
	}

	/* must be owned by root or the daemon's real user */
	if (st.st_uid != process_uid && st.st_uid != process_euid && st.st_uid != 0) {
		log_task(LVL_ERROR, "file %s owner must match the daemon owner or be root", resolved_path);
		close(fd);
		return -1;
	}

	/* must be not group-writable unless group matches daemon */
	if ((st.st_mode & S_IWGRP) && st.st_gid != process_gid && st.st_gid != process_egid && st.st_gid != 0) {
		log_task(LVL_ERROR, "file %s must be not group-writable unless group matches daemon owner or root", resolved_path);
		close(fd);
		return -1;
	}

	/* must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_task(LVL_ERROR, "file %s must be not world-writable", resolved_path);
		close(fd);
		return -1;
	}

	/* must be not setuid / setgid */
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		log_task(LVL_ERROR, "file %s has setuid/setgid bits set", resolved_path);
		close(fd);
		return -1;
	}

	/* verify the file has not been hardlinked multiple times */
	if (st.st_nlink > 1) {
		log_task(LVL_ERROR, "file %s has multiple hard links", resolved_path);
		close(fd);
		return -1;
	}

	return fd;
}

/**
 * Executes a script directly via its file descriptor.
 */
int os_script(char** argv, char** envp, const char* run_as_user)
{
	char resolved_path[PATH_MAX];
	pid_t pid;
	int ret;
	int status;
	int64_t start, stop;

	int fd = verify_executable(argv[0], resolved_path);
	if (fd < 0) {
		return -1;
	}

	if (verify_shebang_interpreter(fd, resolved_path) != 0) {
		close(fd);
		return -1;
	}

	start = os_tick_sec();

	pid = fork();
	if (pid < 0) {
		log_task(LVL_ERROR, "failed to fork script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(fd);
		return -1;
	}

	if (pid == 0) {
		/* child process */

		/*
		 * Create a new process group for the child.
		 * This isolates the child from signals sent to the daemon's process group
		 * and allows the daemon to kill this process and all its future children
		 * (the entire group) using kill(-pid, SIGTERM).
		 */
		setpgid(0, 0);

		/* drop privileges first (if configured) */
		if (run_as_user && run_as_user[0] != 0) {
			errno = 0;
			struct passwd* pw = getpwnam(run_as_user);
			if (!pw) {
				/* if errno is 0, user simply wasn't found. Otherwise, it's a real error */
				if (errno == 0)
					_exit(127);
				else
					_exit(126);
			}
			if (initgroups(pw->pw_name, pw->pw_gid) != 0)
				_exit(126);
			if (setgid(pw->pw_gid) != 0)
				_exit(126);
			if (setuid(pw->pw_uid) != 0)
				_exit(126);
		}

		/* io sandboxing */
		int null_fd = open("/dev/null", O_RDWR);
		if (null_fd == -1)
			_exit(126);

		/* redirect stdin/out/err to /dev/null */
		if (dup2(null_fd, STDIN_FILENO) == -1
			|| dup2(null_fd, STDOUT_FILENO) == -1
			|| dup2(null_fd, STDERR_FILENO) == -1)
			_exit(126);

		/* if the fd we opened is not one of the standard ones, close it */
		if (null_fd > STDERR_FILENO)
			close(null_fd);

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
		os_signal_restore_after_fork();

		/* child will receive SIGALRM in 300 seconds (5 minutes) as a timeout */
		alarm(300);

		/* use the resolved path for execution */
		argv[0] = resolved_path;

		/*
		 * Direct Execution via File Descriptor
		 * The kernel uses the shebang in the FD to find the interpreter.
		 */
		if (envp != NULL) {
			int envv_count = 0;
			while (envp[envv_count] != NULL) {
				envv_count++;
			}
			int scrubbed_count = sizeof(envp_scrubbed) / sizeof(envp_scrubbed[0]) - 1;
			char* envp_dynamic[scrubbed_count + envv_count + 1];
			for (int i = 0; i < scrubbed_count; ++i) {
				envp_dynamic[i] = envp_scrubbed[i];
			}
			for (int i = 0; i < envv_count; ++i) {
				envp_dynamic[scrubbed_count + i] = envp[i];
			}
			envp_dynamic[scrubbed_count + envv_count] = NULL;

#if HAVE_FEXECVE
			fexecve(fd, argv, envp_dynamic);
#else
			/* fallback: unfortunately must use the path */
			execve(resolved_path, argv, envp_dynamic);
#endif
		} else {
#if HAVE_FEXECVE
			fexecve(fd, argv, envp_scrubbed);
#else
			/* fallback: unfortunately must use the path */
			execve(resolved_path, argv, envp_scrubbed);
#endif
		}
		_exit(127);
	}

	/* parent process */
	close(fd);

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		log_task(LVL_ERROR, "failed to wait for script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		return -1;
	}

	stop = os_tick_sec();
	int64_t execution_time = stop - start;
	if (execution_time > 30)
		log_task(LVL_WARNING, "script %s took %" PRId64 " seconds", resolved_path, execution_time);

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0)
			log_task(LVL_INFO, "script %s terminated in %" PRId64 " seconds with success", resolved_path, execution_time);
		else
			log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds with exit code %d", resolved_path, execution_time, exit_code);
		return exit_code;
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		int sig = WTERMSIG(status);
		if (sig == SIGALRM) {
			log_task(LVL_WARNING, "script %s timeout after %" PRId64 " seconds", resolved_path, execution_time);
		} else {
			log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds with signal %s(%d)", resolved_path, execution_time, signal_name(sig), sig);
		}
		return 128 + sig;
	} else {
		/* in Linux it should never happen */
		log_task(LVL_ERROR, "script %s terminated in %" PRId64 " seconds for unknown reason, status=%d", resolved_path, execution_time, status);
		return -1;
	}
}

int os_command(const char* command, const char* run_as_user, const char* stdin_text)
{
	pid_t pid;
	int ret;
	int status;
	int pipe_fds[2] = { -1, -1 };
	int64_t start, stop;

	/* create pipe only if we have text to send */
	if (stdin_text != NULL) {
		if (pipe(pipe_fds) < 0) {
			log_task(LVL_ERROR, "failed to create pipe for command, errno=%s(%d)", strerror(errno), errno);
			return -1;
		}
	}

	start = os_tick_sec();

	pid = fork();
	if (pid < 0) {
		log_task(LVL_ERROR, "failed to fork command, command=%s, errno=%s(%d)", command, strerror(errno), errno);
		if (pipe_fds[0] != -1) {
			close(pipe_fds[0]);
			close(pipe_fds[1]);
		}
		return -1;
	}

	if (pid == 0) {
		/* child process */

		/*
		 * Create a new process group for the child.
		 * This isolates the child from signals sent to the daemon's process group
		 * and allows the daemon to kill this process and all its future children
		 * (the entire group) using kill(-pid, SIGTERM).
		 */
		setpgid(0, 0);

		if (pipe_fds[1] != -1)
			close(pipe_fds[1]); /* Close unused write end */

		/* drop privileges first (if configured) */
		if (run_as_user && run_as_user[0] != 0) {
			errno = 0;
			struct passwd* pw = getpwnam(run_as_user);
			if (!pw) {
				/* if errno is 0, user simply wasn't found. Otherwise, it's a real error */
				if (errno == 0)
					_exit(127);
				else
					_exit(126);
			}
			if (initgroups(pw->pw_name, pw->pw_gid) != 0)
				_exit(126);
			if (setgid(pw->pw_gid) != 0)
				_exit(126);
			if (setuid(pw->pw_uid) != 0)
				_exit(126);
		}

		/* io sandboxing */
		int null_fd = open("/dev/null", O_RDWR);
		if (null_fd == -1)
			_exit(126);

		/* redirect STDIN: either from pipe or /dev/null */
		if (pipe_fds[0] != -1) {
			if (dup2(pipe_fds[0], STDIN_FILENO) == -1)
				_exit(126);
			close(pipe_fds[0]);
		} else {
			if (dup2(null_fd, STDIN_FILENO) == -1)
				_exit(126);
		}

		/* Redirect STDOUT and STDERR to /dev/null */
		if (dup2(null_fd, STDOUT_FILENO) == -1
			|| dup2(null_fd, STDERR_FILENO) == -1)
			_exit(126);

		/* if the fd we opened is not one of the standard ones, close it */
		if (null_fd > STDERR_FILENO)
			close(null_fd);

#if defined(CLOSE_RANGE_CLOEXEC) && defined(HAVE_CLOSE_RANGE)
		/*
		 * Set all fd to be closed on exec as extra safety measure
		 *
		 * fallback: if it fails, we assume to be still safe, as all fds and
		 * sockets should be already created with CLOEXEC.
		 */
		close_range(3, ~0U, CLOSE_RANGE_CLOEXEC);
#endif

		/* restore and unblock signals */
		os_signal_restore_after_fork();

		/* child will receive SIGALRM in 300 seconds (5 minutes) as a timeout */
		alarm(300);

		char* const argv[] = { "sh", "-c", (char*)command, 0 };

		execve("/bin/sh", argv, envp_scrubbed);

		_exit(127);
	}

	/* parent process */
	if (pipe_fds[0] != -1)
		close(pipe_fds[0]); /* close unused read end */

	if (pipe_fds[1] != -1) {
		/* write text to child's stdin */
		ssize_t len = strlen(stdin_text);
		if (write(pipe_fds[1], stdin_text, len) != len) {
			log_task(LVL_WARNING, "failed to write full stdin to command %s", command);
		}
		/* closing the pipe sends EOF to the child (e.g., tells curl data is done) */
		close(pipe_fds[1]);
	}

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		log_task(LVL_ERROR, "failed to wait for command, command=%s, errno=%s(%d)", command, strerror(errno), errno);
		return -1;
	}

	stop = os_tick_sec();
	int64_t execution_time = stop - start;
	if (execution_time > 30)
		log_task(LVL_WARNING, "command %s ran for %" PRId64 " seconds that is unexpectedly long", command, execution_time);

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		if (exit_code == 0)
			log_task(LVL_INFO, "command %s terminated in %" PRId64 " seconds with success", command, execution_time);
		else
			log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds with exit code %d", command, execution_time, exit_code);
		return exit_code;
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		int sig = WTERMSIG(status);
		if (sig == SIGALRM) {
			log_task(LVL_WARNING, "command %s timeout after %" PRId64 " seconds", command, execution_time);
		} else {
			log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds with signal %s(%d)", command, execution_time, signal_name(sig), sig);
		}
		return 128 + sig;
	} else {
		/* in Linux it should never happen */
		log_task(LVL_ERROR, "command %s terminated in %" PRId64 " seconds for unknown reason, status=%d", command, execution_time, status);
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

/**
 * os_spawn() - Fork and execute a verified executable, capturing stdout and/or stderr.
 *
 * Spawns @argv[0] in a new process. If @stdout_read_fd is not NULL, stdout is connected
 * to a pipe whose read end is returned in @stdout_read_fd. If @stderr_read_fd is not NULL,
 * stderr is connected to a pipe whose read end is returned in @stderr_read_fd.
 * Otherwise, they are redirected to /dev/null. stdin is always redirected to /dev/null.
 *
 * The child is placed in its own process group (setpgid) to isolate it from signals
 * sent to the daemon's process group.
 *
 * Returns the child PID on success, or -1 on failure.
 */
pid_t os_spawn(char** argv, int* stdout_read_fd, int* stderr_read_fd, const char* run_as_user)
{
	char resolved_path[PATH_MAX];
	int out_pipe[2];
	int err_pipe[2];
	int has_out = (stdout_read_fd != NULL);
	int has_err = (stderr_read_fd != NULL);
	pid_t pid;

	int fd = verify_executable(argv[0], resolved_path);
	if (fd < 0) {
		return -1;
	}

	if (has_out) {
		if (pipe_cloexec(out_pipe) < 0) {
			close(fd);
			return -1;
		}
	}

	if (has_err) {
		if (pipe_cloexec(err_pipe) < 0) {
			if (has_out) {
				close(out_pipe[0]);
				close(out_pipe[1]);
			}
			close(fd);
			return -1;
		}
	}

	pid = fork();
	if (pid < 0) {
		if (has_out) {
			close(out_pipe[0]);
			close(out_pipe[1]);
		}
		if (has_err) {
			close(err_pipe[0]);
			close(err_pipe[1]);
		}
		close(fd);
		return -1;
	}

	if (pid == 0) {
		/* child process */

		setpgid(0, 0);

		/* drop privileges first (if configured) */
		if (run_as_user && run_as_user[0] != 0) {
			errno = 0;
			struct passwd* pw = getpwnam(run_as_user);
			if (!pw) {
				if (errno == 0)
					_exit(127);
				else
					_exit(126);
			}
			if (initgroups(pw->pw_name, pw->pw_gid) != 0)
				_exit(126);
			if (setgid(pw->pw_gid) != 0)
				_exit(126);
			if (setuid(pw->pw_uid) != 0)
				_exit(126);
		}

		/* io sandboxing */
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null_fd < 0)
			_exit(126);

		/* stdin -> /dev/null */
		if (dup2(null_fd, STDIN_FILENO) < 0)
			_exit(126);

		/* stdout */
		if (has_out) {
			if (dup2(out_pipe[1], STDOUT_FILENO) < 0)
				_exit(126);
		} else {
			if (dup2(null_fd, STDOUT_FILENO) < 0)
				_exit(126);
		}

		/* stderr */
		if (has_err) {
			if (dup2(err_pipe[1], STDERR_FILENO) < 0)
				_exit(126);
		} else {
			if (dup2(null_fd, STDERR_FILENO) < 0)
				_exit(126);
		}

		if (has_out) {
			close(out_pipe[0]);
			close(out_pipe[1]);
		}
		if (has_err) {
			close(err_pipe[0]);
			close(err_pipe[1]);
		}

		if (null_fd > STDERR_FILENO)
			close(null_fd);

#if defined(CLOSE_RANGE_CLOEXEC) && defined(HAVE_CLOSE_RANGE)
		close_range(3, fd - 1, CLOSE_RANGE_CLOEXEC);
		close_range(fd + 1, ~0U, CLOSE_RANGE_CLOEXEC);
#endif

		os_signal_restore_after_fork();

		argv[0] = resolved_path;

#if HAVE_FEXECVE
		fexecve(fd, argv, envp_scrubbed);
#else
		execve(resolved_path, argv, envp_scrubbed);
#endif
		_exit(127);
	}

	/* parent */
	close(fd);

	if (has_out) {
		if (fcntl(out_pipe[0], F_SETPIPE_SZ, 4096) == -1) {
			log_task(LVL_WARNING, "failed to set pipe size, errno=%s(%d)", strerror(errno), errno);
		}
		close(out_pipe[1]);
		*stdout_read_fd = out_pipe[0];
	}

	if (has_err) {
		if (fcntl(err_pipe[0], F_SETPIPE_SZ, 4096) == -1) {
			log_task(LVL_WARNING, "failed to set pipe size, errno=%s(%d)", strerror(errno), errno);
		}
		close(err_pipe[1]);
		*stderr_read_fd = err_pipe[0];
	}

	return pid;
}

int os_wait(pid_t pid, int* status)
{
	int ret;

	do {
		ret = waitpid(pid, status, 0);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

int os_term(pid_t pid)
{
	/*
	 * Send signal to the negative PID to target the entire Process Group.
	 * This ensures that SnapRAID and any programs it may have spawned are
	 * terminated together, preventing orphaned worker processes.
	 */
	return kill(-pid, SIGTERM);
}

/****************************************************************************/
/* system */

/**
 * @brief Parses a system attribute file.
 * @param path The filesystem path (e.g., "/proc/cpuinfo").
 * @param tag The tag to search for (e.g., "model name"). If NULL, matches the first line.
 * @param position The zero-based index of the whitespace-separated argument to return. If -1 return everything
 * @param out The output buffer.
 * @param out_size Size of the output buffer.
 * @return char* Pointer to 'out' on success, NULL on failure.
 */
char* sysattr(const char* path, const char* tag, char separator, int position, char* out, size_t out_size)
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

void os_system(struct snapraid_system* system)
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

	os_system_refresh(system);
}

void os_system_refresh(struct snapraid_system* system)
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

uint64_t os_tick_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

int os_randomize(void* ptr, size_t size)
{
	int f;
	ssize_t ret;

	f = open("/dev/urandom", O_RDONLY);
	if (f == -1) {
		/* LCOV_EXCL_START */
		return -1;
		/* LCOV_EXCL_STOP */
	}

	ret = read(f, ptr, size);
	if (ret < 0 || (size_t)ret != size) {
		/* LCOV_EXCL_START */
		close(f);
		return -1;
		/* LCOV_EXCL_STOP */
	}

	if (close(f) != 0) {
		/* LCOV_EXCL_START */
		return -1;
		/* LCOV_EXCL_STOP */
	}

	return 0;
}

/****************************************************************************/
/* daemon */

static int os_pidfile(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg)
{
	/* determine the path if not explicitly provided */
	if (pidfile_arg && pidfile_arg[0]) {
		sncpy(pidfile_path, pidfile_size, pidfile_arg);
	} else {
		if (geteuid() == 0) {
			/* standard for root-level daemons */
			snprintf(pidfile_path, pidfile_size, "/run/%s.pid", DAEMON);
		} else {
			/* standard for user-level processes */
			snprintf(pidfile_path, pidfile_size, "/tmp/%s.pid", DAEMON);
		}
	}

	/*
	 * Open the file, create if missing, open for reading/writing
	 *
	 * O_NOFOLLOW Prevents attacks about making a dangling link pointing
	 * to another file that will be created with the daemon ownership.
	 */
	int fd = open(pidfile_path, O_RDWR | O_CREAT | O_NOFOLLOW, 0644);
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
			fprintf(stderr, "%s is already running.\n", DAEMON);
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
static int os_daemonize(char* pidfile_path, size_t pidfile_size, const char* pidfile_arg)
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
	int pidfd = os_pidfile(pidfile_path, pidfile_size, pidfile_arg);
	if (pidfd < 0)
		return -1;

	/* allow daemon total control over its files */
	umask(0);

	/* ensure the daemon doesn't block any filesystem unmounting */
	if (chdir("/") != 0) {
		close(pidfd);
		return -1;
	}

	/* redirect Standard I/O to /dev/null */
	int fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		close(pidfd);
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0
		|| dup2(fd, STDOUT_FILENO) < 0
		|| dup2(fd, STDERR_FILENO) < 0) {
		close(fd);
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
		pidfd = os_daemonize(pidfile, sizeof(pidfile), state->config.pidfile_arg);
		if (pidfd == -1)
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
		unlink(pidfile);
		close(pidfd);
	}

	return 0;
}
#endif

