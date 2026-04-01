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

#ifndef __MINGW32__ /* Only for Unix */

#include "state.h"
#include "log.h"
#include "support.h"
#include "daemon.h"
#include "conf.h"

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
	/* Linux & BSD */
	"/usr/bin/snapraid",
	"/usr/local/bin/snapraid",
#ifdef __APPLE__
	/* macOS (Intel & Apple Silicon) */
	"/opt/homebrew/bin/snapraid",
#endif
	0
};

const char* os_find_engine(const char* sys_engine)
{
	/* check for existence every time in case it's installed at later time */
	if (sys_engine != 0 && sys_engine[0] != 0) {
		if (access(sys_engine, X_OK) == 0)
			return sys_engine;
	} else {
		for (int i = 0; snapraid_paths[i]; ++i) {
			if (access(snapraid_paths[i], X_OK) == 0)
				return snapraid_paths[i];
		}
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
	if (access(dst, F_OK) == 0)
		return;
#endif
	sncpy(dst, dst_size, "/etc/" DAEMON ".conf");
}

void os_default_data(char* dst, size_t dst_size, const char* root)
{
#ifdef DATADIR
	snprintf(dst, dst_size, DATADIR "/%s", root);
	if (access(dst, F_OK) == 0)
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

/**
 * Executes a script directly via its file descriptor.
 */
int os_script(char** argv, const char* run_as_user)
{
	int fd;
	struct stat st;
	pid_t pid;
	int ret;
	char resolved_path[PATH_MAX];
	char dir_path[PATH_MAX];
	int status;
	uid_t daemon_uid, daemon_euid;
	gid_t daemon_gid, daemon_egid;
	int64_t start, stop;
	const char* script_path = argv[0];

	daemon_uid = getuid();
	daemon_euid = geteuid();
	daemon_gid = getgid();
	daemon_egid = getegid();

	/* verify script path is absolute */
	if (script_path[0] != '/') {
		log_task(LVL_ERROR, "script path %s must be absolute", script_path);
		return -1;
	}

	/* resolve the script path to prevent symlink attacks */
	if (!realpath(script_path, resolved_path)) {
		log_task(LVL_ERROR, "failed to resolve script, path=%s, errno=%s(%d)", script_path, strerror(errno), errno);
		return -1;
	}

	char* last_slash = strrchr(resolved_path, '/');
	if (last_slash && last_slash != resolved_path) {
		size_t dir_len = last_slash - resolved_path;
		memcpy(dir_path, resolved_path, dir_len);
		dir_path[dir_len] = 0;

		if (stat(dir_path, &st) == 0) {
			/* script directory must be owned by root or the daemon's real user */
			if (st.st_uid != daemon_uid && st.st_uid != daemon_euid && st.st_uid != 0) {
				log_task(LVL_ERROR, "script directory %s owner must match the daemon owner or be root", dir_path);
				return -1;
			}

			/* script directory must be not group-writable unless group matches daemon */
			if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
				log_task(LVL_ERROR, "script directory %s must be not group-writable unless group matches daemon owner or root", dir_path);
				return -1;
			}

			/* script directory must be not world-writable */
			if (st.st_mode & S_IWOTH) {
				log_task(LVL_ERROR, "script directory %s must be not world-writable", dir_path);
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
		log_task(LVL_ERROR, "failed to open script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		return -1;
	}

	/* get the file handle (TOCTOU Protection) */
	if (fstat(fd, &st) == -1) {
		log_task(LVL_ERROR, "failed to stat script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
		close(fd);
		return -1;
	}

	/* ensure it's a regular file */
	if (!S_ISREG(st.st_mode)) {
		log_task(LVL_ERROR, "script %s is not a regular file", resolved_path);
		close(fd);
		return -1;
	}

	/* ensure it has execute permissions */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_task(LVL_ERROR, "script %s is not an executable", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be owned by root or the daemon's real user */
	if (st.st_uid != daemon_uid && st.st_uid != daemon_euid && st.st_uid != 0) {
		log_task(LVL_ERROR, "script %s owner must match the daemon owner or be root", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be not group-writable unless group matches daemon */
	if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
		log_task(LVL_ERROR, "script %s must be not group-writable unless group matches daemon owner or root", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_task(LVL_ERROR, "script %s must be not world-writable", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be not setuid / setgid */
	if (st.st_mode & (S_ISUID | S_ISGID)) {
		log_task(LVL_ERROR, "file %s has setuid/setgid bits set", resolved_path);
		close(fd);
		return -1;
	}

	/* verify the file has not been hardlinked multiple times */
	if (st.st_nlink > 1) {
		log_task(LVL_ERROR, "script %s has multiple hard links", resolved_path);
		close(fd);
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
#if HAVE_FEXECVE
		fexecve(fd, argv, envp_scrubbed);
#else
		/* fallback: unfortunately must use the path */
		execve(resolved_path, argv, envp_scrubbed);
#endif
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

pid_t os_spawn(char** argv, int* stderr_fd)
{
	int err_pipe[2];
	pid_t pid;

	if (pipe_cloexec(err_pipe) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(err_pipe[0]);
		close(err_pipe[1]);
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

		/* io sandboxing */
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null_fd < 0)
			_exit(126);

		/* stdin -> /dev/null */
		/* stdout -> /dev/null */
		/* stderr -> pipe */
		if (dup2(null_fd, STDIN_FILENO) < 0
			|| dup2(null_fd, STDOUT_FILENO) < 0
			|| dup2(err_pipe[1], STDERR_FILENO) < 0)
			_exit(126);

		close(err_pipe[0]);
		close(err_pipe[1]);

		/* if the fd we opened is not one of the standard ones, close it */
		if (null_fd > STDERR_FILENO)
			close(null_fd);

		/* restore and unblock signals */
		os_signal_restore_after_fork();

		execve(argv[0], (char* const*)argv, envp_scrubbed);
		_exit(127);
	}

	/* parent */

	/* set the pipe buffer to the minimum to improve responsiveness */
	if (fcntl(err_pipe[0], F_SETPIPE_SZ, 4096) == -1) {
		log_task(LVL_WARNING, "failed to set pipe size, errno=%s(%d)", strerror(errno), errno);
		/* log non-fatal error or ignore */
	}

	close(err_pipe[1]);

	*stderr_fd = err_pipe[0];
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
			char* token = strtok(content, "\n\r");
			if (token) {
				sncpy(out, out_size, token);
				result = out;
			}
			break;
		}

		if (match && position >= 0) {
			/* tokenize the line content to find the argument at 'position' */
			char* token = strtok(content, " \t\n\r");
			int i = 0;

			if (tag)
				++i; /* skip the tag already processed */

			while (token != NULL) {
				if (i == position) {
					sncpy(out, out_size, token);
					result = out;
					break;
				}

				token = strtok(NULL, " \t\n\r");
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

	if (access("/sys/devices/system/edac/mc/mc0/size_mb", F_OK) == 0)
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

	/* open the file, create if missing, open for reading/writing */
	int fd = open(pidfile_path, O_RDWR | O_CREAT, 0644);
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

