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
#include "support.h"

/****************************************************************************/
/* exec */

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
		log_msg(LVL_ERROR, "script %s is too small or missing a shebang", script_path);
		return -1;
	}
	shebang[bytes_read] = 0;

	/* check for shebang */
	if (shebang[0] != '#' || shebang[1] != '!') {
		log_msg(LVL_ERROR, "script %s is missing shebang (#!)", script_path);
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

	/* interpreter must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_msg(LVL_ERROR, "interpreter %s is world-writable", interpreter);
		return -1;
	}

	/* interpreter must be not group-writable (unless group is root) */
	if ((st.st_mode & S_IWGRP) && st.st_gid != 0) {
		log_msg(LVL_ERROR, "interpreter %s is group-writable by non-root group", interpreter);
		return -1;
	}

	/* interpreter must be executable */
	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		log_msg(LVL_ERROR, "interpreter %s is not executable", interpreter);
		return -1;
	}

	/* interpreter must be not setuid / setgid */
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
int os_script(const char* script_path, const char* run_as_user)
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

			/* script directory must be not group-writable unless group matches daemon */
			if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
				log_msg(LVL_ERROR, "script directory %s must be not group-writable unless group matches daemon owner or root", dir_path);
				return -1;
			}

			/* script directory must be not world-writable */
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

	/* script must be not group-writable unless group matches daemon */
	if ((st.st_mode & S_IWGRP) && st.st_gid != daemon_gid && st.st_gid != daemon_egid && st.st_gid != 0) {
		log_msg(LVL_ERROR, "script %s must be not group-writable unless group matches daemon owner or root", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be not world-writable */
	if (st.st_mode & S_IWOTH) {
		log_msg(LVL_ERROR, "script %s must be not world-writable", resolved_path);
		close(fd);
		return -1;
	}

	/* script must be not setuid / setgid */
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

		/* drop privileges first (if configured) */
		if (run_as_user && run_as_user[0] != '\0') {
			errno = 0;
			struct passwd *pw = getpwnam(run_as_user);
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
		_exit(127);
	}

	/* parent process */
	close(fd);

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		log_msg(LVL_ERROR, "failed to wait for script, path=%s, errno=%s(%d)", resolved_path, strerror(errno), errno);
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
		int sig = WTERMSIG(status);
		if (sig == SIGALRM) {
			log_msg(LVL_WARNING, "script %s timeout after %lld seconds", resolved_path, execution_time);
		} else {
			log_msg(LVL_INFO, "script %s terminated in %lld seconds with signal %s(%d)", resolved_path, execution_time, log_signame(sig), sig);
		}
		return 128 + sig;
	} else {
		/* it should never happen */
		log_msg(LVL_INFO, "script %s terminated in %lld seconds for unknown reason, status=%d", resolved_path, execution_time, status);
		return -1;
	}
}

int os_command(const char* command, const char* target_user, const char* stdin_text)
{
	pid_t pid;
	int ret;
	int status;
	int pipe_fds[2] = { -1, -1 };
	struct timespec start_ts, stop_ts;

	/* create pipe only if we have text to send */
	if (stdin_text != NULL) {
		if (pipe(pipe_fds) < 0) {
			log_msg(LVL_ERROR, "failed to create pipe for command, errno=%s(%d)", strerror(errno), errno);
			return -1;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	pid = fork();
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to fork command, command=%s, errno=%s(%d)", command, strerror(errno), errno);
		if (pipe_fds[0] != -1) {
			close(pipe_fds[0]);
			close(pipe_fds[1]);
		}
		return -1;
	}

	if (pid == 0) {
		/* child process */

		if (pipe_fds[1] != -1)
			close(pipe_fds[1]); /* Close unused write end */

		/* drop privileges first (if configured) */
		if (target_user && target_user[0] != '\0') {
			errno = 0;
			struct passwd *pw = getpwnam(target_user);
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

		char* const argv[] = { "sh", "-c", (char *)command, 0 };

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
			log_msg(LVL_WARNING, "failed to write full stdin to command %s", command);
		}
		/* closing the pipe sends EOF to the child (e.g., tells curl data is done) */
		close(pipe_fds[1]);
	}

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		log_msg(LVL_ERROR, "failed to wait for command, command=%s, errno=%s(%d)", command, strerror(errno), errno);
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &stop_ts);
	long long execution_time = (stop_ts.tv_sec - start_ts.tv_sec);

	if (execution_time > 30)
		log_msg(LVL_WARNING, "command %s ran for %lld seconds that is unexpectedly long", command, execution_time);

	if (WIFEXITED(status)) {
		/* child's exit(code) or return from main */
		log_msg(LVL_INFO, "command %s terminated in %lld seconds with code %d", command, execution_time, WEXITSTATUS(status));
		return WEXITSTATUS(status);
	} else if (WIFSIGNALED(status)) {
		/* child died from a signal */
		int sig = WTERMSIG(status);
		if (sig == SIGALRM) {
			log_msg(LVL_WARNING, "command %s timeout after %lld seconds", command, execution_time);
		} else {
			log_msg(LVL_INFO, "command %s terminated in %lld seconds with signal %s(%d)", command, execution_time, log_signame(sig), sig);
		}
		return 128 + sig;
	} else {
		/* it should never happen */
		log_msg(LVL_INFO, "command %s terminated in %lld seconds for unknown reason, status=%d", command, execution_time, status);
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
		/* child */

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
	close(err_pipe[1]);

	*stderr_fd = err_pipe[0];
	return pid;
}

/****************************************************************************/
/* signal */

static void signal_handler_term(int sig)
{
	(void)sig;
	state_ptr()->daemon_running = DAEMON_QUIT;
	state_ptr()->daemon_sig = sig;
}

static void signal_handler_hup(int sig)
{
	(void)sig;
	state_ptr()->daemon_running = DAEMON_RELOAD;
}

void os_signal_restore_after_fork(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGQUIT, &sa, 0);
	sigaction(SIGHUP, &sa, 0);
	sigaction(SIGPIPE, &sa, 0);

	/* Ensure signals are unblocked */
	sigset_t mask;
	sigemptyset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL); /* cannot use pthread_sigmask after fork */
}

void os_signal_set(int enable)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGHUP);

	pthread_sigmask(enable ? SIG_UNBLOCK : SIG_BLOCK, &set, 0);
}

void os_signal_init(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
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
}

/**
 * Detaches the process from the controlling terminal and runs it in the background.
 * Follows the "double-fork" method to ensure the daemon cannot re-acquire a TTY.
 */
int os_daemonize(void)
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
	(void)chdir("/");

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

