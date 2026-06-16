// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#include "portable.h"

#ifndef __MINGW32__ /* Only for Unix */

#include "os.h"
#include "state.h"
#include "log.h"

/****************************************************************************/
/* signal */

void os_signal_restore_after_fork(void)
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

void os_signal_set(int enable)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);

	pthread_sigmask(enable ? SIG_UNBLOCK : SIG_BLOCK, &set, 0);
}

void os_signal_init(void (*handler_term)(int sig), void (*handler_hup)(int sig))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler_term;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	sa.sa_handler = handler_hup;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART; /* use the SA_RESTART to automatically restart interrupted system calls */

	sigaction(SIGHUP, &sa, 0);

	sa.sa_handler = SIG_IGN; /* ignore the signal */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, 0);
}

/****************************************************************************/
/* unix */

#if !HAVE_EACCESS
int eaccess(const char* pathname, int mode)
{
	return faccessat(AT_FDCWD, pathname, mode, AT_EACCESS);
}
#endif

/****************************************************************************/
/* exec */

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
 *   - On systems with fexecve(2) support, the returned fd is opened without
 *     O_CLOEXEC if the file is a script (@is_script=1). This is necessary because
 *     fexecve(2) executes scripts by passing a descriptor path (e.g., /dev/fd/N)
 *     to the script interpreter, which requires the fd to remain open across
 *     the execve syscall. For compiled binaries, O_CLOEXEC is safely applied
 *     to prevent leaking the fd to the spawned process. On systems without
 *     fexecve(2), execve(2) is used with @resolved_path and O_CLOEXEC is
 *     always applied.
 *
 * @exec_path     Absolute path to the executable to verify.
 * @resolved_path Caller-allocated buffer of at least PATH_MAX bytes. On
 *                success, filled with the canonicalized path from realpath(3).
 *
 * Returns an open file descriptor (>= 0) on success. The caller is
 * responsible for closing it. Returns -1 on any verification failure;
 * the specific reason is emitted via log_task(LVL_ERROR, ...).
 */
static int verify_executable(const char* exec_path, char* resolved_path, int is_script)
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
	 */
	int flags = O_RDONLY | O_NOFOLLOW;
#if HAVE_FEXECVE
	if (!is_script) {
		flags |= O_CLOEXEC; /* with fexecve cannot use O_CLOEXEC (Close on Exec) for scripts */
	}
#else
	(void)is_script;
	flags |= O_CLOEXEC;
#endif

	int fd = openat(dir_fd, exec_name, flags);
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

	/* explicitly reject scripts if not allowed */
	if (!is_script) {
		char magic[2];
		if (read(fd, magic, 2) == 2 && magic[0] == '#' && magic[1] == '!') {
			log_task(LVL_ERROR, "file %s is a script, which is not supported", resolved_path);
			close(fd);
			return -1;
		}
		if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
			/* ignore lseek errors on block devices or pipes, though it's a regular file here */
		}
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

	int fd = verify_executable(argv[0], resolved_path, 1);
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
		 *
		 * For scripts we cannot set fd as CLOEXEC.
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

	int fd = verify_executable(argv[0], resolved_path, 0);
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
/* os */

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

static uid_t unpriv_uid = -1;
static gid_t unpriv_gid = -1;
static int can_switch = 0;

void os_privileges_drop(void)
{
	/*
	 * Detect if running as root
	 *
	 * Note that all calls to os_privileges_release() and os_privileges_acquire()
	 * are no-ops before this detection.
	 */
	if (getuid() == 0 || geteuid() == 0) {
		/* find the unprivileged user "nobody" */
		struct passwd* pw = getpwnam("nobody");
		if (pw) {
			unpriv_uid = pw->pw_uid;
			unpriv_gid = pw->pw_gid;
			can_switch = 1;
		}
	}

	os_privileges_release();
}

void os_privileges_acquire(void)
{
	if (can_switch) {
		if (seteuid(0) != 0) {
			log_task(LVL_ERROR, "failed to acquire privileges, errno=%s(%d)", strerror(errno), errno);
		}
		if (setegid(0) != 0) {
			log_task(LVL_ERROR, "failed to acquire group privileges, errno=%s(%d)", strerror(errno), errno);
		}
	}
}

void os_privileges_release(void)
{
	if (can_switch) {
		if (setegid(unpriv_gid) != 0) {
			log_task(LVL_ERROR, "failed to release group privileges, errno=%s(%d)", strerror(errno), errno);
		}
		if (seteuid(unpriv_uid) != 0) {
			log_task(LVL_ERROR, "failed to release privileges, errno=%s(%d)", strerror(errno), errno);
		}
	}
}

#endif

