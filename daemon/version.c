// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "os/portable.h"

#include "app.h"
#include "state.h"
#include "support.h"
#include "log.h"
#include "version.h"

#define JSMN_HEADER
#include "jsmn/jsmn.h"

#define VERSION_RESPONSE_MAX 131072

/**
 * Advance iterator past the current JSMN token and all its child nodes.
 */
static int jsmn_skip(const jsmntok_t* jv, int jc, int i)
{
	int end = jv[i].end;
	do {
		++i;
	} while (i < jc && jv[i].start < end);
	return i;
}

/**
 * Sanitize and truncate a string in-place for log output.
 * Replaces control and non-printable characters with spaces, and truncates to 80 characters
 * adding "..." suffix if truncated.
 */
static void curl_sanitize_inplace(char* str)
{
	const size_t max_len = 80;
	size_t i = 0;
	while (str[i] != 0 && i < max_len) {
		unsigned char c = (unsigned char)str[i];
		if (c < 32 || c == 127)
			str[i] = ' ';
		++i;
	}

	if (str[i] != 0) {
		str[max_len - 3] = '.';
		str[max_len - 2] = '.';
		str[max_len - 1] = '.';
		str[max_len] = 0;
	}
}

static int parse_github_release_tag(const char* js, size_t jl, char* tag_out, size_t tag_out_size)
{
	jsmn_parser jp;
	jsmn_init(&jp);
	int jc = jsmn_parse(&jp, js, jl, 0, 0);
	if (jc < 0) {
		return -1;
	}
	jsmntok_t* jv = malloc_nofail(jc * sizeof(jsmntok_t));
	jsmn_init(&jp);
	int parse_res = jsmn_parse(&jp, js, jl, jv, jc);
	if (parse_res < 0) {
		free(jv);
		return -1;
	}
	if (jc < 1 || jv[0].type != JSMN_OBJECT) {
		free(jv);
		return -1;
	}
	int found = 0;
	int i = 1;
	while (i < jc) {
		if (jv[i].type == JSMN_STRING) {
			size_t len = jv[i].end - jv[i].start;
			if (len == 8 && strncmp(js + jv[i].start, "tag_name", 8) == 0) {
				if (i + 1 < jc && jv[i + 1].type == JSMN_STRING) {
					size_t val_len = jv[i + 1].end - jv[i + 1].start;
					char tag[64];
					if (json_unescape(js + jv[i + 1].start, val_len, tag, sizeof(tag)) == 0) {
						const char* p = tag;
						if (*p == 'v')
							++p;
						sncpy(tag_out, tag_out_size, p);
						found = 1;
					}
					break;
				}
			}
		}

		/* advance past the key string token */
		++i;

		/* skip top-level value token and its sub-nodes */
		if (i < jc)
			i = jsmn_skip(jv, jc, i);
	}
	free(jv);
	return found ? 0 : -1;
}

static void check_repo_version(struct snapraid_state* state, const char* curl_path, const char* repo, char* version_out, size_t version_out_size)
{
	char url[256];
	snprintf(url, sizeof(url), "https://api.github.com/repos/%s/releases/latest", repo);

	char* argv[] = {
		(char*)curl_path,
		"-s",
		"--max-filesize",
		"131072",
		"-m",
		"10",
		url,
		NULL
	};

	int stdout_fd = -1;
	/* run curl with the daemon's current unprivileged credentials; update checks do not require root privileges */
	pid_t pid = os_spawn(argv, &stdout_fd, NULL, NULL);
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to check updates for %s: spawn failed, errno=%s(%d)", repo, strerror(errno), errno);
		return;
	}

	ss_t ss;
	ss_init(&ss, 8192);

	int response_too_large = 0;
	char read_buf[512];
	while (1) {
		ssize_t r = read(stdout_fd, read_buf, sizeof(read_buf));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;

		if (ss_len(&ss) + r < VERSION_RESPONSE_MAX)
			ss_write(&ss, read_buf, r);
		else
			response_too_large = 1;
	}
	close(stdout_fd);

	int status = 0;
	pid_t ret = os_wait(pid, &status);
	if (ret == -1) {
		log_msg(LVL_ERROR, "failed to check updates for %s: wait failed, errno=%s(%d)", repo, strerror(errno), errno);
		ss_done(&ss);
		return;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		char* output = ss_extract(&ss);
		curl_sanitize_inplace(output);
		if (output[0] != 0) {
			if (WIFEXITED(status)) {
				log_msg(LVL_ERROR, "failed to check updates for %s: curl exited with code %d, output: %s", repo, WEXITSTATUS(status), output);
			} else {
				log_msg(LVL_ERROR, "failed to check updates for %s: curl terminated abnormally, output: %s", repo, output);
			}
		} else {
			if (WIFEXITED(status)) {
				log_msg(LVL_ERROR, "failed to check updates for %s: curl exited with code %d", repo, WEXITSTATUS(status));
			} else {
				log_msg(LVL_ERROR, "failed to check updates for %s: curl terminated abnormally", repo);
			}
		}
		ss_done(&ss);
		return;
	}

	if (response_too_large) {
		log_msg(LVL_ERROR, "failed to check updates for %s: response exceeds %d bytes", repo, VERSION_RESPONSE_MAX);
		ss_done(&ss);
		return;
	}

	char* js = ss_extract(&ss);
	char tag[64];
	if (parse_github_release_tag(js, ss_len(&ss), tag, sizeof(tag)) != 0) {
		curl_sanitize_inplace(js);
		if (js[0] != 0) {
			log_msg(LVL_ERROR, "failed to check updates for %s: parse failed, response: %s", repo, js);
		} else {
			log_msg(LVL_ERROR, "failed to check updates for %s: parse failed", repo);
		}
		ss_done(&ss);
		return;
	}
	ss_done(&ss);

	state_lock();
	sncpy(version_out, version_out_size, tag);
	pulse(state, PULSE_ARRAY);
	state_unlock();
}

void version_check(struct snapraid_state* state)
{
	const char* curl_path = app_find_curl();
	if (!curl_path) {
		log_msg(LVL_ERROR, "failed to check updates: curl executable not found");
		return;
	}

	check_repo_version(state, curl_path, "amadvance/snapraid-daemon", state->latest_daemon_version, sizeof(state->latest_daemon_version));
	check_repo_version(state, curl_path, "amadvance/snapraid", state->latest_engine_version, sizeof(state->latest_engine_version));
}

