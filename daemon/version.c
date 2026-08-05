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

static int parse_github_release_tag(const char* js, size_t jl, char* tag_out, size_t tag_out_size)
{
	jsmn_parser jp;
	jsmn_init(&jp);
	int jc = jsmn_parse(&jp, js, jl, NULL, 0);
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
	for (int i = 1; i < jc; i += 1 + jv[i].size) {
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
		"-m",
		"10",
		url,
		NULL
	};

	int stdout_fd = -1;
	os_privileges_acquire();
	pid_t pid = os_spawn(argv, &stdout_fd, NULL, NULL);
	os_privileges_release();
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to check updates for %s: spawn failed, errno=%s(%d)", repo, strerror(errno), errno);
		return;
	}

	ss_t ss;
	ss_init(&ss, 8192);

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
		ss_write(&ss, read_buf, r);
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
		if (WIFEXITED(status)) {
			log_msg(LVL_ERROR, "failed to check updates for %s: curl exited with code %d", repo, WEXITSTATUS(status));
		} else {
			log_msg(LVL_ERROR, "failed to check updates for %s: curl terminated abnormally", repo);
		}
		ss_done(&ss);
		return;
	}

	char* js = ss_extract(&ss);
	char tag[64];
	if (parse_github_release_tag(js, ss_len(&ss), tag, sizeof(tag)) != 0) {
		log_msg(LVL_ERROR, "failed to check updates for %s: parse failed", repo);
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

