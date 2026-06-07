// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Andrea Mazzoleni

#include "portable.h"

#include "state.h"
#include "support.h"
#include "log.h"
#include "daemon.h"
#include "version.h"

#define JSMN_HEADER
#include "../jsmn/jsmn.h"

static int parse_github_release_tag(const char* js, size_t jl, char* tag_out, size_t tag_out_size)
{
	jsmn_parser jp;
	jsmntok_t jv[512];
	jsmn_init(&jp);
	int jc = jsmn_parse(&jp, js, jl, jv, 512);
	if (jc < 0) {
		return -1;
	}
	if (jc < 1 || jv[0].type != JSMN_OBJECT) {
		return -1;
	}
	for (int i = 1; i < jc; i += 1 + jv[i].size) {
		if (jv[i].type == JSMN_STRING) {
			size_t len = jv[i].end - jv[i].start;
			if (len == 8 && strncmp(js + jv[i].start, "tag_name", 8) == 0) {
				if (i + 1 < jc && jv[i + 1].type == JSMN_STRING) {
					size_t val_len = jv[i + 1].end - jv[i + 1].start;
					char tag[64];
					if (json_unescape(js + jv[i + 1].start, val_len, tag, sizeof(tag)) != 0) {
						return -1;
					}
					const char* p = tag;
					if (*p == 'v')
						++p;
					sncpy(tag_out, tag_out_size, p);
					return 0;
				}
			}
		}
	}
	return -1;
}

void version_check(struct snapraid_state* state)
{
	const char* curl_path = os_find_curl();
	if (!curl_path) {
		log_msg(LVL_ERROR, "failed to check updates: curl executable not found");
		return;
	}
	char* argv[] = {
		(char*)curl_path,
		"-s",
		"-m",
		"10",
		"https://api.github.com/repos/amadvance/snapraid-daemon/releases/latest",
		NULL
	};

	int stdout_fd = -1;
	pid_t pid = os_spawn(argv, &stdout_fd, NULL, NULL);
	if (pid < 0) {
		log_msg(LVL_ERROR, "failed to check updates: spawn failed, errno=%s(%d)", strerror(errno), errno);
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
	int ret = os_wait(pid, &status);
	if (ret == -1) {
		log_msg(LVL_ERROR, "failed to check updates: wait failed, errno=%s(%d)", strerror(errno), errno);
		ss_done(&ss);
		return;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		if (WIFEXITED(status)) {
			log_msg(LVL_ERROR, "failed to check updates: curl exited with code %d", WEXITSTATUS(status));
		} else {
			log_msg(LVL_ERROR, "failed to check updates: curl terminated abnormally");
		}
		ss_done(&ss);
		return;
	}

	char* js = ss_extract(&ss);
	char tag[64];
	if (parse_github_release_tag(js, ss_len(&ss), tag, sizeof(tag)) != 0) {
		log_msg(LVL_ERROR, "failed to check updates: parse failed");
		ss_done(&ss);
		return;
	}
	ss_done(&ss);

	state_lock();
	sncpy(state->global.latest_daemon_version, sizeof(state->global.latest_daemon_version), tag);
	pulse(state, PULSE_ARRAY);
	state_unlock();
}

