// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __REST_H
#define __REST_H

#include "state.h"

/****************************************************************************/
/* rest */

/**
 * Initialize REST API server using explicit network configuration parameters.
 * @param state Current snapraid state
 * @param net_enabled Network server enable flag
 * @param net_port Network listening port string
 * @param net_acl Access control list string
 * @return 0 on success, -1 on error
 */
int rest_init(struct snapraid_state* state, int net_enabled, const char* net_port, const char* net_acl);

/**
 * Cleanup REST API server using explicit network enable flag.
 * @param state Current snapraid state
 * @param net_enabled Network server enable flag
 */
void rest_done(struct snapraid_state* state, int net_enabled);

/**
 * Reload REST API server (restart if needed due to config change).
 * Must be called without holding state_lock.
 * @param state Current snapraid state
 * @param prev_net_enabled Previous network server enable flag
 * @param net_enabled New network server enable flag
 * @param net_port New network listening port string
 * @param net_acl New access control list string
 * @return 0 on success, -1 on error
 */
int rest_reload(struct snapraid_state* state, int prev_net_enabled, int net_enabled, const char* net_port, const char* net_acl);

#endif

