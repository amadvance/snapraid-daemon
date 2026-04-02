// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __REST_H
#define __REST_H

#include "state.h"

/****************************************************************************/
/* rest */

/**
 * Initialize REST API server.
 * @param state Current snapraid state
 * @return 0 on success, -1 on error
 */
int rest_init(struct snapraid_state* state);

/**
 * Cleanup REST API server.
 * @param state Current snapraid state
 */
void rest_done(struct snapraid_state* state);

#endif

