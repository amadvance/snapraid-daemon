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

#ifndef __LOG_H
#define __LOG_H

/****************************************************************************/
/* log */

/**
 * Initialize logging system.
 * @param ident Identifier for log messages
 * @return 0 on success, -1 on error
 */
int log_init(const char* ident);

/**
 * Cleanup logging system.
 */
void log_done(void);

/**
 * Write log message.
 * @param level Log level
 * @param fmt Format string
 * @param ... Format arguments
 */
void log_msg(int level, const char *fmt, ...) __attribute__((format(attribute_printf, 2, 3)));

/**
 * Write log message with state lock held.
 * @param level Log level
 * @param fmt Format string
 * @param ... Format arguments
 */
void log_msg_lock(int level, const char *fmt, ...) __attribute__((format(attribute_printf, 2, 3)));

/**
 * Get string representation of signal number.
 * @param sig Signal number
 * @return Signal name string
 */
const char* signal_name(int sig);

#endif

