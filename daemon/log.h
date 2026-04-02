// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

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
 * Write a generic log message.
 *
 * These messages go in syslog.
 *
 * @param level Log level
 * @param fmt Format string
 * @param ... Format arguments
 */
void log_msg(int level, const char* fmt, ...) __attribute__((format(attribute_printf, 2, 3)));

/**
 * Write a log message generate by a task execution.
 *
 * These messages go both in syslog and in the task log.
 *
 * @param level Log level
 * @param fmt Format string
 * @param ... Format arguments
 */
void log_task(int level, const char* fmt, ...) __attribute__((format(attribute_printf, 2, 3)));

/**
 * Clear previously stored task logs because a new task starts
 */
void log_task_reset(void);

/**
 * Move stored task logs into the task message list.
 */
void log_task_push(tommy_list* message_list);

/**
 * Get string representation of signal number.
 * @param sig Signal number
 * @return Signal name string
 */
const char* signal_name(int sig);

#endif

