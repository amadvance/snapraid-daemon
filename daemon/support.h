// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Andrea Mazzoleni

#ifndef __SUPPORT_H
#define __SUPPORT_H

#include "state.h"
#include "memory.h"
#include "str.h"

/****************************************************************************/
/* mime */

#define MIME_BINARY "application/octet-stream"

/**
 * Get MIME type for a file path based on its extension.
 * @param path File path or name
 * @param is_static If the path should be served with static headers.
 * @return MIME type string. 0 if unknown
 */
const char* get_mime_type(const char* path, int* is_static);

/****************************************************************************/
/* crc32 */

/**
 * Calculates CRC32 for a buffer.
 * Initial CRC should be 0 (or 0xFFFFFFFF if you want to skip XORing in the loop).
 */
uint32_t calculate_crc32(const void* data, size_t length);

/****************************************************************************/
/* unescape */

/*
 * Unescape a JSON string
 */
int json_unescape(const char* src, size_t src_len, char* dst, size_t dst_size);

/****************************************************************************/
/* pulse */

/**
 * Update pulse counters from a task pulse mask.
 * @param state Current snapraid state
 * @param pulse Task pulse structure
 * @return Combined pulse mask
 */
unsigned pulse_rev(struct snapraid_state* state, struct snapraid_pulse* pulse);

/**
 * Trigger a pulse for the specified mask.
 */
void pulse(struct snapraid_state* state, unsigned mask);

/**
 * Convert string to integer and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_strint(struct snapraid_state* state, unsigned mask, int* out, const char* src);

/**
 * Convert string to unsigned integer and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_struint(struct snapraid_state* state, unsigned mask, unsigned* out, const char* src);

/**
 * Convert string to 64-bit integer and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_stri64(struct snapraid_state* state, unsigned mask, int64_t* out, const char* src);

/**
 * Convert string to 64-bit unsigned integer and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_stru64(struct snapraid_state* state, unsigned mask, uint64_t* out, const char* src);

/**
 * Convert string to double and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_double(struct snapraid_state* state, unsigned mask, double* out, const char* src);

/**
 * Update string and trigger pulse if changed.
 * \return -1 on error, 0 if equal, 1 if changed
 */
int pulse_str(struct snapraid_state* state, unsigned mask, char* out, size_t out_size, const char* src);

/****************************************************************************/
/* thread */

/**
 * Thread wrappers to handle error conditions.
 */
void thread_mutex_init(thread_mutex_t* mutex);
void thread_mutex_destroy(thread_mutex_t* mutex);
void thread_mutex_lock(thread_mutex_t* mutex);
void thread_mutex_unlock(thread_mutex_t* mutex);
void thread_cond_init(thread_cond_t* cond);
void thread_cond_destroy(thread_cond_t* cond);
void thread_cond_signal(thread_cond_t* cond);
void thread_cond_broadcast(thread_cond_t* cond);
void thread_cond_wait(thread_cond_t* cond, thread_mutex_t* mutex);
void thread_rwlock_init(thread_rwlock_t* rwlock);
void thread_rwlock_destroy(thread_rwlock_t* rwlock);
void thread_rwlock_rdlock(thread_rwlock_t* rwlock);
void thread_rwlock_wrlock(thread_rwlock_t* rwlock);
void thread_rwlock_unlock(thread_rwlock_t* rwlock);
void thread_create(thread_id_t* thread, void* (*func)(void*), void* arg);
void thread_join(thread_id_t thread, void** retval);
void thread_yield(void);

/****************************************************************************/
/* compression */

#define Z_NONE 0
#define Z_ZLIB 1
#define Z_ZSTD 2

/**
 * Determine supported compression for a connection.
 */
int mg_accept_z(struct mg_connection* conn);

/**
 * Write gzipped data to connection.
 */
int mg_write_gzip(struct mg_connection* conn, const char* src, size_t src_size);

/**
 * Write zstd compressed data to connection.
 */
int mg_write_zstd(struct mg_connection* conn, const char* src, size_t src_size);

#endif

