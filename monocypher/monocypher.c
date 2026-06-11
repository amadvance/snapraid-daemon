// Monocypher version __git__
//
// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2017-2020, Loup Vaillant
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2017-2020 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "monocypher.h"

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)

#define FOR(i, start, end)         FOR_T(size_t, i, start, end)

#define COPY(dst, src, size)       FOR(_i_, 0, size) (dst)[_i_] = (src)[_i_]

#define ZERO(buf, size)            FOR(_i_, 0, size) (buf)[_i_] = 0

#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))

#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))

#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))

#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))

typedef int8_t   i8;

typedef uint8_t  u8;

typedef int16_t  i16;

typedef uint32_t u32;

typedef int32_t  i32;

typedef int64_t  i64;

typedef uint64_t u64;

static size_t gap(size_t x, size_t pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static u32 load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
	out[0] = (u8)(in      );
	out[1] = (u8)(in >>  8);
	out[2] = (u8)(in >> 16);
	out[3] = (u8)(in >> 24);
}

static void store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)(in      ));
	store32_le(out + 4, (u32)(in >> 32));
}

static void load64_le_buf (u64 *dst, const u8 *src, size_t size) {
	FOR(i, 0, size) { dst[i] = load64_le(src + i*8); }
}

static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
	FOR(i, 0, size) { store64_le(dst + i*8, src[i]); }
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }

static int neq0(u64 diff)
{
	// constant time comparison to zero
	// return diff != 0 ? -1 : 0
	u64 half = (diff >> 32) | ((u32)diff);  // half < 2^32
	u64 eq0  = 1 & ((half - 1) >> 32);      // half == 0 ? 1 : 0
	return (int)eq0 - 1;                    // half == 0 ? 0 : -1
}

static u64 x16(const u8 a[16], const u8 b[16])
{
	return (load64_le(a + 0) ^ load64_le(b + 0))
		|  (load64_le(a + 8) ^ load64_le(b + 8));
}

static u64 x32(const u8 a[32],const u8 b[32]){return x16(a,b)| x16(a+16, b+16);}

int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }

void crypto_wipe(void *secret, size_t size)
{
	volatile u8 *v_secret = (u8*)secret;
	ZERO(v_secret, size);
}

static const u64 iv[8] = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block)
{
	static const u8 sigma[12][16] = {
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
		{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
		{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
		{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
		{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
		{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
		{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
		{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
		{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
		{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	};

	// increment input offset
	u64   *x = ctx->input_offset;
	size_t y = ctx->input_idx;
	x[0] += y;
	if (x[0] < y) {
		x[1]++;
	}

	// init work vector
	u64 v0 = ctx->hash[0];  u64 v8  = iv[0];
	u64 v1 = ctx->hash[1];  u64 v9  = iv[1];
	u64 v2 = ctx->hash[2];  u64 v10 = iv[2];
	u64 v3 = ctx->hash[3];  u64 v11 = iv[3];
	u64 v4 = ctx->hash[4];  u64 v12 = iv[4] ^ ctx->input_offset[0];
	u64 v5 = ctx->hash[5];  u64 v13 = iv[5] ^ ctx->input_offset[1];
	u64 v6 = ctx->hash[6];  u64 v14 = iv[6] ^ (u64)~(is_last_block - 1);
	u64 v7 = ctx->hash[7];  u64 v15 = iv[7];

	// mangle work vector
	u64 *input = ctx->input;
#define BLAKE2_G(a, b, c, d, x, y)	\
	a += b + x;  d = rotr64(d ^ a, 32); \
	c += d;      b = rotr64(b ^ c, 24); \
	a += b + y;  d = rotr64(d ^ a, 16); \
	c += d;      b = rotr64(b ^ c, 63)
#define BLAKE2_ROUND(i)	\
	BLAKE2_G(v0, v4, v8 , v12, input[sigma[i][ 0]], input[sigma[i][ 1]]); \
	BLAKE2_G(v1, v5, v9 , v13, input[sigma[i][ 2]], input[sigma[i][ 3]]); \
	BLAKE2_G(v2, v6, v10, v14, input[sigma[i][ 4]], input[sigma[i][ 5]]); \
	BLAKE2_G(v3, v7, v11, v15, input[sigma[i][ 6]], input[sigma[i][ 7]]); \
	BLAKE2_G(v0, v5, v10, v15, input[sigma[i][ 8]], input[sigma[i][ 9]]); \
	BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]); \
	BLAKE2_G(v2, v7, v8 , v13, input[sigma[i][12]], input[sigma[i][13]]); \
	BLAKE2_G(v3, v4, v9 , v14, input[sigma[i][14]], input[sigma[i][15]])

#ifdef BLAKE2_NO_UNROLLING
	FOR (i, 0, 12) {
		BLAKE2_ROUND(i);
	}
#else
	BLAKE2_ROUND(0);  BLAKE2_ROUND(1);  BLAKE2_ROUND(2);  BLAKE2_ROUND(3);
	BLAKE2_ROUND(4);  BLAKE2_ROUND(5);  BLAKE2_ROUND(6);  BLAKE2_ROUND(7);
	BLAKE2_ROUND(8);  BLAKE2_ROUND(9);  BLAKE2_ROUND(10); BLAKE2_ROUND(11);
#endif

	// update hash
	ctx->hash[0] ^= v0 ^ v8;   ctx->hash[1] ^= v1 ^ v9;
	ctx->hash[2] ^= v2 ^ v10;  ctx->hash[3] ^= v3 ^ v11;
	ctx->hash[4] ^= v4 ^ v12;  ctx->hash[5] ^= v5 ^ v13;
	ctx->hash[6] ^= v6 ^ v14;  ctx->hash[7] ^= v7 ^ v15;
}

void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const u8 *key, size_t key_size)
{
	// initial hash
	COPY(ctx->hash, iv, 8);
	ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

	ctx->input_offset[0] = 0;  // beginning of the input, no offset
	ctx->input_offset[1] = 0;  // beginning of the input, no offset
	ctx->hash_size       = hash_size;
	ctx->input_idx       = 0;
	ZERO(ctx->input, 16);

	// if there is a key, the first block is that key (padded with zeroes)
	if (key_size > 0) {
		u8 key_block[128] = {0};
		COPY(key_block, key, key_size);
		// same as calling crypto_blake2b_update(ctx, key_block , 128)
		load64_le_buf(ctx->input, key_block, 16);
		ctx->input_idx = 128;
		WIPE_BUFFER(key_block);
	}
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size)
{
	crypto_blake2b_keyed_init(ctx, hash_size, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
	// Avoid undefined NULL pointer increments with empty messages
	if (message_size == 0) {
		return;
	}

	// Align with word boundaries
	if ((ctx->input_idx & 7) != 0) {
		size_t nb_bytes = MIN(gap(ctx->input_idx, 8), message_size);
		size_t word     = ctx->input_idx >> 3;
		size_t byte     = ctx->input_idx & 7;
		FOR (i, 0, nb_bytes) {
			ctx->input[word] |= (u64)message[i] << ((byte + i) << 3);
		}
		ctx->input_idx += nb_bytes;
		message        += nb_bytes;
		message_size   -= nb_bytes;
	}

	// Align with block boundaries (faster than byte by byte)
	if ((ctx->input_idx & 127) != 0) {
		size_t nb_words = MIN(gap(ctx->input_idx, 128), message_size) >> 3;
		load64_le_buf(ctx->input + (ctx->input_idx >> 3), message, nb_words);
		ctx->input_idx += nb_words << 3;
		message        += nb_words << 3;
		message_size   -= nb_words << 3;
	}

	// Process block by block
	size_t nb_blocks = message_size >> 7;
	FOR (i, 0, nb_blocks) {
		if (ctx->input_idx == 128) {
			blake2b_compress(ctx, 0);
		}
		load64_le_buf(ctx->input, message, 16);
		message += 128;
		ctx->input_idx = 128;
	}
	message_size &= 127;

	if (message_size != 0) {
		// Compress block & flush input buffer as needed
		if (ctx->input_idx == 128) {
			blake2b_compress(ctx, 0);
			ctx->input_idx = 0;
		}
		if (ctx->input_idx == 0) {
			ZERO(ctx->input, 16);
		}
		// Fill remaining words (faster than byte by byte)
		size_t nb_words = message_size >> 3;
		load64_le_buf(ctx->input, message, nb_words);
		ctx->input_idx += nb_words << 3;
		message        += nb_words << 3;
		message_size   -= nb_words << 3;

		// Fill remaining bytes
		FOR (i, 0, message_size) {
			size_t word = ctx->input_idx >> 3;
			size_t byte = ctx->input_idx & 7;
			ctx->input[word] |= (u64)message[i] << (byte << 3);
			ctx->input_idx++;
		}
	}
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash)
{
	blake2b_compress(ctx, 1); // compress the last block
	size_t hash_size = MIN(ctx->hash_size, 64);
	size_t nb_words  = hash_size >> 3;
	store64_le_buf(hash, ctx->hash, nb_words);
	FOR (i, nb_words << 3, hash_size) {
		hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
	}
	WIPE_CTX(ctx);
}

void crypto_blake2b_keyed(u8 *hash,          size_t hash_size,
                          const u8 *key,     size_t key_size,
                          const u8 *message, size_t message_size)
{
	crypto_blake2b_ctx ctx;
	crypto_blake2b_keyed_init(&ctx, hash_size, key, key_size);
	crypto_blake2b_update    (&ctx, message, message_size);
	crypto_blake2b_final     (&ctx, hash);
}

void crypto_blake2b(u8 *hash, size_t hash_size, const u8 *msg, size_t msg_size)
{
	crypto_blake2b_keyed(hash, hash_size, 0, 0, msg, msg_size);
}

typedef struct { u64 a[128]; } blk;

static void blake_update_32(crypto_blake2b_ctx *ctx, u32 input)
{
	u8 buf[4];
	store32_le(buf, input);
	crypto_blake2b_update(ctx, buf, 4);
	WIPE_BUFFER(buf);
}

static void blake_update_32_buf(crypto_blake2b_ctx *ctx,
                                const u8 *buf, u32 size)
{
	blake_update_32(ctx, size);
	crypto_blake2b_update(ctx, buf, size);
}

static void copy_block(blk *o,const blk*in){FOR(i, 0, 128) o->a[i]  = in->a[i];}

static void  xor_block(blk *o,const blk*in){FOR(i, 0, 128) o->a[i] ^= in->a[i];}

static void extended_hash(u8       *digest, u32 digest_size,
                          const u8 *input , u32 input_size)
{
	crypto_blake2b_ctx ctx;
	crypto_blake2b_init  (&ctx, MIN(digest_size, 64));
	blake_update_32      (&ctx, digest_size);
	crypto_blake2b_update(&ctx, input, input_size);
	crypto_blake2b_final (&ctx, digest);

	if (digest_size > 64) {
		// the conversion to u64 avoids integer overflow on
		// ludicrously big hash sizes.
		u32 r   = (u32)(((u64)digest_size + 31) >> 5) - 2;
		u32 i   =  1;
		u32 in  =  0;
		u32 out = 32;
		while (i < r) {
			// Input and output overlap. This is intentional
			crypto_blake2b(digest + out, 64, digest + in, 64);
			i   +=  1;
			in  += 32;
			out += 32;
		}
		crypto_blake2b(digest + out, digest_size - (32 * r), digest + in , 64);
	}
}

#define LSB(x) ((u64)(u32)x)

#define G(a, b, c, d)	\
	a += b + ((LSB(a) * LSB(b)) << 1);  d ^= a;  d = rotr64(d, 32); \
	c += d + ((LSB(c) * LSB(d)) << 1);  b ^= c;  b = rotr64(b, 24); \
	a += b + ((LSB(a) * LSB(b)) << 1);  d ^= a;  d = rotr64(d, 16); \
	c += d + ((LSB(c) * LSB(d)) << 1);  b ^= c;  b = rotr64(b, 63)

#define ROUND(v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,	\
              v8,  v9, v10, v11, v12, v13, v14, v15)	\
	G(v0, v4,  v8, v12);  G(v1, v5,  v9, v13); \
	G(v2, v6, v10, v14);  G(v3, v7, v11, v15); \
	G(v0, v5, v10, v15);  G(v1, v6, v11, v12); \
	G(v2, v7,  v8, v13);  G(v3, v4,  v9, v14)

static void g_rounds(blk *b)
{
	// column rounds (work_block = Q)
	for (int i = 0; i < 128; i += 16) {
		ROUND(b->a[i   ], b->a[i+ 1], b->a[i+ 2], b->a[i+ 3],
		      b->a[i+ 4], b->a[i+ 5], b->a[i+ 6], b->a[i+ 7],
		      b->a[i+ 8], b->a[i+ 9], b->a[i+10], b->a[i+11],
		      b->a[i+12], b->a[i+13], b->a[i+14], b->a[i+15]);
	}
	// row rounds (b = Z)
	for (int i = 0; i < 16; i += 2) {
		ROUND(b->a[i   ], b->a[i+ 1], b->a[i+ 16], b->a[i+ 17],
		      b->a[i+32], b->a[i+33], b->a[i+ 48], b->a[i+ 49],
		      b->a[i+64], b->a[i+65], b->a[i+ 80], b->a[i+ 81],
		      b->a[i+96], b->a[i+97], b->a[i+112], b->a[i+113]);
	}
}

const crypto_argon2_extras crypto_argon2_no_extras = { 0, 0, 0, 0 };

void crypto_argon2(u8 *hash, u32 hash_size, void *work_area,
                   crypto_argon2_config config,
                   crypto_argon2_inputs inputs,
                   crypto_argon2_extras extras)
{
	const u32 segment_size = config.nb_blocks / config.nb_lanes / 4;
	const u32 lane_size    = segment_size * 4;
	const u32 nb_blocks    = lane_size * config.nb_lanes; // rounding down

	// work area seen as blocks (must be suitably aligned)
	blk *blocks = (blk*)work_area;
	{
		u8 initial_hash[72]; // 64 bytes plus 2 words for future hashes
		crypto_blake2b_ctx ctx;
		crypto_blake2b_init (&ctx, 64);
		blake_update_32     (&ctx, config.nb_lanes ); // p: number of "threads"
		blake_update_32     (&ctx, hash_size);
		blake_update_32     (&ctx, config.nb_blocks);
		blake_update_32     (&ctx, config.nb_passes);
		blake_update_32     (&ctx, 0x13);             // v: version number
		blake_update_32     (&ctx, config.algorithm); // y: Argon2i, Argon2d...
		blake_update_32_buf (&ctx, inputs.pass, inputs.pass_size);
		blake_update_32_buf (&ctx, inputs.salt, inputs.salt_size);
		blake_update_32_buf (&ctx, extras.key,  extras.key_size);
		blake_update_32_buf (&ctx, extras.ad,   extras.ad_size);
		crypto_blake2b_final(&ctx, initial_hash); // fill 64 first bytes only

		// fill first 2 blocks of each lane
		u8 hash_area[1024];
		FOR_T(u32, l, 0, config.nb_lanes) {
			FOR_T(u32, i, 0, 2) {
				store32_le(initial_hash + 64, i); // first  additional word
				store32_le(initial_hash + 68, l); // second additional word
				extended_hash(hash_area, 1024, initial_hash, 72);
				load64_le_buf(blocks[l * lane_size + i].a, hash_area, 128);
			}
		}

		WIPE_BUFFER(initial_hash);
		WIPE_BUFFER(hash_area);
	}

	// Argon2i and Argon2id start with constant time indexing
	int constant_time = config.algorithm != CRYPTO_ARGON2_D;

	// Fill (and re-fill) the rest of the blocks
	//
	// Note: even though each segment within the same slice can be
	// computed in parallel, (one thread per lane), we are computing
	// them sequentially, because Monocypher doesn't support threads.
	//
	// Yet optimal performance (and therefore security) requires one
	// thread per lane. The only reason Monocypher supports multiple
	// lanes is compatibility.
	blk tmp;
	FOR_T(u32, pass, 0, config.nb_passes) {
		FOR_T(u32, slice, 0, 4) {
			// On the first slice of the first pass,
			// blocks 0 and 1 are already filled, hence pass_offset.
			u32 pass_offset  = pass == 0 && slice == 0 ? 2 : 0;
			u32 slice_offset = slice * segment_size;

			// Argon2id switches back to non-constant time indexing
			// after the first two slices of the first pass
			if (slice == 2 && config.algorithm == CRYPTO_ARGON2_ID) {
				constant_time = 0;
			}

			// Each iteration of the following loop may be performed in
			// a separate thread.  All segments must be fully completed
			// before we start filling the next slice.
			FOR_T(u32, segment, 0, config.nb_lanes) {
				blk index_block;
				u32 index_ctr = 1;
				FOR_T (u32, block, pass_offset, segment_size) {
					// Current and previous blocks
					u32  lane_offset   = segment * lane_size;
					blk *segment_start = blocks + lane_offset + slice_offset;
					blk *current       = segment_start + block;
					blk *previous      =
						block == 0 && slice_offset == 0
						? segment_start + lane_size - 1
						: segment_start + block - 1;

					u64 index_seed;
					if (constant_time) {
						if (block == pass_offset || (block % 128) == 0) {
							// Fill or refresh deterministic indices block

							// seed the beginning of the block...
							ZERO(index_block.a, 128);
							index_block.a[0] = pass;
							index_block.a[1] = segment;
							index_block.a[2] = slice;
							index_block.a[3] = nb_blocks;
							index_block.a[4] = config.nb_passes;
							index_block.a[5] = config.algorithm;
							index_block.a[6] = index_ctr;
							index_ctr++;

							// ... then shuffle it
							copy_block(&tmp, &index_block);
							g_rounds  (&index_block);
							xor_block (&index_block, &tmp);
							copy_block(&tmp, &index_block);
							g_rounds  (&index_block);
							xor_block (&index_block, &tmp);
						}
						index_seed = index_block.a[block % 128];
					} else {
						index_seed = previous->a[0];
					}

					// Establish the reference set.  *Approximately* comprises:
					// - The last 3 slices (if they exist yet)
					// - The already constructed blocks in the current segment
					u32 next_slice   = ((slice + 1) % 4) * segment_size;
					u32 window_start = pass == 0 ? 0     : next_slice;
					u32 nb_segments  = pass == 0 ? slice : 3;
					u32 lane         =
						pass == 0 && slice == 0
						? segment
						: (u32)(index_seed >> 32) % config.nb_lanes;
					u32 window_size  =
						nb_segments * segment_size +
						(lane  == segment ? block-1 :
						 block == 0       ? (u32)-1 : 0);

					// Find reference block
					u64  j1        = index_seed & 0xffffffff; // block selector
					u64  x         = (j1 * j1)         >> 32;
					u64  y         = (window_size * x) >> 32;
					u64  z         = (window_size - 1) - y;
					u32  ref       = (u32)((window_start + z) % lane_size);
					u32  index     = lane * lane_size + ref;
					blk *reference = blocks + index;

					// Shuffle the previous & reference block
					// into the current block
					copy_block(&tmp, previous);
					xor_block (&tmp, reference);
					if (pass == 0) { copy_block(current, &tmp); }
					else           { xor_block (current, &tmp); }
					g_rounds  (&tmp);
					xor_block (current, &tmp);
				}
			}
		}
	}

	// Wipe temporary block
	volatile u64* p = tmp.a;
	ZERO(p, 128);

	// XOR last blocks of each lane
	blk *last_block = blocks + lane_size - 1;
	FOR_T (u32, lane, 1, config.nb_lanes) {
		blk *next_block = last_block + lane_size;
		xor_block(next_block, last_block);
		last_block = next_block;
	}

	// Serialize last block
	u8 final_block[1024];
	store64_le_buf(final_block, last_block->a, 128);

	// Wipe work area
	p = (u64*)work_area;
	ZERO(p, 128 * nb_blocks);

	// Hash the very last block with H' into the output hash
	extended_hash(hash, hash_size, final_block, 1024);
	WIPE_BUFFER(final_block);
}
