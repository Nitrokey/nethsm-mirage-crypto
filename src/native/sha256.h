/*
 * Copyright (C) 2006-2009 Vincent Hanquez <vincent@snarc.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CRYPTOHASH_SHA256_H
#define CRYPTOHASH_SHA256_H

#include <stdint.h>
#include "fast_sha256_defs.h"

typedef struct sha256_ctx {
  ALIGN(16) sha256_state_t state;
  uint64_t len;

  ALIGN(16) uint8_t data[2 * SHA256_BLOCK_BYTE_LEN];

  sha256_word_t rem;
} sha256_ctx_t;

#define sha224_ctx             sha256_ctx

#define SHA224_DIGEST_SIZE	28
#define SHA224_CTX_SIZE		sizeof(struct sha224_ctx)

#define SHA256_DIGEST_SIZE	32
#define SHA256_CTX_SIZE		sizeof(struct sha256_ctx)

void _mc_sha224_init(struct sha224_ctx *ctx);
void _mc_sha224_update(struct sha224_ctx *ctx, uint8_t *data, uint32_t len);
void _mc_sha224_finalize(struct sha224_ctx *ctx, uint8_t *out);

void _mc_sha256_init(struct sha256_ctx *ctx);
void _mc_sha256_update(struct sha256_ctx *ctx, uint8_t *data, uint32_t len);
void _mc_sha256_finalize(struct sha256_ctx *ctx, uint8_t *out);

#endif
