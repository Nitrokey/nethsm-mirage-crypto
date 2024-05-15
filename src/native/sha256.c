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

#include <assert.h>

#include "fast_sha256_defs.h"
#include "sha256.h"

_INLINE_ void sha224_init(OUT sha256_ctx_t *ctx)
{
  ctx->state.w[0] = UINT32_C(0xc1059ed8);
  ctx->state.w[1] = UINT32_C(0x367cd507);
  ctx->state.w[2] = UINT32_C(0x3070dd17);
  ctx->state.w[3] = UINT32_C(0xf70e5939);
  ctx->state.w[4] = UINT32_C(0xffc00b31);
  ctx->state.w[5] = UINT32_C(0x68581511);
  ctx->state.w[6] = UINT32_C(0x64f98fa7);
  ctx->state.w[7] = UINT32_C(0xbefa4fa4);
}

_INLINE_ void sha256_init(OUT sha256_ctx_t *ctx)
{
  ctx->state.w[0] = UINT32_C(0x6a09e667);
  ctx->state.w[1] = UINT32_C(0xbb67ae85);
  ctx->state.w[2] = UINT32_C(0x3c6ef372);
  ctx->state.w[3] = UINT32_C(0xa54ff53a);
  ctx->state.w[4] = UINT32_C(0x510e527f);
  ctx->state.w[5] = UINT32_C(0x9b05688c);
  ctx->state.w[6] = UINT32_C(0x1f83d9ab);
  ctx->state.w[7] = UINT32_C(0x5be0cd19);
}

_INLINE_ void sha256_compress(IN OUT sha256_ctx_t *ctx,
                              IN const uint8_t *data,
                              IN const size_t   blocks_num)
{
  assert((ctx != NULL) && (data != NULL));

  // OpenSSL code can crash without this check
  if(blocks_num == 0) {
    return;
  }

  RUN_OPENSSL_CODE_WITH_AVX2(
        sha256_block_data_order_local(ctx->state.w, data, blocks_num););
}

_INLINE_ void sha256_update(IN OUT sha256_ctx_t *ctx,
                            IN const uint8_t *data,
                            IN size_t         byte_len)
{
  // On exiting this function ctx->rem < SHA256_BLOCK_BYTE_LEN

  assert((ctx != NULL) && (data != NULL));

  if(byte_len == 0) {
    return;
  }

  // Accumulate the overall size
  ctx->len += byte_len;

  // Less than a block. Store the data in a temporary buffer
  if((ctx->rem != 0) && ((ctx->rem + byte_len) < SHA256_BLOCK_BYTE_LEN)) {
    my_memcpy(&ctx->data[ctx->rem], data, byte_len);
    ctx->rem += byte_len;
    return;
  }

  // Complete and compress a previously stored block
  if(ctx->rem != 0) {
    const size_t clen = SHA256_BLOCK_BYTE_LEN - ctx->rem;
    my_memcpy(&ctx->data[ctx->rem], data, clen);
    sha256_compress(ctx, ctx->data, 1);

    data += clen;
    byte_len -= clen;

    ctx->rem = 0;
    secure_clean(ctx->data, SHA256_BLOCK_BYTE_LEN);
  }

  // Compress full blocks
  if(byte_len >= SHA256_BLOCK_BYTE_LEN) {
    const size_t blocks_num           = (byte_len >> 6);
    const size_t full_blocks_byte_len = (blocks_num << 6);

    sha256_compress(ctx, data, blocks_num);

    data += full_blocks_byte_len;
    byte_len -= full_blocks_byte_len;
  }

  // Store the reminder
  my_memcpy(ctx->data, data, byte_len);
  ctx->rem = byte_len;
}

_INLINE_ void sha256_final(OUT uint8_t *dgst, IN OUT sha256_ctx_t *ctx)
{
  assert((ctx != NULL) && (dgst != NULL));
  assert(ctx->rem < SHA256_BLOCK_BYTE_LEN);

  // Byteswap the length in bits of the hashed message
  const uint64_t bswap_len      = bswap_64(8 * ctx->len);
  const size_t   last_block_num = (ctx->rem < 56) ? 1 : 2;
  const size_t   last_qw_pos =
    (last_block_num * SHA256_BLOCK_BYTE_LEN) - sizeof(bswap_len);

  ctx->data[ctx->rem++] = SHA256_MSG_END_SYMBOL;

  // Reset the rest of the data buffer
  my_memset(&ctx->data[ctx->rem], 0, sizeof(ctx->data) - ctx->rem);
  my_memcpy(&ctx->data[last_qw_pos], (const uint8_t *)&bswap_len,
            sizeof(bswap_len));

  // Compress the final block
  sha256_compress(ctx, ctx->data, last_block_num);

  // This implementation assumes running on a Little endian machine
  ctx->state.w[0] = bswap_32(ctx->state.w[0]);
  ctx->state.w[1] = bswap_32(ctx->state.w[1]);
  ctx->state.w[2] = bswap_32(ctx->state.w[2]);
  ctx->state.w[3] = bswap_32(ctx->state.w[3]);
  ctx->state.w[4] = bswap_32(ctx->state.w[4]);
  ctx->state.w[5] = bswap_32(ctx->state.w[5]);
  ctx->state.w[6] = bswap_32(ctx->state.w[6]);
  ctx->state.w[7] = bswap_32(ctx->state.w[7]);
  my_memcpy(dgst, &ctx->state, SHA256_HASH_BYTE_LEN);

  secure_clean(ctx, sizeof(*ctx));
}


void _mc_sha224_init(struct sha224_ctx *ctx)
{
  sha224_init(ctx);
}

void _mc_sha256_init(struct sha256_ctx *ctx)
{
  sha256_init(ctx);
}


void _mc_sha256_update(struct sha256_ctx *ctx, uint8_t *data, uint32_t len)
{
  sha256_update(ctx, data, len);
}
void _mc_sha224_update(struct sha224_ctx *ctx, uint8_t *data, uint32_t len)
{
	_mc_sha256_update(ctx, data, len);
}


void _mc_sha256_finalize(struct sha256_ctx *ctx, uint8_t *out)
{
  sha256_final(out, ctx);
}

void _mc_sha224_finalize(struct sha224_ctx *ctx, uint8_t *out)
{
	uint8_t intermediate[SHA256_DIGEST_SIZE];

	_mc_sha256_finalize(ctx, intermediate);
	memcpy(out, intermediate, SHA224_DIGEST_SIZE);
}
