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

#include "fast_sha512_defs.h"
#include "sha512.h"


_INLINE_ void sha384_init(OUT sha512_ctx_t *ctx)
{
  ctx->state.w[0] = UINT64_C(0xcbbb9d5dc1059ed8);
  ctx->state.w[1] = UINT64_C(0x629a292a367cd507);
  ctx->state.w[2] = UINT64_C(0x9159015a3070dd17);
  ctx->state.w[3] = UINT64_C(0x152fecd8f70e5939);
  ctx->state.w[4] = UINT64_C(0x67332667ffc00b31);
  ctx->state.w[5] = UINT64_C(0x8eb44a8768581511);
  ctx->state.w[6] = UINT64_C(0xdb0c2e0d64f98fa7);
  ctx->state.w[7] = UINT64_C(0x47b5481dbefa4fa4);
}

_INLINE_ void sha512_init(OUT sha512_ctx_t *ctx)
{
  ctx->state.w[0] = UINT64_C(0x6a09e667f3bcc908);
  ctx->state.w[1] = UINT64_C(0xbb67ae8584caa73b);
  ctx->state.w[2] = UINT64_C(0x3c6ef372fe94f82b);
  ctx->state.w[3] = UINT64_C(0xa54ff53a5f1d36f1);
  ctx->state.w[4] = UINT64_C(0x510e527fade682d1);
  ctx->state.w[5] = UINT64_C(0x9b05688c2b3e6c1f);
  ctx->state.w[6] = UINT64_C(0x1f83d9abfb41bd6b);
  ctx->state.w[7] = UINT64_C(0x5be0cd19137e2179);
}

_INLINE_ void sha512_compress(IN OUT sha512_ctx_t *ctx,
                              IN const uint8_t *data,
                              IN const size_t   blocks_num)
{
  assert((ctx != NULL) && (data != NULL));

  // OpenSSL code can crash without this check
  if(blocks_num == 0) {
    return;
  }

  RUN_OPENSSL_CODE_WITH_AVX2(
    sha512_block_data_order_local(ctx->state.w, data, blocks_num););
}

_INLINE_ void sha512_update(IN OUT sha512_ctx_t *ctx,
                            IN const uint8_t *data,
                            IN size_t         byte_len)
{
  // On exiting this function ctx->rem < SHA512_BLOCK_BYTE_LEN

  assert((ctx != NULL) && (data != NULL));

  if(byte_len == 0) {
    return;
  }

  // Accumulate the overall size
  ctx->len += byte_len;

  // Less than a block. Store the data in a temporary buffer
  if((ctx->rem != 0) && (ctx->rem + byte_len < SHA512_BLOCK_BYTE_LEN)) {
    my_memcpy(&ctx->data[ctx->rem], data, byte_len);
    ctx->rem += byte_len;
    return;
  }

  // Complete and compress a previously stored block
  if(ctx->rem != 0) {
    const size_t clen = SHA512_BLOCK_BYTE_LEN - ctx->rem;
    my_memcpy(&ctx->data[ctx->rem], data, clen);
    sha512_compress(ctx, ctx->data, 1);

    data += clen;
    byte_len -= clen;

    ctx->rem = 0;
    secure_clean(ctx->data, SHA512_BLOCK_BYTE_LEN);
  }

  // Compress full blocks
  if(byte_len >= SHA512_BLOCK_BYTE_LEN) {
    const size_t blocks_num           = (byte_len >> 7);
    const size_t full_blocks_byte_len = (blocks_num << 7);

    sha512_compress(ctx, data, blocks_num);

    data += full_blocks_byte_len;
    byte_len -= full_blocks_byte_len;
  }

  // Store the reminder
  my_memcpy(ctx->data, data, byte_len);
  ctx->rem = byte_len;
}

_INLINE_ void sha512_final(OUT uint8_t *dgst, IN OUT sha512_ctx_t *ctx)
{
  assert((ctx != NULL) && (dgst != NULL));
  assert(ctx->rem < SHA512_BLOCK_BYTE_LEN);

  // Byteswap the length in bits of the hashed message
  const uint64_t bswap_len      = bswap_64(8 * ctx->len);
  const size_t   last_block_num = (ctx->rem < 112) ? 1 : 2;
  const size_t   last_qw_pos =
    (last_block_num * SHA512_BLOCK_BYTE_LEN) - sizeof(bswap_len);

  ctx->data[ctx->rem++] = SHA512_MSG_END_SYMBOL;

  // Reset the rest of the data buffer
  my_memset(&ctx->data[ctx->rem], 0, sizeof(ctx->data) - ctx->rem);
  my_memcpy(&ctx->data[last_qw_pos], (const uint8_t *)&bswap_len,
            sizeof(bswap_len));

  // Compress the final block
  sha512_compress(ctx, ctx->data, last_block_num);

  // This implementation assumes running on a Little endian machine
  ctx->state.w[0] = bswap_64(ctx->state.w[0]);
  ctx->state.w[1] = bswap_64(ctx->state.w[1]);
  ctx->state.w[2] = bswap_64(ctx->state.w[2]);
  ctx->state.w[3] = bswap_64(ctx->state.w[3]);
  ctx->state.w[4] = bswap_64(ctx->state.w[4]);
  ctx->state.w[5] = bswap_64(ctx->state.w[5]);
  ctx->state.w[6] = bswap_64(ctx->state.w[6]);
  ctx->state.w[7] = bswap_64(ctx->state.w[7]);
  my_memcpy(dgst, ctx->state.w, SHA512_HASH_BYTE_LEN);

  secure_clean(ctx, sizeof(*ctx));
}


void _mc_sha384_init(struct sha512_ctx *ctx)
{
  sha384_init(ctx);
}

void _mc_sha512_init(struct sha512_ctx *ctx)
{
  sha512_init(ctx);
}


void _mc_sha384_update(struct sha384_ctx *ctx, uint8_t *data, uint32_t len)
{
	_mc_sha512_update(ctx, data, len);
}

void _mc_sha512_update(struct sha512_ctx *ctx, uint8_t *data, uint32_t len)
{
  sha512_update(ctx, data, len);
}

void _mc_sha384_finalize(struct sha384_ctx *ctx, uint8_t *out)
{
	uint8_t intermediate[SHA512_DIGEST_SIZE];

	_mc_sha512_finalize(ctx, intermediate);
	memcpy(out, intermediate, SHA384_DIGEST_SIZE);
}

void _mc_sha512_finalize(struct sha512_ctx *ctx, uint8_t *out)
{
  sha512_final(out, ctx);
}
