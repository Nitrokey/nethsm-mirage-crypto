// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "fast_defs.h"

typedef uint64_t sha512_word_t;

#define SHA512_BLOCK_BYTE_LEN  128
#define SHA512_ROUNDS_NUM      80
#define SHA512_MSG_END_SYMBOL  (0x80)
#define SHA512_HASH_WORDS_NUM  (SHA512_HASH_BYTE_LEN / sizeof(sha512_word_t))
#define SHA512_BLOCK_WORDS_NUM (SHA512_BLOCK_BYTE_LEN / sizeof(sha512_word_t))

#define SHA512_FINAL_ROUND_START_IDX 64

// The SHA state: parameters a-h
typedef struct sha512_state_st {
  ALIGN(16) sha512_word_t w[SHA512_HASH_WORDS_NUM];
} sha512_state_t;

// This ASM code was borrowed from OpenSSL as is.
extern void sha512_block_data_order_local(IN OUT sha512_word_t *state,
                                          IN const uint8_t *data,
                                          IN size_t         blocks_num);
