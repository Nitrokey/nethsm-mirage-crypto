// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "fast_defs.h"

typedef uint32_t sha256_word_t;

#define SHA256_BLOCK_BYTE_LEN  64
#define SHA256_ROUNDS_NUM      64
#define SHA256_MSG_END_SYMBOL  (0x80)
#define SHA256_HASH_WORDS_NUM  (SHA256_HASH_BYTE_LEN / sizeof(sha256_word_t))
#define SHA256_BLOCK_WORDS_NUM (SHA256_BLOCK_BYTE_LEN / sizeof(sha256_word_t))

#define SHA256_FINAL_ROUND_START_IDX 48

// The SHA state: parameters a-h
typedef ALIGN(16) struct sha256_state_st {
  sha256_word_t w[SHA256_HASH_WORDS_NUM];
} sha256_state_t;

// This ASM code was borrowed from OpenSSL as is.
extern void sha256_block_data_order_local(IN OUT sha256_word_t *state,
                                          IN const uint8_t *data,
                                          IN size_t         blocks_num);
