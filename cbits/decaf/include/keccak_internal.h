/**
 * @cond internal
 * @file keccak_internal.h
 * @copyright
 *   Copyright (c) 2016 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Keccak internal interfaces.  Will be used by STROBE once reintegrated.
 */
#ifndef __CRYPTONITE_DECAF_KECCAK_INTERNAL_H__
#define __CRYPTONITE_DECAF_KECCAK_INTERNAL_H__ 1

#include <stdint.h>

/* The internal, non-opaque definition of the cryptonite_decaf_sponge struct. */
typedef union {
    uint64_t w[25]; uint8_t b[25*8];
} kdomain_t[1];

typedef struct cryptonite_decaf_kparams_s {
    uint8_t position, flags, rate, start_round, pad, rate_pad, max_out, remaining;
} cryptonite_decaf_kparams_s, cryptonite_decaf_kparams_t[1];

typedef struct cryptonite_decaf_keccak_sponge_s {
    kdomain_t state;
    cryptonite_decaf_kparams_t params;
} cryptonite_decaf_keccak_sponge_s, cryptonite_decaf_keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1

void __attribute__((noinline)) cryptonite_keccakf(kdomain_t state, uint8_t start_round);

static inline void dokeccak (cryptonite_decaf_keccak_sponge_t cryptonite_decaf_sponge) {
    cryptonite_keccakf(cryptonite_decaf_sponge->state, cryptonite_decaf_sponge->params->start_round);
    cryptonite_decaf_sponge->params->position = 0;
}

#endif /* __CRYPTONITE_DECAF_KECCAK_INTERNAL_H__ */
