#ifndef CRYPTOHASH_BLAKE2SP_H
#define CRYPTOHASH_BLAKE2SP_H

#include "blake2.h"

typedef blake2sp_state blake2sp_ctx;

void cryptonite_blake2sp_init(blake2sp_ctx *ctx, uint32_t hashlen);
void cryptonite_blake2sp_init_key(blake2sp_ctx *ctx, uint32_t hashlen, const uint8_t *key, size_t keylen);
void cryptonite_blake2sp_update(blake2sp_ctx *ctx, const uint8_t *data, uint32_t len);
void cryptonite_blake2sp_finalize(blake2sp_ctx *ctx, uint32_t hashlen, uint8_t *out);

#endif
