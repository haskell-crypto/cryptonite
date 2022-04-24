#include "cryptonite_blake2bp.h"

void cryptonite_blake2bp_init(blake2bp_ctx *ctx, uint32_t hashlen)
{
	_cryptonite_blake2bp_init(ctx, hashlen / 8);
}

void cryptonite_blake2bp_init_key(blake2bp_ctx *ctx, uint32_t hashlen, const uint8_t *key, size_t keylen)
{
	_cryptonite_blake2bp_init_key(ctx, hashlen / 8, (const void *) key, keylen);
}

void cryptonite_blake2bp_update(blake2bp_ctx *ctx, const uint8_t *data, uint32_t len)
{
	_cryptonite_blake2bp_update(ctx, data, len);
}

void cryptonite_blake2bp_finalize(blake2bp_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	_cryptonite_blake2bp_final(ctx, out, hashlen / 8);
}
