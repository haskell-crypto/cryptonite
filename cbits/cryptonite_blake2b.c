#include "cryptonite_blake2b.h"

void cryptonite_blake2b_init(blake2b_ctx *ctx, uint32_t hashlen)
{
	_cryptonite_blake2b_init(ctx, hashlen / 8);
}

void cryptonite_blake2b_update(blake2b_ctx *ctx, const uint8_t *data, uint32_t len)
{
	_cryptonite_blake2b_update(ctx, data, len);
}

void cryptonite_blake2b_finalize(blake2b_ctx *ctx, uint32_t hashlen, uint8_t *out)
{
	_cryptonite_blake2b_final(ctx, out, hashlen / 8);
}
