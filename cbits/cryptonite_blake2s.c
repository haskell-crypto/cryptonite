#include "cryptonite_blake2s.h"

void cryptonite_blake2s_init(blake2s_ctx *ctx)
{
  blake2s_init(ctx, 32);
}

void cryptonite_blake2s_update(blake2s_ctx *ctx, const uint8_t *data, uint32_t len)
{
  blake2s_update(ctx, data, len);
}

void cryptonite_blake2s_finalize(blake2s_ctx *ctx, uint8_t *out)
{
  blake2s_final(ctx, out, 32);
}
