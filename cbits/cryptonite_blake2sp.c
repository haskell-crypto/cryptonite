#include "cryptonite_blake2sp.h"

void cryptonite_blake2spp_init(blake2sp_ctx *ctx)
{
  blake2sp_init(ctx, 32);
}

void cryptonite_blake2sp_update(blake2sp_ctx *ctx, const uint8_t *data, uint32_t len)
{
  blake2sp_update(ctx, data, len);
}

void cryptonite_blake2sp_finalize(blake2sp_ctx *ctx, uint8_t *out)
{
  blake2sp_final(ctx, out, 32);
}
