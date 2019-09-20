#ifndef ED25519_USING_BLAKE2

#include <cryptonite_sha512.h>
typedef struct sha512_ctx ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx) {
	cryptonite_sha512_init(ctx);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	cryptonite_sha512_update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	cryptonite_sha512_finalize(ctx, hash);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	ed25519_hash_context ctx;
	cryptonite_sha512_init(&ctx);
	cryptonite_sha512_update(&ctx, in, inlen);
	cryptonite_sha512_finalize(&ctx, hash);
	memset(&ctx, 0, sizeof(ctx));
}

#else /* ED25519_USING_BLAKE2 */

#include <cryptonite_blake2b.h>
typedef blake2b_ctx ed25519_hash_context;

static void
ed25519_hash_init(ed25519_hash_context *ctx) {
	cryptonite_blake2b_init(ctx, 512);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	cryptonite_blake2b_update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	cryptonite_blake2b_finalize(ctx, 512, hash);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	ed25519_hash_context ctx;
	cryptonite_blake2b_init(&ctx, 512);
	cryptonite_blake2b_update(&ctx, in, inlen);
	cryptonite_blake2b_finalize(&ctx, 512, hash);
	memset(&ctx, 0, sizeof(ctx));
}

#endif /* ED25519_USING_BLAKE2 */
