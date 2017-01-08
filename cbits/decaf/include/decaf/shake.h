/**
 * @file decaf/shake.h
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and CRYPTONITE_DECAF_SHAKE-n instances.
 */

#ifndef __CRYPTONITE_DECAF_SHAKE_H__
#define __CRYPTONITE_DECAF_SHAKE_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h> /* for NULL */

#include <decaf/common.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INTERNAL_SPONGE_STRUCT
    /** Sponge container object for the various primitives. */
    typedef struct cryptonite_decaf_keccak_sponge_s {
        /** @cond internal */
        uint64_t opaque[26];
        /** @endcond */
    } cryptonite_decaf_keccak_sponge_s;

    /** Convenience GMP-style one-element array version */
    typedef struct cryptonite_decaf_keccak_sponge_s cryptonite_decaf_keccak_sponge_t[1];

    /** Parameters for sponge construction, distinguishing CRYPTONITE_DECAF_SHA3 and
     * CRYPTONITE_DECAF_SHAKE instances.
     */
    struct cryptonite_decaf_kparams_s;
#endif

/**
 * @brief Initialize a sponge context object.
 * @param [out] sponge The object to initialize.
 * @param [in] params The sponge's parameter description.
 */
void cryptonite_decaf_sponge_init (
    cryptonite_decaf_keccak_sponge_t sponge,
    const struct cryptonite_decaf_kparams_s *params
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Absorb data into a CRYPTONITE_DECAF_SHA3 or CRYPTONITE_DECAF_SHAKE hash context.
 * @param [inout] sponge The context.
 * @param [in] in The input data.
 * @param [in] len The input data's length in bytes.
 * @return CRYPTONITE_DECAF_FAILURE if the sponge has already been used for output.
 * @return CRYPTONITE_DECAF_SUCCESS otherwise.
 */
cryptonite_decaf_error_t cryptonite_decaf_sha3_update (
    struct cryptonite_decaf_keccak_sponge_s * __restrict__ sponge,
    const uint8_t *in,
    size_t len
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Squeeze output data from a CRYPTONITE_DECAF_SHA3 or CRYPTONITE_DECAF_SHAKE hash context.
 * This does not destroy or re-initialize the hash context, and
 * cryptonite_decaf_sha3 output can be called more times.
 *
 * @param [inout] sponge The context.
 * @param [out] out The output data.
 * @param [in] len The requested output data length in bytes.
 * @return CRYPTONITE_DECAF_FAILURE if the sponge has exhausted its output capacity.
 * @return CRYPTONITE_DECAF_SUCCESS otherwise.
 */  
cryptonite_decaf_error_t cryptonite_decaf_sha3_output (
    cryptonite_decaf_keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Squeeze output data from a CRYPTONITE_DECAF_SHA3 or CRYPTONITE_DECAF_SHAKE hash context.
 * This re-initializes the context to its starting parameters.
 *
 * @param [inout] sponge The context.
 * @param [out] out The output data.
 * @param [in] len The requested output data length in bytes.
 */  
cryptonite_decaf_error_t cryptonite_decaf_sha3_final (
    cryptonite_decaf_keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Reset the sponge to the empty string.
 *
 * @param [inout] sponge The context.
 */  
void cryptonite_decaf_sha3_reset (
    cryptonite_decaf_keccak_sponge_t sponge
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Return the default output length of the sponge construction,
 * for the purpose of C++ default operators.
 *
 * Returns n/8 for CRYPTONITE_DECAF_SHA3-n and 2n/8 for CRYPTONITE_DECAF_SHAKE-n.
 */  
size_t cryptonite_decaf_sponge_default_output_bytes (
    const cryptonite_decaf_keccak_sponge_t sponge /**< [inout] The context. */
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Return the default output length of the sponge construction,
 * for the purpose of C++ default operators.
 *
 * Returns n/8 for CRYPTONITE_DECAF_SHA3-n and SIZE_MAX for CRYPTONITE_DECAF_SHAKE-n.
 */  
size_t cryptonite_decaf_sponge_max_output_bytes (
    const cryptonite_decaf_keccak_sponge_t sponge /**< [inout] The context. */
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Destroy a CRYPTONITE_DECAF_SHA3 or CRYPTONITE_DECAF_SHAKE sponge context by overwriting it with 0.
 * @param [out] sponge The context.
 */  
void cryptonite_decaf_sponge_destroy (
    cryptonite_decaf_keccak_sponge_t sponge
) CRYPTONITE_DECAF_API_VIS;

/**
 * @brief Hash (in) to (out)
 * @param [in] in The input data.
 * @param [in] inlen The length of the input data.
 * @param [out] out A buffer for the output data.
 * @param [in] outlen The length of the output data.
 * @param [in] params The parameters of the sponge hash.
 */  
cryptonite_decaf_error_t cryptonite_decaf_sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct cryptonite_decaf_kparams_s *params
) CRYPTONITE_DECAF_API_VIS;

/* FUTURE: expand/doxygenate individual CRYPTONITE_DECAF_SHAKE/CRYPTONITE_DECAF_SHA3 instances? */

/** @cond internal */
#define CRYPTONITE_DECAF_DEC_SHAKE(n) \
    extern const struct cryptonite_decaf_kparams_s CRYPTONITE_DECAF_SHAKE##n##_params_s CRYPTONITE_DECAF_API_VIS; \
    typedef struct cryptonite_decaf_shake##n##_ctx_s { cryptonite_decaf_keccak_sponge_t s; } cryptonite_decaf_shake##n##_ctx_t[1]; \
    static inline void CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_init(cryptonite_decaf_shake##n##_ctx_t sponge) { \
        cryptonite_decaf_sponge_init(sponge->s, &CRYPTONITE_DECAF_SHAKE##n##_params_s); \
    } \
    static inline void CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_gen_init(cryptonite_decaf_keccak_sponge_t sponge) { \
        cryptonite_decaf_sponge_init(sponge, &CRYPTONITE_DECAF_SHAKE##n##_params_s); \
    } \
    static inline cryptonite_decaf_error_t CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_update(cryptonite_decaf_shake##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        return cryptonite_decaf_sha3_update(sponge->s, in, inlen); \
    } \
    static inline void  CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_final(cryptonite_decaf_shake##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        cryptonite_decaf_sha3_output(sponge->s, out, outlen); \
        cryptonite_decaf_sponge_init(sponge->s, &CRYPTONITE_DECAF_SHAKE##n##_params_s); \
    } \
    static inline void  CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_output(cryptonite_decaf_shake##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        cryptonite_decaf_sha3_output(sponge->s, out, outlen); \
    } \
    static inline void  CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        cryptonite_decaf_sponge_hash(in,inlen,out,outlen,&CRYPTONITE_DECAF_SHAKE##n##_params_s); \
    } \
    static inline void  CRYPTONITE_DECAF_NONNULL cryptonite_decaf_shake##n##_destroy( cryptonite_decaf_shake##n##_ctx_t sponge ) { \
        cryptonite_decaf_sponge_destroy(sponge->s); \
    }

#define CRYPTONITE_DECAF_DEC_SHA3(n) \
    extern const struct cryptonite_decaf_kparams_s CRYPTONITE_DECAF_SHA3_##n##_params_s CRYPTONITE_DECAF_API_VIS; \
    typedef struct cryptonite_decaf_sha3_##n##_ctx_s { cryptonite_decaf_keccak_sponge_t s; } cryptonite_decaf_sha3_##n##_ctx_t[1]; \
    static inline void CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_init(cryptonite_decaf_sha3_##n##_ctx_t sponge) { \
        cryptonite_decaf_sponge_init(sponge->s, &CRYPTONITE_DECAF_SHA3_##n##_params_s); \
    } \
    static inline void CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_gen_init(cryptonite_decaf_keccak_sponge_t sponge) { \
        cryptonite_decaf_sponge_init(sponge, &CRYPTONITE_DECAF_SHA3_##n##_params_s); \
    } \
    static inline cryptonite_decaf_error_t CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_update(cryptonite_decaf_sha3_##n##_ctx_t sponge, const uint8_t *in, size_t inlen ) { \
        return cryptonite_decaf_sha3_update(sponge->s, in, inlen); \
    } \
    static inline cryptonite_decaf_error_t CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_final(cryptonite_decaf_sha3_##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        cryptonite_decaf_error_t ret = cryptonite_decaf_sha3_output(sponge->s, out, outlen); \
        cryptonite_decaf_sponge_init(sponge->s, &CRYPTONITE_DECAF_SHA3_##n##_params_s); \
        return ret; \
    } \
    static inline cryptonite_decaf_error_t CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_output(cryptonite_decaf_sha3_##n##_ctx_t sponge, uint8_t *out, size_t outlen ) { \
        return cryptonite_decaf_sha3_output(sponge->s, out, outlen); \
    } \
    static inline cryptonite_decaf_error_t CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        return cryptonite_decaf_sponge_hash(in,inlen,out,outlen,&CRYPTONITE_DECAF_SHA3_##n##_params_s); \
    } \
    static inline void CRYPTONITE_DECAF_NONNULL cryptonite_decaf_sha3_##n##_destroy(cryptonite_decaf_sha3_##n##_ctx_t sponge) { \
        cryptonite_decaf_sponge_destroy(sponge->s); \
    }
/** @endcond */

CRYPTONITE_DECAF_DEC_SHAKE(128)
CRYPTONITE_DECAF_DEC_SHAKE(256)
CRYPTONITE_DECAF_DEC_SHA3(224)
CRYPTONITE_DECAF_DEC_SHA3(256)
CRYPTONITE_DECAF_DEC_SHA3(384)
CRYPTONITE_DECAF_DEC_SHA3(512)
#undef CRYPTONITE_DECAF_DEC_SHAKE
#undef CRYPTONITE_DECAF_DEC_SHA3

#ifdef __cplusplus
} /* extern "C" */
#endif
    
#endif /* __CRYPTONITE_DECAF_SHAKE_H__ */
