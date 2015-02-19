/**
 * @file shake.h
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#ifndef __SHAKE_H__
#define __SHAKE_H__

#include <stdint.h>

#ifndef INTERNAL_SPONGE_STRUCT
    typedef struct keccak_sponge_s {
        uint64_t opaque[26];
    } keccak_sponge_t[1];
    struct kparams_s;
#endif

/**
 * @brief Initialize a sponge context object.
 * @param [out] sponge The object to initialize.
 * @param [in] params The sponge's parameter description.
 */
void sponge_init (
    keccak_sponge_t sponge,
    const struct kparams_s *params
);

/**
 * @brief Absorb data into a SHA3 or SHAKE hash context.
 * @param [inout] sponge The context.
 * @param [in] in The input data.
 * @param [in] len The input data's length in bytes.
 */
void sha3_update (
    struct keccak_sponge_s * __restrict__ sponge,
    const uint8_t *in,
    size_t len
);

/**
 * @brief Squeeze output data from a SHA3 or SHAKE hash context.
 * This does not destroy or re-initialize the hash context, and
 * sha3 output can be called more times.
 *
 * @param [inout] sponge The context.
 * @param [out] in The output data.
 * @param [in] len The requested output data length in bytes.
 */  
void sha3_output (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
);

/**
 * @brief Destroy a SHA3 or SHAKE sponge context by overwriting it with 0.
 * @param [out] sponge The context.
 */  
void sponge_destroy (
    keccak_sponge_t sponge
);


/**
 * @brief Hash (in) to (out)
 * @param [in] in The input data.
 * @param [in] inlen The length of the input data.
 * @param [out] out A buffer for the output data.
 * @param [in] outlen The length of the output data.
 */  
void sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct kparams_s *params
);

/* TODO: expand/doxygenate individual SHAKE/SHA3 instances? */

#define DECSHAKE(n) \
    extern const struct kparams_s *SHAKE##n##_params; \
    static inline void shake##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, SHAKE##n##_params); \
    } \
    static inline void shake##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void shake##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, SHAKE##n##_params); \
    } \
    static inline void shake##n##_hash(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen ) { \
        sponge_hash(in,inlen,out,outlen,SHAKE##n##_params); \
    } \
    static inline void shake##n##_destroy( keccak_sponge_t sponge ) { \
        sponge_destroy(sponge); \
    }
    
#define DECSHA3(n) \
    extern const struct kparams_s *SHA3_##n##_params; \
    static inline void sha3_##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, SHA3_##n##_params); \
    } \
    static inline void sha3_##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void sha3_##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, SHA3_##n##_params); \
    } \
    static inline void sha3_##n##_hash(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen ) { \
        sponge_hash(in,inlen,out,outlen,SHA3_##n##_params); \
    } \
    static inline void sha3_##n##_destroy( keccak_sponge_t sponge ) { \
        sponge_destroy(sponge); \
    }

DECSHAKE(128)
DECSHAKE(256)
DECSHA3(224)
DECSHA3(256)
DECSHA3(384)
DECSHA3(512)
    
#endif /* __SHAKE_H__ */
