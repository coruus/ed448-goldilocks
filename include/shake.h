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
#include <sys/types.h>

#include "decaf.h" /* TODO: orly? */

/* TODO: unify with other headers (maybe all into one??); add nonnull attributes */
/** @cond internal */
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
/** @endcond */

/* TODO: different containing structs for each primitive? */
#ifndef INTERNAL_SPONGE_STRUCT
    /** Sponge container object for the various primitives. */
    typedef struct keccak_sponge_s {
        /** @cond internal */
        uint64_t opaque[26];
        /** @endcond */
    } keccak_sponge_t[1];
    struct kparams_s;
    typedef struct { uint64_t opaque; } strobe_params_t[1];
#endif

typedef struct strobe_s {
    keccak_sponge_t sponge;
    strobe_params_t params;
} strobe_s, strobe_t[1];

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a sponge context object.
 * @param [out] sponge The object to initialize.
 * @param [in] params The sponge's parameter description.
 */
void sponge_init (
    keccak_sponge_t sponge,
    const struct kparams_s *params
) API_VIS;

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
) API_VIS;

/**
 * @brief Squeeze output data from a SHA3 or SHAKE hash context.
 * This does not destroy or re-initialize the hash context, and
 * sha3 output can be called more times.
 *
 * @param [inout] sponge The context.
 * @param [out] out The output data.
 * @param [in] len The requested output data length in bytes.
 */  
void sha3_output (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) API_VIS;

/**
 * @brief Return the default output length of the sponge construction,
 * for the purpose of C++ default operators.
 *
 * Returns n/8 for SHA3-n and 2n/8 for SHAKE-n.
 *
 * @param [inout] sponge The context.
 */  
size_t sponge_default_output_bytes (
    const keccak_sponge_t sponge
) API_VIS;

/**
 * @brief Destroy a SHA3 or SHAKE sponge context by overwriting it with 0.
 * @param [out] sponge The context.
 */  
void sponge_destroy (
    keccak_sponge_t sponge
) API_VIS;

/**
 * @brief Hash (in) to (out)
 * @param [in] in The input data.
 * @param [in] inlen The length of the input data.
 * @param [out] out A buffer for the output data.
 * @param [in] outlen The length of the output data.
 * @param [in] params The parameters of the sponge hash.
 */  
void sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct kparams_s *params
) API_VIS;

/* TODO: expand/doxygenate individual SHAKE/SHA3 instances? */

/** @cond internal */
#define DECSHAKE(n) \
    extern const struct kparams_s SHAKE##n##_params_s API_VIS; \
    static inline void shake##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void shake##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void shake##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void shake##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHAKE##n##_params_s); \
    } \
    static inline void shake##n##_destroy( keccak_sponge_t sponge ) { \
        sponge_destroy(sponge); \
    }
    
#define DECSHA3(n) \
    extern const struct kparams_s SHA3_##n##_params_s API_VIS; \
    static inline void sha3_##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void sha3_##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void sha3_##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void sha3_##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHA3_##n##_params_s); \
    } \
    static inline void sha3_##n##_destroy( keccak_sponge_t sponge ) { \
        sponge_destroy(sponge); \
    }
/** @endcond */

DECSHAKE(128)
DECSHAKE(256)
DECSHA3(224)
DECSHA3(256)
DECSHA3(384)
DECSHA3(512)

/**
 * @brief Initialize a sponge-based CSPRNG from a buffer.
 *
 * @param [out] sponge The sponge object.
 * @param [in] in The initial data.
 * @param [in] len The length of the initial data.
 * @param [in] deterministic If zero, allow RNG to stir in nondeterministic
 * data from RDRAND or RDTSC.
 */
void spongerng_init_from_buffer (
    keccak_sponge_t sponge,
    const uint8_t * __restrict__ in,
    size_t len,
    int deterministic
) API_VIS;

/* FIXME!! This interface has the opposite retval convention from other functions
 * in the library.  (0=success).  Should they be harmonized?
 */

/**
 * @brief Initialize a sponge-based CSPRNG from a file.
 *
 * @param [out] sponge The sponge object.
 * @param [in] file A name of a file containing initial data.
 * @param [in] len The length of the initial data.  Must be positive.
 * @param [in] deterministic If zero, allow RNG to stir in nondeterministic
 * data from RDRAND or RDTSC.
 *
 * @retval 0 Success.
 * @retval positive An error has occurred, and this was the errno.
 * @retval -1 An unknown error has occurred.
 * @retval -2 len was 0.
 */
int spongerng_init_from_file (
    keccak_sponge_t sponge,
    const char *file,
    size_t len,
    int deterministic
) API_VIS WARN_UNUSED;


/* FIXME!! This interface has the opposite retval convention from other functions
 * in the library.  (0=success).  Should they be harmonized?
 */

/**
 * @brief Initialize a nondeterministic sponge-based CSPRNG from /dev/urandom.
 *
 * @param [out] sponge The sponge object.
 *
 * @retval 0 Success.
 * @retval positive An error has occurred, and this was the errno.
 * @retval -1 An unknown error has occurred.
 */
int spongerng_init_from_dev_urandom (
    keccak_sponge_t sponge
) API_VIS WARN_UNUSED;

/**
 * @brief Output bytes from a sponge-based CSPRNG.
 *
 * @param [inout] sponge The sponge object.
 * @param [out] out The output buffer.
 * @param [in] len The output buffer's length.
 */
void spongerng_next (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) API_VIS;

/**
 * @brief Stir entropy data into a sponge-based CSPRNG from a buffer.
 *
 * @param [out] sponge The sponge object.
 * @param [in] in The entropy data.
 * @param [in] len The length of the initial data.
 */
void spongerng_stir (
    keccak_sponge_t sponge,
    const uint8_t * __restrict__ in,
    size_t len
) API_VIS;

/**
 * @brief Initialize Strobe protocol context.
 * @param [out] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 */
void strobe_init(
    strobe_t strobe,
    const struct kparams_s *params,
    uint8_t am_client
);
    
/**
 * @brief Produce an authenticator.
 * @param [inout] strobe The Strobe protocol context
 * @param [out] out The authenticator
 * @param len The length, which must be no more than
 * @todo 32?
 */
void strobe_produce_auth (
   strobe_t strobe,
   unsigned char *out,
   size_t len
);

/**
 * @brief Produce a session-bound pseudorandom value.
 *
 * @warning This "prng" value is NOT suitable for
 * refreshing forward secrecy!  It's to replace things
 * like TCP session hash.
 *
 * @todo Figure out how to treat this wrt anti-rollback.
 *
 * @param [inout] strobe The Strobe protocol context
 * @param [out] out The authenticator
 * @param len The length.
 */   
void strobe_prng (
   strobe_t strobe,
   unsigned char *out,
   size_t len
);

/**
 * @brief Verify an authenticator.
 * @param [inout] strobe The Strobe protocol context
 * @param [in] in The authenticator
 * @param len The length, which must be no more than
 * @todo 32?
 */
decaf_bool_t strobe_verify_auth (
    strobe_t strobe,
    const unsigned char *in,
    size_t len
);

/**
 * @brief Respecify Strobe protocol object's crypto.
 * @param [inout] The initialized strobe context.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 */
void strobe_respec (
    strobe_t strobe,
    const struct kparams_s *params
);

/**
 * @brief Destroy a Strobe context.
 * @param [out] strobe The object to destroy.
 */
void strobe_destroy (
    strobe_t strobe
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#undef API_VIS
#undef WARN_UNUSED
    
#endif /* __SHAKE_H__ */
