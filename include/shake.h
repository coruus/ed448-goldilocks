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
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL13 __attribute__((nonnull(1,3)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
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
#endif

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
    static inline void NONNULL1 shake##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void NONNULL2 shake##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void  NONNULL2 shake##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, &SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL13 shake##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHAKE##n##_params_s); \
    } \
    static inline void  NONNULL1 shake##n##_destroy( keccak_sponge_t sponge ) { \
        sponge_destroy(sponge); \
    }
    
#define DECSHA3(n) \
    extern const struct kparams_s SHA3_##n##_params_s API_VIS; \
    static inline void NONNULL1 sha3_##n##_init(keccak_sponge_t sponge) { \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL2 sha3_##n##_update(keccak_sponge_t sponge, const uint8_t *in, size_t inlen ) { \
        sha3_update(sponge, in, inlen); \
    } \
    static inline void NONNULL2 sha3_##n##_final(keccak_sponge_t sponge, uint8_t *out, size_t outlen ) { \
        sha3_output(sponge, out, outlen); \
        sponge_init(sponge, &SHA3_##n##_params_s); \
    } \
    static inline void NONNULL13 sha3_##n##_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) { \
        sponge_hash(in,inlen,out,outlen,&SHA3_##n##_params_s); \
    } \
    static inline void NONNULL1 sha3_##n##_destroy( keccak_sponge_t sponge ) { \
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
) NONNULL2 API_VIS;

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
) NONNULL2 API_VIS WARN_UNUSED;


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
) NONNULL2 API_VIS;

extern const struct kparams_s STROBE_128 API_VIS;
extern const struct kparams_s STROBE_256 API_VIS;
extern const struct kparams_s STROBE_KEYED_128 API_VIS;
extern const struct kparams_s STROBE_KEYED_256 API_VIS;

/** TODO: remove this restriction?? */
#define STROBE_MAX_AUTH_BYTES 255

/** TODO: check "more" flags? */

/**
 * @brief Initialize Strobe protocol context.
 * @param [out] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 */
void strobe_init (
    keccak_sponge_t sponge,
    const struct kparams_s *params,
    uint8_t am_client
) NONNULL2 API_VIS;
   
/**
 * @brief Send plaintext in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] in The plaintext.
 * @param [in] len The length of the plaintext.
 * @param [in] iSent Nonzero if this side of exchange sent the plaintext.
 * @param [in] more Nonzero if this is a continuation.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_plaintext (
    keccak_sponge_t sponge,
    const unsigned char *in,
    size_t len,
    uint8_t iSent,
    uint8_t more
) NONNULL2 API_VIS;
   
/**
 * @brief Report authenticated data in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] in The plaintext.
 * @param [in] len The length of the ad.
 * @param [in] more Nonzero if this is a continuation.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_ad (
    keccak_sponge_t sponge,
    const unsigned char *in,
    size_t len,
    uint8_t more
) NONNULL2 API_VIS;
   
/**
 * @brief Set nonce in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] in The nonce.
 * @param [in] len The length of the nonce.
 * @param [in] more Nonzero if this is a continuation.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_nonce (
    keccak_sponge_t sponge,
    const unsigned char *in,
    size_t len,
    uint8_t more
) NONNULL2 API_VIS;
   
/**
 * @brief Set key in strobe context.
 * @param [inout] The initialized strobe object.
 * @param [in] Strobe parameter descriptor
 * @param [in] in The key.
 * @param [in] len The length of the key.
 * @param [in] more Nonzero if this is a continuation.
 */
decaf_bool_t strobe_key (
    keccak_sponge_t sponge,
    const unsigned char *in,
    size_t len,
    uint8_t more
) NONNULL2 API_VIS;
    
/**
 * @brief Produce an authenticator.
 * @param [inout] strobe The Strobe protocol context
 * @param [out] out The authenticator
 * @param len The length, which must be no more than
 * @todo 32?
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_produce_auth (
   keccak_sponge_t sponge,
   unsigned char *out,
   size_t len
) NONNULL2 API_VIS;
   
/**
 * @brief Encrypt bytes from in to out.
 * @warning Doesn't produce an auth tag (TODO?)
 * @param [inout] strobe The Strobe protocol context.
 * @param [in] in The plaintext.
 * @param [out] out The ciphertext.
 * @param [in] len The length of plaintext and ciphertext.
 * @param [in] more This is a continuation.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_encrypt (
   keccak_sponge_t sponge,
   unsigned char *out,
   const unsigned char *in,
   size_t len,
   uint8_t more
) NONNULL3 API_VIS;
   
/**
 * @brief Decrypt bytes from in to out.
 * @warning Doesn't check an auth tag (TODO?)
 * @param [inout] strobe The Strobe protocol context.
 * @param [in] in The ciphertext.
 * @param [out] out The plaintext.
 * @param [in] len The length of plaintext and ciphertext.
 * @param [in] more This is a continuation.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */
decaf_bool_t strobe_decrypt (
   keccak_sponge_t sponge,
   unsigned char *out,
   const unsigned char *in,
   size_t len,
   uint8_t more
) NONNULL3 API_VIS;

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
 *
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation applied, but is dangerous
 * because it breaks the usual flow (by doing keyed operations
 * before a key is specified, or by specifying more when the previous
 * operation didn't match).
 */   
decaf_bool_t strobe_prng (
   keccak_sponge_t sponge,
   unsigned char *out,
   size_t len,
   uint8_t more
) NONNULL2 API_VIS;

/**
 * @brief Verify an authenticator.
 * @param [inout] strobe The Strobe protocol context
 * @param [in] in The authenticator
 * @param len The length, which must be no more than
 * @todo 32?
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation failed because of a
 * bad validator (or because you aren't keyed)
 */
decaf_bool_t strobe_verify_auth (
    keccak_sponge_t sponge,
    const unsigned char *in,
    size_t len
) WARN_UNUSED NONNULL2 API_VIS;

/**
 * @brief Respecify Strobe protocol object's crypto.
 * @param [inout] The initialized strobe context.
 * @param [in] Strobe parameter descriptor
 * @param [in] am_client Nonzero if this party
 * is the client.
 * @retval DECAF_SUCCESS The operation applied successfully.
 * @retval DECAF_FAILURE The operation failed because of a
 * bad validator (or because you aren't keyed)
 */
decaf_bool_t strobe_respec (
    keccak_sponge_t sponge,
    const struct kparams_s *params
) NONNULL2 API_VIS;

#ifdef __cplusplus
} /* extern "C" */
#endif

#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL1
#undef NONNULL13
#undef NONNULL2
#undef NONNULL3
    
#endif /* __SHAKE_H__ */
