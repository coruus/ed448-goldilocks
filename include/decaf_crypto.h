/**
 * @file decaf_crypto.h
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Decaf cyrpto routines. 
 * @warning Experimental!  The names, parameter orders etc are likely to change.
 */

#ifndef __DECAF_CRYPTO_H__
#define __DECAF_CRYPTO_H__ 1

#include "decaf.h"
#include "shake.h"

#define DECAF_448_SYMMETRIC_KEY_BYTES 32
/** @cond internal */
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
#define NONNULL134 __attribute__((nonnull(1,3,4)))
#define NONNULL5 __attribute__((nonnull(1,2,3,4,5)))
/** @endcond */

/** A symmetric key, the compressed point of a private key. */
typedef unsigned char decaf_448_symmetric_key_t[DECAF_448_SYMMETRIC_KEY_BYTES];

/** An encoded public key. */
typedef unsigned char decaf_448_public_key_t[DECAF_448_SER_BYTES];

/** A private key. */
typedef struct {
    decaf_448_symmetric_key_t sym;
    decaf_448_scalar_t secret_scalar;
    decaf_448_public_key_t pub;
} decaf_448_private_key_t[1];

#ifdef __cplusplus
extern "C" {
#endif
    
/**
 * @brief Derive a key from its compressed form.
 * @param [out] privkey The derived private key.
 * @param [in] proto The compressed or proto-key, which must be 32 random bytes.
 */
void decaf_448_derive_private_key (
    decaf_448_private_key_t priv,
    const decaf_448_symmetric_key_t proto
) NONNULL2 API_VIS;

/**
 * @brief Destroy a private key.
 */
void decaf_448_destroy_private_key (
    decaf_448_private_key_t priv
) NONNULL1 API_VIS;

/**
 * @brief Convert a private key to a public one.
 * @param [out] pub The extracted private key.
 * @param [in] priv The private key.
 */
void decaf_448_private_to_public (
    decaf_448_public_key_t pub,
    const decaf_448_private_key_t priv
) NONNULL2 API_VIS;
    
/**
 * @brief Compute a Diffie-Hellman shared secret.
 *
 * This is an example routine; real protocols would use something
 * protocol-specific.
 *
 * @param [out] shared A buffer to store the shared secret.
 * @param [in] shared_bytes The size of the buffer.
 * @param [in] my_privkey My private key.
 * @param [in] your_pubkey Your public key.
 *
 * @retval DECAF_SUCCESS Key exchange was successful.
 * @retval DECAF_FAILURE Key exchange failed.
 */
decaf_bool_t
decaf_448_shared_secret (
    uint8_t *shared,
    size_t shared_bytes,
    const decaf_448_private_key_t my_privkey,
    const decaf_448_public_key_t your_pubkey
) NONNULL134 WARN_UNUSED API_VIS;
    
#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL1
#undef NONNULL2
#undef NONNULL3
#undef NONNULL134
#undef NONNULL5

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __DECAF_CRYPTO_H__ */


