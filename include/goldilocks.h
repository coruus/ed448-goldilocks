/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file goldilocks.h
 * @author Mike Hamburg
 * @brief Goldilocks high-level functions.
 */
#ifndef __GOLDILOCKS_H__
#define __GOLDILOCKS_H__ 1

#include <stdint.h>

/**
 * @brief Serialized form of a Goldilocks public key.
 *
 * @warning This isn't even my final form!
 */
struct goldilocks_public_key_t {
    uint8_t opaque[56]; /**< Serialized data. */
};

/**
 * @brief Serialized form of a Goldilocks private key.
 *
 * Contains 56 bytes of actual private key, 56 bytes of
 * public key, and 32 bytes of symmetric key for randomization.
 *
 * @warning This isn't even my final form!
 */
struct goldilocks_private_key_t {
    uint8_t opaque[144]; /**< Serialized data. */
};

#ifdef __cplusplus
extern "C" {
#endif

/** @brief No error. */
static const int GOLDI_EOK      = 0;

/** @brief Error: your key or other state is corrupt. */
static const int GOLDI_ECORRUPT = 44801;

/** @brief Error: other party's key is corrupt. */
static const int GOLDI_EINVAL   = 44802;

/** @brief Error: not enough entropy. */
static const int GOLDI_ENODICE  = 44804;

/** @brief Error: you need to initialize the library first. */
static const int GOLDI_EUNINIT  = 44805;

/** @brief Error: called init() but we are already initialized. */
static const int GOLDI_EALREADYINIT  = 44805;

/**
 * @brief Initialize Goldilocks' precomputed tables and
 * random number generator.  This function must be called before
 * any of the other Goldilocks routines (except
 * goldilocks_shared_secret in the current version) and should be
 * called only once per process.
 *
 * There is currently no way to tear down this state.  It is possible
 * that a future version of this library will not require this function.
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_EALREADYINIT Already initialized.
 * @retval GOLDI_ECORRUPT Memory is corrupted, or another thread is already init'ing.
 * @retval Nonzero An error occurred.
 */
int
goldilocks_init ()
__attribute__((warn_unused_result));


/**
 * @brief Generate a new random keypair.
 * @param [out] privkey The generated private key.
 * @param [out] pubkey The generated public key.
 *
 * @warning This isn't even my final form!
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_ENODICE Insufficient entropy.
 * @retval GOLDI_EUNINIT You must call goldilocks_init() first.
 */
int
goldilocks_keygen (
    struct goldilocks_private_key_t *privkey,
    struct goldilocks_public_key_t *pubkey
) __attribute__((warn_unused_result,nonnull(1,2)));

/**
 * @brief Extract the public key from a private key.
 *
 * This is essentially a memcpy from the public part of the privkey.
 *    
 * @param [out] pubkey The extracted private key.
 * @param [in] privkey The private key.
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_ECORRUPT The private key is corrupt.
 */
int
goldilocks_private_to_public (
    struct goldilocks_public_key_t *pubkey,
    const struct goldilocks_private_key_t *privkey
) __attribute__((nonnull(1,2)));

/**
 * @brief Generate a Diffie-Hellman shared secret in constant time.
 *
 * This function uses some compile-time flags whose merit remains to
 * be decided.
 *
 * If the flag EXPERIMENT_ECDH_OBLITERATE_CT is set, prepend 40 bytes
 * of zeros to the secret before hashing.  In the case that the other
 * party's key is detectably corrupt, instead the symmetric part
 * of the secret key is used to produce a pseudorandom value.
 *
 * If EXPERIMENT_ECDH_STIR_IN_PUBKEYS is set, the sum and product of
 * the two parties' public keys is prepended to the hash.
 *
 * In the current version, this function can safely be run even without
 * goldilocks_init().  But this property is not guaranteed for future
 * versions, so call it anyway.
 *
 * @warning This isn't even my final form!
 *
 * @param [out] shared The shared secret established with the other party.
 * @param [in] my_privkey My private key.
 * @param [in] your_pubkey The other party's public key.
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_ECORRUPT My key is corrupt.
 * @retval GOLDI_EINVAL   The other party's key is corrupt.
 * @retval GOLDI_EUNINIT You must call goldilocks_init() first.
 */
int
goldilocks_shared_secret (
    uint8_t shared[64],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_public_key_t *your_pubkey
) __attribute__((warn_unused_result,nonnull(1,2,3)));
    
/**
 * @brief Sign a message.
 *
 * The signature is deterministic, using the symmetric secret found in the
 * secret key to form a nonce.
 *
 * The technique used in signing is a modified Schnorr system, like EdDSA.
 *
 * @warning This isn't even my final form!
 *
 * @param [out] signature_out Space for the output signature.
 * @param [in] message The message to be signed.
 * @param [in] message_len The length of the message to be signed.
 * @param [in] privkey My private key.
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_ECORRUPT My key is corrupt.
 * @retval GOLDI_EUNINIT You must call goldilocks_init() first.
 */
int
goldilocks_sign (
    uint8_t signature_out[56*2],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_private_key_t *privkey
) __attribute__((nonnull(1,2,4)));

/**
 * @brief Verify a signature.
 *
 * This function is fairly strict.  It will correctly detect when
 * the signature has the wrong cofactor component, or when the sig
 * values aren't less than p or q.
 * 
 * Currently this function does not detect when the public key is weird,
 * eg 0, has cofactor, etc.  As a result, a party with a bogus public
 * key could create signatures that succeed on some systems and fail on
 * others.
 *
 * @warning This isn't even my final form!
 *
 * @param [in] signature The signature.
 * @param [in] message The message to be verified.
 * @param [in] message_len The length of the message to be verified.
 * @param [in] pubkey The signer's public key.
 *
 * @retval GOLDI_EOK Success.
 * @retval GOLDI_EINVAL The public key or signature is corrupt.
 * @retval GOLDI_EUNINIT You must call goldilocks_init() first.
 */
int
goldilocks_verify (
    const uint8_t signature[56*2],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_public_key_t *pubkey
) __attribute__((warn_unused_result,nonnull(1,2,4)));

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __GOLDILOCKS_H__ */
