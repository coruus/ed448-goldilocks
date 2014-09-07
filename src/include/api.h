/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <string.h>
#include <stdlib.h>
#include "goldilocks.h"

#define PUBLICKEY_BYTES GOLDI_PUBLIC_KEY_BYTES
#define SECRETKEY_BYTES GOLDI_PRIVATE_KEY_BYTES
#define SIGNATURE_BYTES GOLDI_SIGNATURE_BYTES
#define SHAREDSECRET_BYTES GOLDI_SHARED_SECRET_BYTES

#define crypto_dh_SYSNAME_PUBLICKEYBYTES PUBLICKEY_BYTES
#define crypto_dh_SYSNAME_SECRETKEYBYTES SECRETKEY_BYTES
#define PRIVATEKEY_BYTES SECRETKEY_BYTES
#define crypto_dh_SYSNAME_BYTES SHAREDSECRET_BYTES
#define crypto_dh_SYSNAME_IMPLEMENTATION "AMD64"
#define crypto_dh_SYSNAME_VERSION "2014-07-11"

#define crypto_sign_SYSNAME_PUBLICKEYBYTES PUBLICKEY_BYTES
#define crypto_sign_SYSNAME_SECRETKEYBYTES SECRETKEY_BYTES
#define crypto_sign_SYSNAME_IMPLEMENTATION "AMD64"
#define crypto_sign_SYSNAME_VERSION "2014-07-11"
#define crypto_sign_SYSNAME_BYTES SIGNATURE_BYTES

#define crypto_dh_SYSNAME_keypair crypto_dh_keypair
#define crypto_dh_SYSNAME crypto_dh
#define crypto_sign_SYSNAME_keypair crypto_dh_keypair
#define crypto_sign_SYSNAME crypto_sign
#define crypto_sign_SYSNAME_open crypto_sign_open

#define CRYPTO_DETERMINISTIC 1

/*
#ifndef LOOPS
#define LOOPS 512
#endif
*/

static inline int timingattacks(void) { return 0; }
static inline int copyrightclaims(void) { return 0; }
static inline int patentclaims(void) {
    /* Until the end of July 2014, point compression
     * is patented. */
    return 20;
}

static inline int crypto_dh_keypair (
    unsigned char pk[SECRETKEY_BYTES],
    unsigned char sk[PUBLICKEY_BYTES]
) {
  int ret;
  ret = goldilocks_init();
  if (ret && ret != GOLDI_EALREADYINIT)
    return ret;
  if ((ret = goldilocks_keygen(
      (struct goldilocks_private_key_t *)sk,
      (struct goldilocks_public_key_t *)pk
  ))) abort();
  return ret;
}

static inline int crypto_sign (
    unsigned char *sm,
    unsigned long long *smlen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char sk[SECRETKEY_BYTES]
) {
    unsigned char sig[SIGNATURE_BYTES];
    int ret = goldilocks_sign(
        sig, m, mlen,
        (const struct goldilocks_private_key_t *)sk
    );
    if (!ret) {
        memmove(sm + SIGNATURE_BYTES, m, mlen);
        memcpy(sm, sig, SIGNATURE_BYTES);
        *smlen = mlen + SIGNATURE_BYTES;
    }
    return ret ? -1 : 0;
}

static inline int crypto_sign_open (
    unsigned char *m,
    unsigned long long *mlen,
    const unsigned char *sm,
    unsigned long long smlen,
    const unsigned char pk[PUBLICKEY_BYTES]
) {
    int ret = goldilocks_verify(
        sm, sm + SIGNATURE_BYTES, smlen - SIGNATURE_BYTES,
        (const struct goldilocks_public_key_t *)pk
    );
    if (!ret) {
        *mlen = smlen - SIGNATURE_BYTES;
        memmove(m, sm + SIGNATURE_BYTES, *mlen);
    }
    return ret ? -1 : 0;
}

static inline int crypto_dh (
    unsigned char s[SHAREDSECRET_BYTES],
    const unsigned char pk[PUBLICKEY_BYTES],
    const unsigned char sk[SECRETKEY_BYTES]
) {
  return goldilocks_shared_secret (
        s,
        (const struct goldilocks_private_key_t *)sk,
        (const struct goldilocks_public_key_t *)pk
  );
}

