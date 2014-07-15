/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <string.h>
#include "goldilocks.h"

#define PUBLICKEY_BYTES GOLDI_PUBLIC_KEY_BYTES
#define SECRETKEY_BYTES GOLDI_PRIVATE_KEY_BYTES
#define SIGNATURE_BYTES GOLDI_SIGNATURE_BYTES
#define SHAREDSECRET_BYTES GOLDI_SHARED_SECRET_BYTES

#define crypto_dh_PUBLICKEYBYTES PUBLICKEY_BYTES
#define crypto_dh_SECRETKEYBYTES SECRETKEY_BYTES
#define PRIVATEKEY_BYTES SECRETKEY_BYTES
#define crypto_dh_BYTES SHAREDSECRET_BYTES
#define crypto_dh_IMPLEMENTATION "AMD64"
#define crypto_dh_VERSION "2014-07-11"

#define crypto_sign_PUBLICKEYBYTES PUBLICKEY_BYTES
#define crypto_sign_SECRETKEYBYTES SECRETKEY_BYTES
#define crypto_sign_IMPLEMENTATION "AMD64"
#define crypto_sign_VERSION "2014-07-11"
#define crypto_sign_BYTES SIGNATURE_BYTES

#define CRYPTO_DETERMINISTIC 1

/*
#ifndef LOOPS
#define LOOPS 512
#endif
*/

static inline int timingattacks() {
  return 0;
}
static inline int copyrightclaims() {
  return 0;
}
static inline int patentclaims() {
  /* Until the end of July 2014, point compression
   * is patented. */
  return 20;
}

#define crypto_sign_keypair crypto_dh_keypair
static inline int crypto_dh_keypair(unsigned char pk[SECRETKEY_BYTES],
                                    unsigned char sk[PUBLICKEY_BYTES]) {
  int ret;
  ret = goldilocks_init();
  if (ret && ret != GOLDI_EALREADYINIT)
    return ret;
  if ((ret = goldilocks_keygen((struct goldilocks_private_key_t*)sk,
                               (struct goldilocks_public_key_t*)pk)))
    abort();
  return ret;
}

static inline void keypair(unsigned char sk[SECRETKEY_BYTES],
                           unsigned long long* sklen,
                           unsigned char pk[PUBLICKEY_BYTES],
                           unsigned long long* pklen) {
  int ret = goldilocks_init();
  if (ret)
    abort();

  ret = goldilocks_keygen((struct goldilocks_private_key_t*)sk,
                          (struct goldilocks_public_key_t*)pk);
  if (ret)
    abort();

  *sklen = SECRETKEY_BYTES;
  *pklen = PUBLICKEY_BYTES;
}

static inline int crypto_sign(unsigned char* sm,
                              unsigned long long* smlen,
                              const unsigned char* m,
                              unsigned long long mlen,
                              const unsigned char sk[SECRETKEY_BYTES]) {
  int ret = goldilocks_sign(sm, m, mlen, (const struct goldilocks_private_key_t*)sk);
  if (ret)
    abort();

  memcpy(sm + SIGNATURE_BYTES, m, mlen);

  *smlen = mlen + SIGNATURE_BYTES;
  return 0;
}

static inline void signmessage(unsigned char* sm,
                               unsigned long long* smlen,
                               const unsigned char* m,
                               unsigned long long mlen,
                               const unsigned char sk[SECRETKEY_BYTES],
                               unsigned long long sklen) {
  if (sklen != PRIVATEKEY_BYTES)
    abort();

  int ret = goldilocks_sign(sm, m, mlen, (const struct goldilocks_private_key_t*)sk);
  if (ret)
    abort();

  memcpy(sm + SIGNATURE_BYTES, m, mlen);

  *smlen = mlen + SIGNATURE_BYTES;
}

static inline int crypto_sign_open(unsigned char* m,
                                   unsigned long long* mlen,
                                   const unsigned char* sm,
                                   unsigned long long smlen,
                                   const unsigned char pk[PUBLICKEY_BYTES]) {
  int ret = goldilocks_verify(sm,
                              sm + SIGNATURE_BYTES,
                              smlen - SIGNATURE_BYTES,
                              (const struct goldilocks_public_key_t*)pk);
  if (!ret) {
    *mlen = smlen - SIGNATURE_BYTES;
    memcpy(m, sm + SIGNATURE_BYTES, *mlen);
  }
  return ret ? -1 : 0;
}

static inline int verification(const unsigned char* m,
                               unsigned long long mlen,
                               const unsigned char* sm,
                               unsigned long long smlen,
                               const unsigned char pk[PUBLICKEY_BYTES],
                               unsigned long long pklen) {
  if (pklen != PUBLICKEY_BYTES)
    abort();

  int ret = goldilocks_verify(sm, m, mlen, (const struct goldilocks_public_key_t*)pk);
  return ret ? -1 : 0;
}

static inline int crypto_dh(unsigned char s[SHAREDSECRET_BYTES],
                            const unsigned char sk[SECRETKEY_BYTES],
                            const unsigned char pk[PUBLICKEY_BYTES]) {
  return goldilocks_shared_secret(s,
                                  (const struct goldilocks_private_key_t*)sk,
                                  (const struct goldilocks_public_key_t*)pk);
}

static inline int sharedsecret(unsigned char s[SHAREDSECRET_BYTES],
                               unsigned long long* slen,
                               const unsigned char sk[SECRETKEY_BYTES],
                               unsigned long long sklen,
                               const unsigned char pk[PUBLICKEY_BYTES],
                               unsigned long long pklen) {
  if (pklen != PUBLICKEY_BYTES)
    abort();
  if (sklen != SECRETKEY_BYTES)
    abort();

  int ret = goldilocks_shared_secret(s,
                                     (const struct goldilocks_private_key_t*)sk,
                                     (const struct goldilocks_public_key_t*)pk);
  if (ret)
    return -1;
  *slen = SHAREDSECRET_BYTES;
  return 0;
}
