/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "crypto_sign.h"

int crypto_sign_keypair (
    unsigned char pk[PUBLICKEY_BYTES],
    unsigned char sk[SECRETKEY_BYTES]
) {
    decaf_448_symmetric_key_t proto;
    randombytes(proto,sizeof(proto));
    decaf_448_derive_private_key((decaf_448_private_key_s *)sk,proto);
    decaf_448_private_to_public(pk,
        (decaf_448_private_key_s *)sk
    );
    return 0;
}

int crypto_sign (
    unsigned char *sm,
    unsigned long long *smlen,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char sk[SECRETKEY_BYTES]
) {
    unsigned char sig[SIGNATURE_BYTES];
    decaf_448_sign(
        sig,
        (const struct goldilocks_private_key_t *)sk,
        m, mlen
    );
    memmove(sm + SIGNATURE_BYTES, m, mlen);
    memcpy(sm, sig, SIGNATURE_BYTES);
    *smlen = mlen + SIGNATURE_BYTES;
    return 0;
}

int crypto_sign_open (
    unsigned char *m,
    unsigned long long *mlen,
    const unsigned char *sm,
    unsigned long long smlen,
    const unsigned char pk[PUBLICKEY_BYTES]
) {
    int ret = decaf_448_verify(
        sm,pk,
        sm + SIGNATURE_BYTES, smlen - SIGNATURE_BYTES
    );
    if (ret) {
        *mlen = smlen - SIGNATURE_BYTES;
        memmove(m, sm + SIGNATURE_BYTES, *mlen);
    }
    return ret ? 0 : -1;
}
