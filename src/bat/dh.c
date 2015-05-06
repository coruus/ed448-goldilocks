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
#include "api.h"
#include "crypto_dh.h"
#include "randombytes.h"

int crypto_dh_keypair (
    unsigned char pk[PUBLICKEY_BYTES],
    unsigned char sk[SECRETKEY_BYTES]
) {
    decaf_448_symmetric_key_t proto;
    randombytes(proto,sizeof(proto));
    decaf_448_derive_private_key((decaf_448_private_key_s *)sk,proto);
    decaf_448_private_to_public(pk,(decaf_448_private_key_s *)sk);
    return 0;
}

int crypto_dh (
    unsigned char s[SHAREDSECRET_BYTES],
    const unsigned char pk[PUBLICKEY_BYTES],
    const unsigned char sk[SECRETKEY_BYTES]
) {
    return !decaf_448_shared_secret (s,SHAREDSECRET_BYTES,
        (const decaf_448_private_key_s *)sk, pk
    );
}
