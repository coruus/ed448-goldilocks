/**
 * @file sizes.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief BATMAN / SUPERCOP glue for benchmarking.
 */

#include <string.h>
#include "decaf_crypto.h"

#define PUBLICKEY_BYTES (sizeof(decaf_448_public_key_t))
#define SECRETKEY_BYTES (sizeof(decaf_448_private_key_t))
#define SIGNATURE_BYTES (sizeof(decaf_448_signature_t))

#define CRYPTO_PUBLICKEYBYTES PUBLICKEY_BYTES
#define CRYPTO_SECRETKEYBYTES SECRETKEY_BYTES
#define CRYPTO_BYTES SIGNATURE_BYTES
#define PRIVATEKEY_BYTES SECRETKEY_BYTES
#define CRYPTO_VERSION "__TODAY__"

#define CRYPTO_DETERMINISTIC 1

