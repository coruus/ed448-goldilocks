/**
 * @cond internal
 * @file decaf_crypto.c
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Decaf cyrpto routines. 
 */

#include "decaf_crypto.h"
#include <string.h>

void decaf_448_derive_private_key (
    decaf_448_private_key_t priv,
    const decaf_448_symmetric_key_t proto
) {
    const char *magic = "decaf_448_derive_private_key";
    keccak_sponge_t sponge;
    uint8_t encoded_scalar[64];
    decaf_448_point_t pub;
    shake256_init(sponge);
    shake256_update(sponge, proto, sizeof(decaf_448_symmetric_key_t));
    shake256_update(sponge, (const unsigned char *)magic, strlen(magic));
    shake256_final(sponge, encoded_scalar, sizeof(encoded_scalar));
    shake256_destroy(sponge);
    
    memcpy(priv->sym, proto, sizeof(decaf_448_symmetric_key_t));
    decaf_448_scalar_decode_long(priv->secret_scalar, encoded_scalar, sizeof(encoded_scalar));
    
    decaf_448_precomputed_scalarmul(pub, decaf_448_precomputed_base, priv->secret_scalar);
    decaf_448_point_encode(priv->pub, pub);
    
    decaf_bzero(encoded_scalar, sizeof(encoded_scalar));
}

void
decaf_448_destroy_private_key (
    decaf_448_private_key_t priv
)  {
    decaf_bzero((void*)priv, sizeof(decaf_448_private_key_t));
}

void decaf_448_private_to_public (
    decaf_448_public_key_t pub,
    const decaf_448_private_key_t priv
) {
    memcpy(pub, priv->pub, sizeof(decaf_448_public_key_t));
}

decaf_bool_t
decaf_448_shared_secret (
    uint8_t *shared,
    size_t shared_bytes,
    const decaf_448_private_key_t my_privkey,
    const decaf_448_public_key_t your_pubkey
) {
    decaf_448_point_t point;
    uint8_t ss_ser[DECAF_448_SER_BYTES];
    const char *nope = "decaf_448_ss_invalid";
    decaf_bool_t ret = decaf_448_point_decode(point, your_pubkey, DECAF_FALSE);
    decaf_448_point_scalarmul(point, point, my_privkey->secret_scalar);
    
    unsigned i;
    /* Lexsort keys.  Less will be -1 if mine is less, and 0 otherwise. */
    uint16_t less = 0;
    for (i=0; i<DECAF_448_SER_BYTES; i++) {
        uint16_t delta = my_privkey->pub[i];
        delta -= your_pubkey[i];
        /* Case:
         * = -> delta = 0 -> hi delta-1 = -1, hi delta = 0
         * > -> delta > 0 -> hi delta-1 = 0, hi delta = 0
         * < -> delta < 0 -> hi delta-1 = (doesnt matter), hi delta = -1
         */
        less &= delta-1;
        less |= delta;
    }
    less >>= 8;

    keccak_sponge_t sponge;
    shake256_init(sponge);

    /* update the lesser */
    for (i=0; i<sizeof(ss_ser); i++) {
        ss_ser[i] = (my_privkey->pub[i] & less) | (your_pubkey[i] & ~less);
    }
    shake256_update(sponge, ss_ser, sizeof(ss_ser));

    /* update the greater */
    for (i=0; i<sizeof(ss_ser); i++) {
        ss_ser[i] = (my_privkey->pub[i] & ~less) | (your_pubkey[i] & less);
    }
    shake256_update(sponge, ss_ser, sizeof(ss_ser));
    
    /* encode the shared secret but mask with secret key */
    decaf_448_point_encode(ss_ser, point);
    
    /* If invalid, then replace ... */
    for (i=0; i<sizeof(ss_ser); i++) {
        ss_ser[i] &= ret;
        
        if (i < sizeof(my_privkey->sym)) {
            ss_ser[i] |= my_privkey->sym[i] & ~ret;
        } else if (i - sizeof(my_privkey->sym) < strlen(nope)) {
            ss_ser[i] |= nope[i-sizeof(my_privkey->sym)] & ~ret;
        }
    }

    shake256_update(sponge, ss_ser, sizeof(ss_ser));
    shake256_final(sponge, shared, shared_bytes);
    shake256_destroy(sponge);
    
    decaf_bzero(ss_ser, sizeof(ss_ser));
    
    return ret;
}
