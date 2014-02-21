/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#include "goldilocks.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "crandom.h"

#ifndef GOLDILOCKS_RANDOM_INIT_FILE
#define GOLDILOCKS_RANDOM_INIT_FILE "/dev/urandom"
#endif

#ifndef GOLDILOCKS_RANDOM_RESEED_INTERVAL
#define GOLDILOCKS_RANDOM_RESEED_INTERVAL 10000
#endif

/* We'll check it ourselves */
#ifndef GOLDILOCKS_RANDOM_RESEEDS_MANDATORY
#define GOLDILOCKS_RANDOM_RESEEDS_MANDATORY 0
#endif

/* TODO: word size; precompute */
const struct affine_t goldilocks_base_point = {
    {{ 0xf0de840aed939full, 0xc170033f4ba0c7ull, 0xf3932d94c63d96ull, 0x9cecfa96147eaaull,
       0x5f065c3c59d070ull, 0x3a6a26adf73324ull, 0x1b4faff4609845ull, 0x297ea0ea2692ffull
    }},
    {{ 19, 0, 0, 0, 0, 0, 0, 0 }}
};

// FIXME: threading
// TODO: autogen instead of init
struct {
    struct tw_niels_t combs[80];
    struct tw_niels_t wnafs[32];
    struct crandom_state_t rand;
} goldilocks_global;

int
goldilocks_init() {
    struct extensible_t ext;
    struct tw_extensible_t text;
    
    /* Sanity check: the base point is on the curve. */
    assert(p448_affine_validate(&goldilocks_base_point));
    
    /* Convert it to twisted Edwards. */
    convert_affine_to_extensible(&ext, &goldilocks_base_point);
    p448_isogeny_un_to_tw(&text, &ext);
    
    /* Precompute the tables. */
    precompute_for_combs(goldilocks_global.combs, &text, 5, 5, 18);
    precompute_for_wnaf(goldilocks_global.wnafs, &text, 5);
    
    return crandom_init_from_file(&goldilocks_global.rand,
        GOLDILOCKS_RANDOM_INIT_FILE,
        GOLDILOCKS_RANDOM_RESEED_INTERVAL,
        GOLDILOCKS_RANDOM_RESEEDS_MANDATORY);
}

// TODO: move to a better place
// TODO: word size
void
p448_serialize(uint8_t *serial, const struct p448_t *x) {
    int i,j;
    p448_t red;
    p448_copy(&red, x);
    p448_strong_reduce(&red);
    for (i=0; i<8; i++) {
        for (j=0; j<7; j++) {
            serial[7*i+j] = red.limb[i];
            red.limb[i] >>= 8;
        }
        assert(red.limb[i] == 0);
    }
}

void
q448_serialize(uint8_t *serial, const word_t x[7]) {
    int i,j;
    for (i=0; i<7; i++) {
        for (j=0; j<8; j++) {
            serial[8*i+j] = x[i]>>(8*j);
        }
    }
}

mask_t
q448_deserialize(word_t x[7], const uint8_t serial[56]) {
    int i,j;
    for (i=0; i<7; i++) {
        word_t out = 0;
        for (j=0; j<8; j++) {
            out |= ((word_t)serial[8*i+j])<<(8*j);
        }
        x[i] = out;
    }
    // TODO: check for reduction
    return MASK_SUCCESS;
}

mask_t
p448_deserialize(p448_t *x, const uint8_t serial[56]) {
    int i,j;
    for (i=0; i<8; i++) {
        word_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((word_t)serial[7*i+j])<<(8*j);
        }
        x->limb[i] = out;
    }
    // TODO: check for reduction
    return MASK_SUCCESS;
}

static word_t
q448_lo[4] = {
    0xdc873d6d54a7bb0dull,
    0xde933d8d723a70aaull,
    0x3bb124b65129c96full,
    0x000000008335dc16ull
};

int
goldilocks_keygen(
    uint8_t private[56],
    uint8_t public[56]
) {
    // TODO: check for init.  Also maybe take CRANDOM object?  API...
    word_t sk[448*2/WORD_BITS];
    
    struct tw_extensible_t exta;
    struct p448_t pk;
    
    int ret = crandom_generate(&goldilocks_global.rand, (unsigned char *)sk, sizeof(sk));
    barrett_reduce(sk,sizeof(sk)/sizeof(sk[0]),0,q448_lo,7,4,62); // TODO word size
    q448_serialize(private, sk);
    
    edwards_comb(&exta, sk, goldilocks_global.combs, 5, 5, 18);
    isogeny_and_serialize(&pk, &exta);
    p448_serialize(public, &pk);
    
    return ret;
}

int
goldilocks_shared_secret(
    uint8_t shared[56],
    const uint8_t private[56],
    const uint8_t public[56]
) {
    // TODO: SHA
    word_t sk[448/WORD_BITS];
    struct p448_t pk;
    
    mask_t succ = p448_deserialize(&pk,public);
    succ &= q448_deserialize(sk,private);
    succ &= p448_montgomery_ladder(&pk,&pk,sk,446,2);
    
    p448_serialize(shared,&pk);
    // TODO: hash
    
    if (succ) {
        return 0;
    } else {
        return -1;
    }
}
