/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#include <errno.h>

#include "goldilocks.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "crandom.h"
#include "sha512.h"

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

// /* TODO: direct */
// void
// transfer_and_serialize(struct p448_t *out, const struct tw_extensible_t *twext) {
//     struct extensible_t ext;
//     transfer_tw_to_un(&ext, twext);
//     serialize_extensible(out, &ext);
// }

// FIXME: threading
// TODO: autogen instead of init
struct {
    struct tw_niels_t combs[80];
    struct tw_niels_t wnafs[32];
    struct crandom_state_t rand;
} goldilocks_global;

int
goldilocks_init () {
    struct extensible_t ext;
    struct tw_extensible_t text;
    
    /* Sanity check: the base point is on the curve. */
    assert(validate_affine(&goldilocks_base_point));
    
    /* Convert it to twisted Edwards. */
    convert_affine_to_extensible(&ext, &goldilocks_base_point);
    twist(&text, &ext);
    //p448_transfer_un_to_tw(&text, &ext);
    
    /* Precompute the tables. */
    precompute_for_combs(goldilocks_global.combs, &text, 5, 5, 18);
    precompute_for_wnaf(goldilocks_global.wnafs, &text, 5);
    
    return crandom_init_from_file(&goldilocks_global.rand,
        GOLDILOCKS_RANDOM_INIT_FILE,
        GOLDILOCKS_RANDOM_RESEED_INTERVAL,
        GOLDILOCKS_RANDOM_RESEEDS_MANDATORY);
}

static word_t
q448_lo[4] = {
    0xdc873d6d54a7bb0dull,
    0xde933d8d723a70aaull,
    0x3bb124b65129c96full,
    0x000000008335dc16ull
};

static const struct p448_t
sqrt_d_minus_1 = {{
    0xd2e21836749f46ull,
    0x888db42b4f0179ull,
    0x5a189aabdeea38ull,
    0x51e65ca6f14c06ull,
    0xa49f7b424d9770ull,
    0xdcac4628c5f656ull,
    0x49443b8748734aull,
    0x12fec0c0b25b7aull
}};

int
goldilocks_keygen (
    struct goldilocks_private_key_t *privkey,
    struct goldilocks_public_key_t *pubkey
) {
    // TODO: check for init.  Also maybe take CRANDOM object?  API...
    word_t sk[448*2/WORD_BITS];
    
    struct tw_extensible_t exta;
    struct p448_t pk;
    
    int ret = crandom_generate(&goldilocks_global.rand, (unsigned char *)sk, sizeof(sk));
    barrett_reduce(sk,sizeof(sk)/sizeof(sk[0]),0,q448_lo,7,4,62); // TODO word size
    q448_serialize(privkey->opaque, sk);
    
    edwards_comb(&exta, sk, goldilocks_global.combs, 5, 5, 18);
    //transfer_and_serialize_qtor(&pk, &sqrt_d_minus_1, &exta);
    untwist_and_double_and_serialize(&pk, &exta);
    
    p448_serialize(pubkey->opaque, &pk);
    memcpy(&privkey->opaque[56], pubkey->opaque, 56);
    
    int ret2 = crandom_generate(&goldilocks_global.rand, &privkey->opaque[112], 32);
    if (!ret) ret = ret2;
    
    return ret ? GOLDI_ENODICE : GOLDI_EOK;
}

int
goldilocks_shared_secret (
    uint8_t shared[64],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_public_key_t *your_pubkey
) {
    word_t sk[448/WORD_BITS];
    struct p448_t pk;
    
    mask_t succ = p448_deserialize(&pk,your_pubkey->opaque), msucc = -1;
    
#ifdef EXPERIMENT_ECDH_STIR_IN_PUBKEYS
    struct p448_t sum, prod;
    msucc &= p448_deserialize(&sum,&my_privkey->opaque[56]);
    p448_mul(&prod,&pk,&sum);
    p448_add(&sum,&pk,&sum);
#endif
    
    msucc &= q448_deserialize(sk,my_privkey->opaque);
    succ &= p448_montgomery_ladder(&pk,&pk,sk,446,2);
    
    p448_serialize(shared,&pk);
    
    /* obliterate records of our failure by adjusting with obliteration key */
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);

#ifdef EXPERIMENT_ECDH_OBLITERATE_CT
    uint8_t oblit[40];
    unsigned i;
    for (i=0; i<8; i++) {
        oblit[i] = "noshared"[i] & ~(succ&msucc);
    }
    for (i=0; i<32; i++) {
        oblit[8+i] = my_privkey->opaque[112+i] & ~(succ&msucc);
    }
    sha512_update(&ctx, oblit, 40);
#endif
    
#ifdef EXPERIMENT_ECDH_STIR_IN_PUBKEYS
    /* stir in the sum and product of the pubkeys. */
    uint8_t a_pk[56];
    p448_serialize(a_pk, &sum);
    sha512_update(&ctx, a_pk, 56);
    p448_serialize(a_pk, &prod);
    sha512_update(&ctx, a_pk, 56);
#endif
       
    /* stir in the shared key and finish */
    sha512_update(&ctx, shared, 56);
    sha512_final(&ctx, shared);
    
    return (GOLDI_ECORRUPT & ~msucc)
        | (GOLDI_EINVAL & msucc &~ succ)
        | (GOLDI_EOK & msucc & succ);
}

int
goldilocks_sign (
    uint8_t signature_out[56*2],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_private_key_t *privkey
) {
    
    /* challenge = H(pk, [nonceG], message).  FIXME: endian. */
    word_t skw[448/WORD_BITS];
    mask_t succ = q448_deserialize(skw,privkey->opaque);
    if (!succ) {
        memset(skw,0,sizeof(skw));
        return GOLDI_ECORRUPT;
    }
        
    /* Derive a nonce.  TODO: use HMAC. FIXME: endian.  FUTURE: factor. */
    word_t tk[512/WORD_BITS];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, (const unsigned char *)"signonce", 8);
    sha512_update(&ctx, &privkey->opaque[112], 32);
    sha512_update(&ctx, message, message_len);
    sha512_update(&ctx, &privkey->opaque[112], 32);
    sha512_final(&ctx, (unsigned char *)tk);
    barrett_reduce(tk,512/WORD_BITS,0,q448_lo,7,4,62); // TODO word size
    
    /* 4[nonce]G */
    uint8_t signature_tmp[56];
    struct tw_extensible_t exta;
    struct p448_t gsk;
    edwards_comb(&exta, tk, goldilocks_global.combs, 5, 5, 18);
    double_tw_extensible(&exta);
    untwist_and_double_and_serialize(&gsk, &exta);
    p448_serialize(signature_tmp, &gsk);
    
    word_t challenge[512/WORD_BITS];
    sha512_update(&ctx, &privkey->opaque[56], 56);
    sha512_update(&ctx, signature_tmp, 56);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, (unsigned char *)challenge);
    
    // reduce challenge and sub.
    barrett_negate(challenge,512/WORD_BITS,q448_lo,7,4,62);

    barrett_mac(
        tk,512/WORD_BITS,
        challenge,512/WORD_BITS,
        skw,448/WORD_BITS,
        q448_lo,7,4,62
    );
        
    word_t carry = add_nr_ext_packed(tk,tk,512/WORD_BITS,tk,512/WORD_BITS,-1);
    barrett_reduce(tk,512/WORD_BITS,carry,q448_lo,7,4,62);
        
    memcpy(signature_out, signature_tmp, 56);
    q448_serialize(signature_out+56, tk);
    memset((unsigned char *)tk,0,sizeof(tk));
    memset((unsigned char *)skw,0,sizeof(skw));
    memset((unsigned char *)challenge,0,sizeof(challenge));
    
    /* response = 2(nonce_secret - sk*challenge)
     * Nonce = 8[nonce_secret]*G
     * PK = 2[sk]*G, except doubled (TODO)
     * so [2] ( [response]G + 2[challenge]PK ) = Nonce
     */
    
    return 0;
}

int
goldilocks_verify (
    const uint8_t signature[56*2],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_public_key_t *pubkey
) {
    struct p448_t pk;
    word_t s[448/WORD_BITS];
    
    mask_t succ = p448_deserialize(&pk,pubkey->opaque);
    if (!succ) return EINVAL;
    
    succ = q448_deserialize(s, &signature[56]);
    if (!succ) return EINVAL;
    
    /* challenge = H(pk, [nonceG], message).  FIXME: endian. */
    word_t challenge[512/WORD_BITS];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, pubkey->opaque, 56);
    sha512_update(&ctx, signature, 56);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, (unsigned char *)challenge);
    barrett_reduce(challenge,512/WORD_BITS,0,q448_lo,7,4,62);
    
    struct p448_t eph;
    struct tw_extensible_t pk_text;
    
    /* deserialize [nonce]G */
    succ = p448_deserialize(&eph, signature);
    if (!succ) return EINVAL;
    
    
    // succ = affine_deserialize(&pk_aff,&pk);
    // if (!succ) return EINVAL;
    // 
    // convert_affine_to_extensible(&pk_ext,&pk_aff);
    // transfer_un_to_tw(&pk_text,&pk_ext);
    succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
    if (!succ) return EINVAL;
    
    edwards_combo_var_fixed_vt( &pk_text, challenge, s, goldilocks_global.wnafs, 5 );
    
    untwist_and_double_and_serialize( &pk, &pk_text );
    p448_sub(&eph, &eph, &pk);
    p448_bias(&eph, 2);
    
    succ = p448_is_zero(&eph);
    
    return succ ? 0 : GOLDI_EINVAL;
}
