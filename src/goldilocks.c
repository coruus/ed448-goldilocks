/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "config.h"
#include "word.h"

#include <errno.h>

#if GOLDILOCKS_USE_PTHREAD
#include <pthread.h>
#endif

#include "goldilocks.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "crandom.h"
#include "sha512.h"
#include "intrinsics.h"

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

/* FUTURE: auto */
const struct affine_t goldilocks_base_point = {
    {{ U58LE(0xf0de840aed939f), U58LE(0xc170033f4ba0c7),
       U58LE(0xf3932d94c63d96), U58LE(0x9cecfa96147eaa),
       U58LE(0x5f065c3c59d070), U58LE(0x3a6a26adf73324),
       U58LE(0x1b4faff4609845), U58LE(0x297ea0ea2692ff)
    }},
    {{ 19 }}
};

static const char *G_INITING = "initializing";
static const char *G_INITED = "initialized";
static const char *G_FAILED = "failed to initialize";

/* FUTURE: auto */
static const word_t goldi_q448_lo[(224+WORD_BITS-1)/WORD_BITS] = {
    U64LE(0xdc873d6d54a7bb0d),
    U64LE(0xde933d8d723a70aa),
    U64LE(0x3bb124b65129c96f),
    0x8335dc16
};
const struct barrett_prime_t goldi_q448 = {
    448/WORD_BITS,
    62 % WORD_BITS,
    sizeof(goldi_q448_lo)/sizeof(goldi_q448_lo[0]),
    goldi_q448_lo
};

/* FUTURE: auto */
struct {
    const char * volatile state;
#if GOLDILOCKS_USE_PTHREAD
    pthread_mutex_t mutex;
#endif
    struct tw_niels_t combs[(WORD_BITS==64) ? 80 : 64];
    struct fixed_base_table_t fixed_base;
    struct tw_niels_t wnafs[32];
    struct crandom_state_t rand;
} goldilocks_global;

static inline mask_t
goldilocks_check_init() {
    if (likely(goldilocks_global.state == G_INITED)) {
        return MASK_SUCCESS;
    } else {
        return MASK_FAILURE;
    }
}

int
goldilocks_init () {
    const char *res = compare_and_swap(&goldilocks_global.state, NULL, G_INITING);
    if (res == G_INITED) return GOLDI_EALREADYINIT;
    else if (res) {
        return GOLDI_ECORRUPT;
    }

#if GOLDILOCKS_USE_PTHREAD
    int ret = pthread_mutex_init(&goldilocks_global.mutex, NULL);
    if (ret) goto fail;
#endif
    
    struct extensible_t ext;
    struct tw_extensible_t text;
    
    /* Sanity check: the base point is on the curve. */
    assert(validate_affine(&goldilocks_base_point));
    
    /* Convert it to twisted Edwards. */
    convert_affine_to_extensible(&ext, &goldilocks_base_point);
    twist_even(&text, &ext);
    
    /* Precompute the tables. */
    mask_t succ;
    
    int big = (WORD_BITS==64);
    uint64_t n = big ? 5 : 8, t = big ? 5 : 4, s = big ? 18 : 14;

    succ =  precompute_fixed_base(&goldilocks_global.fixed_base, &text, n, t, s, goldilocks_global.combs);
    succ &= precompute_fixed_base_wnaf(goldilocks_global.wnafs, &text, 5);
    
    int criff_res = crandom_init_from_file(&goldilocks_global.rand,
        GOLDILOCKS_RANDOM_INIT_FILE,
        GOLDILOCKS_RANDOM_RESEED_INTERVAL,
        GOLDILOCKS_RANDOM_RESEEDS_MANDATORY);
        
    if (succ & !criff_res) {
        if (!bool_compare_and_swap(&goldilocks_global.state, G_INITING, G_INITED)) {
            abort();
        }
        return 0;
    }
    
    /* it failed! fall though... */

fail:
    if (!bool_compare_and_swap(&goldilocks_global.state, G_INITING, G_FAILED)) {
        /* ok something is seriously wrong */
        abort();
    }
    return -1;
}

static const struct p448_t
sqrt_d_minus_1 = {{
    U58LE(0xd2e21836749f46),
    U58LE(0x888db42b4f0179),
    U58LE(0x5a189aabdeea38),
    U58LE(0x51e65ca6f14c06),
    U58LE(0xa49f7b424d9770),
    U58LE(0xdcac4628c5f656),
    U58LE(0x49443b8748734a),
    U58LE(0x12fec0c0b25b7a)
}};

int
goldilocks_keygen (
    struct goldilocks_private_key_t *privkey,
    struct goldilocks_public_key_t *pubkey
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    word_t sk[448*2/WORD_BITS];
    
    struct tw_extensible_t exta;
    struct p448_t pk;

#if GOLDILOCKS_USE_PTHREAD
    int ml_ret = pthread_mutex_lock(&goldilocks_global.mutex);
    if (ml_ret) return ml_ret;
#endif

    int ret = crandom_generate(&goldilocks_global.rand, (unsigned char *)sk, sizeof(sk));
    int ret2 = crandom_generate(&goldilocks_global.rand, &privkey->opaque[112], 32);
    if (!ret) ret = ret2;

#if GOLDILOCKS_USE_PTHREAD
    ml_ret = pthread_mutex_unlock(&goldilocks_global.mutex);
    if (ml_ret) abort();
#endif
    
    barrett_reduce(sk,sizeof(sk)/sizeof(sk[0]),0,&goldi_q448);
    barrett_serialize(privkey->opaque, sk, 448/8);
    
    scalarmul_fixed_base(&exta, sk, 448, &goldilocks_global.fixed_base);
    //transfer_and_serialize_qtor(&pk, &sqrt_d_minus_1, &exta);
    untwist_and_double_and_serialize(&pk, &exta);
    
    p448_serialize(pubkey->opaque, &pk);
    memcpy(&privkey->opaque[56], pubkey->opaque, 56);
    
    return ret ? GOLDI_ENODICE : GOLDI_EOK;
}

int
goldilocks_private_to_public (
    struct goldilocks_public_key_t *pubkey,
    const struct goldilocks_private_key_t *privkey
) {
    struct p448_t pk;
    mask_t msucc = p448_deserialize(&pk,&privkey->opaque[56]);
    
    if (msucc) {
        p448_serialize(pubkey->opaque, &pk);
        return GOLDI_EOK;
    } else {
        return GOLDI_ECORRUPT;
    }
}

int
goldilocks_shared_secret (
    uint8_t shared[64],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_public_key_t *your_pubkey
) {
    /* This function doesn't actually need anything in goldilocks_global,
     * so it doesn't check init.
     */
    
    word_t sk[448/WORD_BITS];
    struct p448_t pk;
    
    mask_t succ = p448_deserialize(&pk,your_pubkey->opaque), msucc = -1;
    
#ifdef EXPERIMENT_ECDH_STIR_IN_PUBKEYS
    struct p448_t sum, prod;
    msucc &= p448_deserialize(&sum,&my_privkey->opaque[56]);
    p448_mul(&prod,&pk,&sum);
    p448_add(&sum,&pk,&sum);
#endif
    
    msucc &= barrett_deserialize(sk,my_privkey->opaque,&goldi_q448);
    succ &= montgomery_ladder(&pk,&pk,sk,446,2);
    
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
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    /* challenge = H(pk, [nonceG], message). */
    word_t skw[448/WORD_BITS];
    mask_t succ = barrett_deserialize(skw,privkey->opaque,&goldi_q448);
    if (!succ) {
        memset(skw,0,sizeof(skw));
        return GOLDI_ECORRUPT;
    }
        
    /* Derive a nonce.  TODO: use HMAC. FUTURE: factor. */
    unsigned char sha_out[512/8];
    word_t tk[448/WORD_BITS];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, (const unsigned char *)"signonce", 8);
    sha512_update(&ctx, &privkey->opaque[112], 32);
    sha512_update(&ctx, message, message_len);
    sha512_update(&ctx, &privkey->opaque[112], 32);
    sha512_final(&ctx, sha_out);
    barrett_deserialize_and_reduce(tk, sha_out, 512/8, &goldi_q448);
    
    /* 4[nonce]G */
    uint8_t signature_tmp[56];
    struct tw_extensible_t exta;
    struct p448_t gsk;
    scalarmul_fixed_base(&exta, tk, 448, &goldilocks_global.fixed_base);
    double_tw_extensible(&exta);
    untwist_and_double_and_serialize(&gsk, &exta);
    p448_serialize(signature_tmp, &gsk);
    
    word_t challenge[448/WORD_BITS];
    sha512_update(&ctx, &privkey->opaque[56], 56);
    sha512_update(&ctx, signature_tmp, 56);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, sha_out);
    barrett_deserialize_and_reduce(challenge, sha_out, 512/8, &goldi_q448);
    
    // reduce challenge and sub.
    barrett_negate(challenge,448/WORD_BITS,&goldi_q448);

    barrett_mac(
        tk,448/WORD_BITS,
        challenge,448/WORD_BITS,
        skw,448/WORD_BITS,
        &goldi_q448
    );
        
    word_t carry = add_nr_ext_packed(tk,tk,448/WORD_BITS,tk,448/WORD_BITS,-1);
    barrett_reduce(tk,448/WORD_BITS,carry,&goldi_q448);
        
    memcpy(signature_out, signature_tmp, 56);
    barrett_serialize(signature_out+56, tk, 448/8);
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
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    struct p448_t pk;
    word_t s[448/WORD_BITS];
    
    mask_t succ = p448_deserialize(&pk,pubkey->opaque);
    if (!succ) return GOLDI_EINVAL;
    
    succ = barrett_deserialize(s, &signature[56], &goldi_q448);
    if (!succ) return GOLDI_EINVAL;
    
    /* challenge = H(pk, [nonceG], message). */
    unsigned char sha_out[512/8];
    word_t challenge[448/WORD_BITS];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, pubkey->opaque, 56);
    sha512_update(&ctx, signature, 56);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, sha_out);
    barrett_deserialize_and_reduce(challenge, sha_out, 512/8, &goldi_q448);
    
    struct p448_t eph;
    struct tw_extensible_t pk_text;
    
    /* deserialize [nonce]G */
    succ = p448_deserialize(&eph, signature);
    if (!succ) return GOLDI_EINVAL;
    
    succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
    if (!succ) return GOLDI_EINVAL;
    
    linear_combo_var_fixed_vt( &pk_text, challenge, 446, s, 446, goldilocks_global.wnafs, 5 );
    
    untwist_and_double_and_serialize( &pk, &pk_text );
    p448_sub(&eph, &eph, &pk);
    p448_bias(&eph, 2);
    
    succ = p448_is_zero(&eph);
    
    return succ ? 0 : GOLDI_EINVAL;
}
