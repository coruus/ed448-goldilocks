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
#include "intrinsics.h"
#include "hash.h"

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

#define GOLDI_FIELD_WORDS ((GOLDI_FIELD_BITS + WORD_BITS - 1) / (WORD_BITS))
#define GOLDI_DIVERSIFY_BYTES 8

/* FUTURE: auto.  MAGIC */
const struct affine_t goldilocks_base_point = {{{U58LE(0xf0de840aed939f),
                                                 U58LE(0xc170033f4ba0c7),
                                                 U58LE(0xf3932d94c63d96),
                                                 U58LE(0x9cecfa96147eaa),
                                                 U58LE(0x5f065c3c59d070),
                                                 U58LE(0x3a6a26adf73324),
                                                 U58LE(0x1b4faff4609845),
                                                 U58LE(0x297ea0ea2692ff)}},
                                               {{19}}};

/* These are just unique identifiers */
static const char* G_INITING = "initializing";
static const char* G_INITED = "initialized";
static const char* G_FAILED = "failed to initialize";

/* Domain separators for hashs. */
// mkk(key, p) = Rijndael256(mbrpad(key, 32), mbrpad(p, 32))
// mkk(k="Ed448-Goldilocks", p="Challenge.")
static const uint8_t goldi_challenge[32] = {0xac,0x46,0x28,0x71,0x24,0x3d,0x9f,0x18,0x85,0x93,0x3a,0x3d,0xce,0x96,0x5b,0x9f,0x73,0x2f,0x40,0x59,0xf7,0x2a,0x1b,0x2a,0xff,0x12,0x20,0x20,0x8a,0x5e,0xf7,0xc0};
// mkk(k="Ed448-Goldilocks", p="Sign once.")
static const uint8_t goldi_signonce[32] = {0xe1,0xa2,0xca,0x66,0xca,0x11,0xe4,0x0c,0xd8,0x60,0x19,0x3c,0xab,0x1d,0x2b,0xc5,0x02,0x0e,0xc4,0x33,0x14,0x59,0x1d,0x04,0x70,0x89,0xfe,0xc8,0x4a,0x6a,0xc8,0xce};
// mkk(k="Ed448-Goldilocks", p="Derive private key.")
static const uint8_t goldi_derivepk[32] = {0x09,0x82,0xb2,0x7b,0x0e,0x68,0x30,0x45,0x33,0xb6,0xa6,0xcf,0x83,0x05,0x67,0x1f,0x8a,0xe1,0x13,0xdc,0xdd,0xed,0x90,0xeb,0x13,0xa1,0x21,0x44,0xec,0xaa,0xd1,0xb5};


/* FUTURE: auto.  MAGIC */
static const word_t goldi_q448_lo[(224 + WORD_BITS - 1) / WORD_BITS] = {
    U64LE(0xdc873d6d54a7bb0d),
    U64LE(0xde933d8d723a70aa),
    U64LE(0x3bb124b65129c96f),
    0x8335dc16};

extern const struct barrett_prime_t goldi_q448 = {
    GOLDI_FIELD_WORDS,
    62 % WORD_BITS,
    sizeof(goldi_q448_lo) / sizeof(goldi_q448_lo[0]),
    goldi_q448_lo};

/* MAGIC */
static const struct p448_t sqrt_d_minus_1 = {{U58LE(0xd2e21836749f46),
                                              U58LE(0x888db42b4f0179),
                                              U58LE(0x5a189aabdeea38),
                                              U58LE(0x51e65ca6f14c06),
                                              U58LE(0xa49f7b424d9770),
                                              U58LE(0xdcac4628c5f656),
                                              U58LE(0x49443b8748734a),
                                              U58LE(0x12fec0c0b25b7a)}};

struct goldilocks_precomputed_public_key_t {
  struct goldilocks_public_key_t pub;
  struct fixed_base_table_t table;
};

#ifndef USE_BIG_TABLES
#ifdef __ARM_NEON__
#define USE_BIG_TABLES 1
#else
#define USE_BIG_TABLES (WORD_BITS == 64)
#endif
#endif

/* FUTURE: auto.  MAGIC */
struct {
  const char* volatile state;
#if GOLDILOCKS_USE_PTHREAD
  pthread_mutex_t mutex;
#endif
  struct tw_niels_t combs[USE_BIG_TABLES ? 80 : 64];
  struct fixed_base_table_t fixed_base;
  struct tw_niels_t wnafs[32];
  struct crandom_state_t rand;
} goldilocks_global;

static inline mask_t goldilocks_check_init() {
  if (likely(goldilocks_global.state == G_INITED)) {
    return MASK_SUCCESS;
  } else {
    return MASK_FAILURE;
  }
}

int goldilocks_init(void) {
  const char* res = compare_and_swap(&goldilocks_global.state, NULL, G_INITING);
  if (res == G_INITED)
    return GOLDI_EALREADYINIT;
  else if (res) {
    return GOLDI_ECORRUPT;
  }

#if GOLDILOCKS_USE_PTHREAD
  int ret = pthread_mutex_init(&goldilocks_global.mutex, NULL);
  if (ret)
    goto fail;
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

  int big = USE_BIG_TABLES;
  uint64_t n = big ? 5 : 8, t = big ? 5 : 4, s = big ? 18 : 14;

  succ = precompute_fixed_base(
      &goldilocks_global.fixed_base, &text, n, t, s, goldilocks_global.combs);
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

int goldilocks_derive_private_key(struct goldilocks_private_key_t* privkey,
                                  const uint8_t proto[GOLDI_SYMKEY_BYTES]) {
  if (!goldilocks_check_init()) {
    return GOLDI_EUNINIT;
  }

  memcpy(&privkey->opaque[2 * GOLDI_FIELD_BYTES], proto, GOLDI_SYMKEY_BYTES);

  uint8_t skb[HASH_OUTPUT_BYTES];
  word_t sk[GOLDI_FIELD_WORDS];
  assert(sizeof(skb) >= sizeof(sk));

  hash_ctx_t ctx;
  struct tw_extensible_t exta;
  struct p448_t pk;

  /* pk = H(proto, goldi_derivepk) */
  hash_init(&ctx);
  hash_update(&ctx, proto, GOLDI_SYMKEY_BYTES);
  hash_update(&ctx, goldi_derivepk, 32);
  hash_digest(&ctx, (uint8_t*)skb, HASH_OUTPUT_BYTES);

  barrett_deserialize_and_reduce(sk, skb, HASH_OUTPUT_BYTES, &goldi_q448);
  barrett_serialize(privkey->opaque, sk, GOLDI_FIELD_BYTES);

  scalarmul_fixed_base(&exta, sk, GOLDI_SCALAR_BITS, &goldilocks_global.fixed_base);
  untwist_and_double_and_serialize(&pk, &exta);

  p448_serialize(&privkey->opaque[GOLDI_FIELD_BYTES], &pk);

  return GOLDI_EOK;
}

void goldilocks_underive_private_key(uint8_t proto[GOLDI_SYMKEY_BYTES],
                                     const struct goldilocks_private_key_t* privkey) {
  memcpy(proto, &privkey->opaque[2 * GOLDI_FIELD_BYTES], GOLDI_SYMKEY_BYTES);
}

int goldilocks_keygen(struct goldilocks_private_key_t* privkey,
                      struct goldilocks_public_key_t* pubkey) {
  if (!goldilocks_check_init()) {
    return GOLDI_EUNINIT;
  }

  uint8_t proto[GOLDI_SYMKEY_BYTES];

#if GOLDILOCKS_USE_PTHREAD
  int ml_ret = pthread_mutex_lock(&goldilocks_global.mutex);
  if (ml_ret)
    return ml_ret;
#endif

  int ret = crandom_generate(&goldilocks_global.rand, proto, sizeof(proto));

#if GOLDILOCKS_USE_PTHREAD
  ml_ret = pthread_mutex_unlock(&goldilocks_global.mutex);
  if (ml_ret)
    abort();
#endif

  int ret2 = goldilocks_derive_private_key(privkey, proto);
  if (!ret)
    ret = ret2;

  ret2 = goldilocks_private_to_public(pubkey, privkey);
  if (!ret)
    ret = ret2;

  return ret ? GOLDI_ENODICE : GOLDI_EOK;
}

int goldilocks_private_to_public(struct goldilocks_public_key_t* pubkey,
                                 const struct goldilocks_private_key_t* privkey) {
  struct p448_t pk;
  mask_t msucc = p448_deserialize(&pk, &privkey->opaque[GOLDI_FIELD_BYTES]);

  if (msucc) {
    p448_serialize(pubkey->opaque, &pk);
    return GOLDI_EOK;
  } else {
    return GOLDI_ECORRUPT;
  }
}

static int goldilocks_shared_secret_core(
    uint8_t* shared, size_t sharedlen,
    const struct goldilocks_private_key_t* my_privkey,
    const struct goldilocks_public_key_t* your_pubkey,
    const struct goldilocks_precomputed_public_key_t* pre) {
  /* This function doesn't actually need anything in goldilocks_global,
   * so it doesn't check init.
   */

  assert(GOLDI_SHARED_SECRET_BYTES == HASH_OUTPUT_BYTES);

  word_t sk[GOLDI_FIELD_WORDS];
  struct p448_t pk;

  mask_t succ = p448_deserialize(&pk, your_pubkey->opaque), msucc = -1;

#ifdef EXPERIMENT_ECDH_STIR_IN_PUBKEYS
  struct p448_t sum, prod;
  msucc &= p448_deserialize(&sum, &my_privkey->opaque[GOLDI_FIELD_BYTES]);
  p448_mul(&prod, &pk, &sum);
  p448_add(&sum, &pk, &sum);
#endif

  msucc &= barrett_deserialize(sk, my_privkey->opaque, &goldi_q448);

#if GOLDI_IMPLEMENT_PRECOMPUTED_KEYS
  if (pre) {
    struct tw_extensible_t tw;
    succ &= scalarmul_fixed_base(&tw, sk, GOLDI_SCALAR_BITS, &pre->table);
    untwist_and_double_and_serialize(&pk, &tw);
  } else {
    succ &= montgomery_ladder(&pk, &pk, sk, GOLDI_SCALAR_BITS, 1);
  }
#else
  (void)pre;
  succ &= montgomery_ladder(&pk, &pk, sk, GOLDI_SCALAR_BITS, 1);
#endif

  p448_serialize(shared, &pk);

  // Initialize sponge.
  hash_ctx_t ctx;
  hash_init(&ctx);

#ifdef EXPERIMENT_ECDH_OBLITERATE_CT
  /* obliterate records of our failure by adjusting with obliteration key */
  uint8_t oblit[GOLDI_DIVERSIFY_BYTES + GOLDI_SYMKEY_BYTES];
  unsigned i;
  for (i = 0; i < GOLDI_DIVERSIFY_BYTES; i++) {
    oblit[i] = "noshared"[i] & ~(succ & msucc);
  }
  for (i = 0; i < GOLDI_SYMKEY_BYTES; i++) {
    oblit[GOLDI_DIVERSIFY_BYTES + i] =
        my_privkey->opaque[2 * GOLDI_FIELD_BYTES + i] & ~(succ & msucc);
  }
  hash_update(&ctx, oblit, sizeof(oblit));
#endif

#ifdef EXPERIMENT_ECDH_STIR_IN_PUBKEYS
  /* stir in the sum and product of the pubkeys */
  uint8_t a_pk[GOLDI_FIELD_BYTES];
  p448_serialize(a_pk, &sum);
  hash_update(&ctx, a_pk, GOLDI_FIELD_BYTES);
  p448_serialize(a_pk, &prod);
  hash_update(&ctx, a_pk, GOLDI_FIELD_BYTES);
#endif

  /* stir in the shared key and finish */
  hash_update(&ctx, shared, GOLDI_FIELD_BYTES);
  hash_digest(&ctx, shared, sharedlen);

  return (GOLDI_ECORRUPT & ~msucc) | (GOLDI_EINVAL & msucc & ~succ) |
         (GOLDI_EOK & msucc & succ);
}

int goldilocks_shared_secret(uint8_t* shared,
                             size_t sharedlen,
                             const struct goldilocks_private_key_t* my_privkey,
                             const struct goldilocks_public_key_t* your_pubkey) {
  return goldilocks_shared_secret_core(shared, sharedlen, my_privkey,
                                       your_pubkey, NULL);
}

static inline void goldilocks_beforegn(hash_ctx_t* ctx, const uint8_t* message,
    size_t messagelen) {
  hash_init(ctx);
  hash_update(ctx, message, messagelen);
}

static inline void goldilocks_aftergn(word_t challenge[GOLDI_FIELD_WORDS],
                                      const hash_ctx_t* mctx,
                                      const uint8_t pubkey[GOLDI_FIELD_BYTES],
                                      const uint8_t gnonce[GOLDI_FIELD_BYTES]) {
  // Clone the sponge.
  hash_ctx_t ctx;
  memcpy(&ctx, mctx, sizeof(hash_ctx_t));

  hash_update(&ctx, gnonce, GOLDI_FIELD_BYTES);
  hash_update(&ctx, pubkey, GOLDI_FIELD_BYTES);
  hash_update(&ctx, goldi_challenge, 32);

  uint8_t hash_out[HASH_OUTPUT_BYTES];
  hash_digest(&ctx, hash_out, HASH_OUTPUT_BYTES);
  barrett_deserialize_and_reduce(challenge, hash_out, sizeof(hash_out), &goldi_q448);
}

static void goldilocks_derive_challenge(word_t challenge[GOLDI_FIELD_WORDS],
                                        const uint8_t pubkey[GOLDI_FIELD_BYTES],
                                        const uint8_t gnonce[GOLDI_FIELD_BYTES],
                                        const uint8_t* message,
                                        uint64_t message_len) {
  /* challenge = H(message, [nonceG], pubkey, goldi_challenge). */
  hash_ctx_t ctx;
  goldilocks_beforegn(&ctx, message, message_len);
  goldilocks_aftergn(challenge, &ctx, pubkey, gnonce);
}

int goldilocks_sign(uint8_t signature_out[GOLDI_SIGNATURE_BYTES],
                    const uint8_t* message,
                    uint64_t message_len,
                    const struct goldilocks_private_key_t* privkey) {
  if (!goldilocks_check_init()) {
    return GOLDI_EUNINIT;
  }

  /* challenge = H(pk, [nonceG], message). */
  word_t skw[GOLDI_FIELD_WORDS];
  mask_t succ = barrett_deserialize(skw, privkey->opaque, &goldi_q448);
  if (!succ) {
    memset(skw, 0, sizeof(skw));
    return GOLDI_ECORRUPT;
  }

  /* Derive a nonce.  TODO: use HMAC. FUTURE: factor. */
  uint8_t hash_out[HASH_OUTPUT_BYTES];
  word_t tk[GOLDI_FIELD_WORDS];
  hash_ctx_t ctx, mctx;
  // Hash the message.
  goldilocks_beforegn(&mctx, message, message_len);
  // Clone the state.
  memcpy(&ctx, &mctx, sizeof(hash_ctx_t));

  /* nonce = H(message, privkey, goldi_signonce); */
  hash_update(&ctx, &privkey->opaque[2 * GOLDI_FIELD_BYTES], GOLDI_SYMKEY_BYTES);
  hash_update(&ctx, goldi_signonce, 32);
  hash_digest(&ctx, hash_out, HASH_OUTPUT_BYTES);
  barrett_deserialize_and_reduce(tk, hash_out, HASH_OUTPUT_BYTES, &goldi_q448);

  /* 4[nonce]G */
  uint8_t signature_tmp[GOLDI_FIELD_BYTES];
  struct tw_extensible_t exta;
  struct p448_t gsk;
  scalarmul_fixed_base(&exta, tk, GOLDI_SCALAR_BITS, &goldilocks_global.fixed_base);
  double_tw_extensible(&exta);
  untwist_and_double_and_serialize(&gsk, &exta);
  p448_serialize(signature_tmp, &gsk);

  // Continue deriving challenge from cloned message sponge.
  word_t challenge[GOLDI_FIELD_WORDS];
  hash_update(&mctx, signature_tmp, GOLDI_FIELD_BYTES);
  hash_update(&mctx, &privkey->opaque[GOLDI_FIELD_BYTES], GOLDI_FIELD_BYTES);
  hash_update(&mctx, goldi_challenge, 32);
  hash_digest(&mctx, hash_out, HASH_OUTPUT_BYTES);
  barrett_deserialize_and_reduce(challenge, hash_out, sizeof(hash_out), &goldi_q448);

/*  goldilocks_derive_challenge(challenge,
                              &privkey->opaque[GOLDI_FIELD_BYTES], // pubkey
                              signature_tmp,                       // [nonceG]
                              message,
                              message_len);*/

  // reduce challenge and sub.
  barrett_negate(challenge, GOLDI_FIELD_WORDS, &goldi_q448);

  barrett_mac(tk,
              GOLDI_FIELD_WORDS,
              challenge,
              GOLDI_FIELD_WORDS,
              skw,
              GOLDI_FIELD_WORDS,
              &goldi_q448);

  word_t carry = add_nr_ext_packed(tk, tk, GOLDI_FIELD_WORDS, tk, GOLDI_FIELD_WORDS, -1);
  barrett_reduce(tk, GOLDI_FIELD_WORDS, carry, &goldi_q448);

  memcpy(signature_out, signature_tmp, GOLDI_FIELD_BYTES);
  barrett_serialize(signature_out + GOLDI_FIELD_BYTES, tk, GOLDI_FIELD_BYTES);
  memset((uint8_t*)tk, 0, sizeof(tk));
  memset((uint8_t*)skw, 0, sizeof(skw));
  memset((uint8_t*)challenge, 0, sizeof(challenge));
  memset(&ctx, 0, sizeof(hash_ctx_t));
  memset(&mctx, 0, sizeof(hash_ctx_t));

  /* response = 2(nonce_secret - sk*challenge)
   * Nonce = 8[nonce_secret]*G
   * PK = 2[sk]*G, except doubled (TODO)
   * so [2] ( [response]G + 2[challenge]PK ) = Nonce
   */

  return 0;
}

int goldilocks_verify(const uint8_t signature[GOLDI_SIGNATURE_BYTES],
                      const uint8_t* message,
                      uint64_t message_len,
                      const struct goldilocks_public_key_t* pubkey) {
  if (!goldilocks_check_init()) {
    return GOLDI_EUNINIT;
  }

  struct p448_t pk;
  word_t s[GOLDI_FIELD_WORDS];

  mask_t succ = p448_deserialize(&pk, pubkey->opaque);
  if (!succ)
    return GOLDI_EINVAL;

  succ = barrett_deserialize(s, &signature[GOLDI_FIELD_BYTES], &goldi_q448);
  if (!succ)
    return GOLDI_EINVAL;

  word_t challenge[GOLDI_FIELD_WORDS];
  goldilocks_derive_challenge(challenge, pubkey->opaque, signature, message, message_len);

  struct p448_t eph;
  struct tw_extensible_t pk_text;

  /* deserialize [nonce]G */
  succ = p448_deserialize(&eph, signature);
  if (!succ)
    return GOLDI_EINVAL;

  succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
  if (!succ)
    return GOLDI_EINVAL;

  linear_combo_var_fixed_vt(&pk_text,
                            challenge,
                            GOLDI_SCALAR_BITS,
                            s,
                            GOLDI_SCALAR_BITS,
                            goldilocks_global.wnafs,
                            5);

  untwist_and_double_and_serialize(&pk, &pk_text);
  p448_sub(&eph, &eph, &pk);
  p448_bias(&eph, 2);

  succ = p448_is_zero(&eph);

  return succ ? 0 : GOLDI_EINVAL;
}

#if GOLDI_IMPLEMENT_PRECOMPUTED_KEYS

struct goldilocks_precomputed_public_key_t* goldilocks_precompute_public_key(
    const struct goldilocks_public_key_t* pub) {
  struct goldilocks_precomputed_public_key_t* precom;
  precom = (struct goldilocks_precomputed_public_key_t*)malloc(sizeof(*precom));

  if (!precom)
    return NULL;

  struct tw_extensible_t pk_text;

  struct p448_t pk;
  mask_t succ = p448_deserialize(&pk, pub->opaque);
  if (!succ) {
    free(precom);
    return NULL;
  }

  succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
  if (!succ) {
    free(precom);
    return NULL;
  }

  int big = USE_BIG_TABLES;
  uint64_t n = big ? 5 : 8, t = big ? 5 : 4, s = big ? 18 : 14;

  succ = precompute_fixed_base(&precom->table, &pk_text, n, t, s, NULL);
  if (!succ) {
    free(precom);
    return NULL;
  }

  memcpy(&precom->pub, pub, sizeof(*pub));

  return precom;
}

void goldilocks_destroy_precomputed_public_key(
    struct goldilocks_precomputed_public_key_t* precom) {
  if (!precom)
    return;
  destroy_fixed_base(&precom->table);
  memset(&precom->pub.opaque, 0, sizeof(precom->pub));
  free(precom);
}

int goldilocks_verify_precomputed(
    const uint8_t signature[GOLDI_SIGNATURE_BYTES],
    const uint8_t* message,
    uint64_t message_len,
    const struct goldilocks_precomputed_public_key_t* pubkey) {
  if (!goldilocks_check_init()) {
    return GOLDI_EUNINIT;
  }

  word_t s[GOLDI_FIELD_WORDS];
  mask_t succ = barrett_deserialize(s, &signature[GOLDI_FIELD_BYTES], &goldi_q448);
  if (!succ)
    return GOLDI_EINVAL;

  word_t challenge[GOLDI_FIELD_WORDS];
  goldilocks_derive_challenge(
      challenge, pubkey->pub.opaque, signature, message, message_len);

  struct p448_t eph, pk;
  struct tw_extensible_t pk_text;

  /* deserialize [nonce]G */
  succ = p448_deserialize(&eph, signature);
  if (!succ)
    return GOLDI_EINVAL;

  succ = linear_combo_combs_vt(&pk_text,
                               challenge,
                               GOLDI_SCALAR_BITS,
                               &pubkey->table,
                               s,
                               GOLDI_SCALAR_BITS,
                               &goldilocks_global.fixed_base);
  if (!succ)
    return GOLDI_EINVAL;

  untwist_and_double_and_serialize(&pk, &pk_text);
  p448_sub(&eph, &eph, &pk);
  p448_bias(&eph, 2);

  succ = p448_is_zero(&eph);

  return succ ? 0 : GOLDI_EINVAL;
}

int goldilocks_shared_secret_precomputed(
    uint8_t* shared, size_t sharedlen,
    const struct goldilocks_private_key_t* my_privkey,
    const struct goldilocks_precomputed_public_key_t* your_pubkey) {
  return goldilocks_shared_secret_core(shared, sharedlen, my_privkey,
                                       &your_pubkey->pub, your_pubkey);
}

#endif  // GOLDI_IMPLEMENT_PRECOMPUTED_KEYS
