/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "word.h"

#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <memory.h>

#include "p448.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "crandom.h"
#include "goldilocks.h"
#include "sha512.h"

static __inline__ void ignore_result(int result) {
  (void)result;
}

static double now() {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

static void p448_randomize(struct crandom_state_t* crand, struct p448_t* a) {
  crandom_generate(crand, (unsigned char*)a, sizeof(*a));
  p448_strong_reduce(a);
}

static void q448_randomize(struct crandom_state_t* crand, word_t sk[448 / WORD_BITS]) {
  crandom_generate(crand, (unsigned char*)sk, 448 / 8);
}

static void p448_print(const char* descr, const struct p448_t* a) {
  p448_t b;
  p448_copy(&b, a);
  p448_strong_reduce(&b);
  int j;
  printf("%s = 0x", descr);
  for (j = sizeof(*a) / sizeof(a->limb[0]) - 1; j >= 0; j--) {
    printf(PRIxWORD58, b.limb[j]);
  }
  printf("\n");
}

static void __attribute__((unused))
p448_print_full(const char* descr, const struct p448_t* a) {
  int j;
  printf("%s = 0x", descr);
  for (j = 15; j >= 0; j--) {
    printf("%02" PRIxWORD "_" PRIxWORD58 " ",
           a->limb[j] >> 28,
           a->limb[j] & ((1 << 28) - 1));
  }
  printf("\n");
}

static void q448_print(const char* descr, const word_t secret[448 / WORD_BITS]) {
  int j;
  printf("%s = 0x", descr);
  for (j = 448 / WORD_BITS - 1; j >= 0; j--) {
    printf(PRIxWORDfull, secret[j]);
  }
  printf("\n");
}

#ifndef N_TESTS_BASE
#define N_TESTS_BASE 10000
#endif

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  struct tw_extensible_t ext;
  struct extensible_t exta;
  struct tw_niels_t niels;
  struct tw_pniels_t pniels;
  struct affine_t affine;
  struct montgomery_t mb;
  struct p448_t a, b, c, d;

  double when;
  int i;

  int nbase = N_TESTS_BASE;

  /* Bad randomness so we can debug. */
  char initial_seed[32];
  for (i = 0; i < 32; i++) initial_seed[i] = i;
  struct crandom_state_t crand;
  crandom_init_from_buffer(&crand, initial_seed);
  /* For testing the performance drop from the crandom debuffering change.
      ignore_result(crandom_init_from_file(&crand, "/dev/urandom", 10000, 1));
  */

  word_t sk[448 / WORD_BITS], tk[448 / WORD_BITS];
  q448_randomize(&crand, sk);

  when = now();
  for (i = 0; i < nbase * 1000; i++) {
    p448_mul(&c, &b, &a);
  }
  when = now() - when;
  printf("mul:         %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 1000; i++) {
    p448_sqr(&c, &a);
  }
  when = now() - when;
  printf("sqr:         %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 500; i++) {
    p448_mul(&c, &b, &a);
    p448_mul(&a, &b, &c);
  }
  when = now() - when;
  printf("mul dep:     %5.1fns\n", when * 1e9 / i / 2);

  when = now();
  for (i = 0; i < nbase * 1000; i++) {
    p448_mulw(&c, &b, 1234562);
  }
  when = now() - when;
  printf("mulw:        %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 10; i++) {
    p448_randomize(&crand, &a);
  }
  when = now() - when;
  printf("rand448:     %5.1fns\n", when * 1e9 / i);

  struct sha512_ctx_t sha;
  uint8_t hashout[128];
  when = now();
  for (i = 0; i < nbase; i++) {
    sha512_init(&sha);
    sha512_final(&sha, hashout);
  }
  when = now() - when;
  printf("sha512 1blk: %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    sha512_update(&sha, hashout, 128);
  }
  when = now() - when;
  printf("sha512 blk:  %5.1fns (%0.2f MB/s)\n", when * 1e9 / i, 128 * i / when / 1e6);

  when = now();
  for (i = 0; i < nbase; i++) {
    p448_isr(&c, &a);
  }
  when = now() - when;
  printf("isr auto:    %5.1fµs\n", when * 1e6 / i);

  for (i = 0; i < 100; i++) {
    p448_randomize(&crand, &a);
    p448_isr(&d, &a);
    p448_sqr(&b, &d);
    p448_mul(&c, &b, &a);
    p448_sqr(&b, &c);
    p448_subw(&b, 1);
    p448_bias(&b, 1);
    if (!p448_is_zero(&b)) {
      printf("ISR validation failure!\n");
      p448_print("a", &a);
      p448_print("s", &d);
    }
  }

  when = now();
  for (i = 0; i < nbase; i++) {
    elligator_2s_inject(&affine, &a);
  }
  when = now() - when;
  printf("elligator:   %5.1fµs\n", when * 1e6 / i);

  for (i = 0; i < 100; i++) {
    p448_randomize(&crand, &a);
    elligator_2s_inject(&affine, &a);
    if (!validate_affine(&affine)) {
      printf("Elligator validation failure!\n");
      p448_print("a", &a);
      p448_print("x", &affine.x);
      p448_print("y", &affine.y);
    }
  }

  when = now();
  for (i = 0; i < nbase; i++) {
    deserialize_affine(&affine, &a);
  }
  when = now() - when;
  printf("decompress:  %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    serialize_extensible(&a, &exta);
  }
  when = now() - when;
  printf("compress:    %5.1fµs\n", when * 1e6 / i);

  int goods = 0;
  for (i = 0; i < 100; i++) {
    p448_randomize(&crand, &a);
    mask_t good = deserialize_affine(&affine, &a);
    if (good & !validate_affine(&affine)) {
      printf("Deserialize validation failure!\n");
      p448_print("a", &a);
      p448_print("x", &affine.x);
      p448_print("y", &affine.y);
    } else if (good) {
      goods++;
      convert_affine_to_extensible(&exta, &affine);
      serialize_extensible(&b, &exta);
      p448_sub(&c, &b, &a);
      p448_bias(&c, 2);
      if (!p448_is_zero(&c)) {
        printf("Reserialize validation failure!\n");
        p448_print("a", &a);
        p448_print("x", &affine.x);
        p448_print("y", &affine.y);
        deserialize_affine(&affine, &b);
        p448_print("b", &b);
        p448_print("x", &affine.x);
        p448_print("y", &affine.y);
        printf("\n");
      }
    }
  }
  if (goods < i / 3) {
    printf("Deserialization validation failure! Deserialized %d/%d points\n", goods, i);
  }

  word_t lsk[768 / WORD_BITS];
  crandom_generate(&crand, (unsigned char*)lsk, sizeof(lsk));

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    barrett_reduce(lsk, sizeof(lsk) / sizeof(word_t), 0, &curve_prime_order);
  }
  when = now() - when;
  printf("barrett red: %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 10; i++) {
    barrett_mac(lsk,
                448 / WORD_BITS,
                lsk,
                448 / WORD_BITS,
                lsk,
                448 / WORD_BITS,
                &curve_prime_order);
  }
  when = now() - when;
  printf("barrett mac: %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    add_tw_niels_to_tw_extensible(&ext, &niels);
  }
  when = now() - when;
  printf("exti+niels:  %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    add_tw_pniels_to_tw_extensible(&ext, &pniels);
  }
  when = now() - when;
  printf("exti+pniels: %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    double_tw_extensible(&ext);
  }
  when = now() - when;
  printf("exti dbl:    %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    untwist_and_double(&exta, &ext);
  }
  when = now() - when;
  printf("i->a isog:   %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    twist_and_double(&ext, &exta);
  }
  when = now() - when;
  printf("a->i isog:   %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase * 100; i++) {
    montgomery_step(&mb);
  }
  when = now() - when;
  printf("monty step:  %5.1fns\n", when * 1e9 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    ignore_result(montgomery_ladder(&a, &b, sk, 448, 0));
  }
  when = now() - when;
  printf("full ladder: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    scalarmul(&ext, sk);
  }
  when = now() - when;
  printf("edwards smz: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    scalarmul_vlook(&ext, sk);
  }
  when = now() - when;
  printf("edwards svl: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    scalarmul(&ext, sk);
    untwist_and_double_and_serialize(&a, &ext);
  }
  when = now() - when;
  printf("edwards smc: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    q448_randomize(&crand, sk);
    scalarmul_vt(&ext, sk, 446);
  }
  when = now() - when;
  printf("edwards vtm: %5.1fµs\n", when * 1e6 / i);

  struct tw_niels_t wnaft[1 << 6];
  when = now();
  for (i = 0; i < nbase / 10; i++) {
    ignore_result(precompute_fixed_base_wnaf(wnaft, &ext, 6));
  }
  when = now() - when;
  printf("wnaf6 pre:   %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    q448_randomize(&crand, sk);
    scalarmul_fixed_base_wnaf_vt(&ext, sk, 446, wnaft, 6);
  }
  when = now() - when;
  printf("edwards vt6: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    ignore_result(precompute_fixed_base_wnaf(wnaft, &ext, 4));
  }
  when = now() - when;
  printf("wnaf4 pre:   %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    q448_randomize(&crand, sk);
    scalarmul_fixed_base_wnaf_vt(&ext, sk, 446, wnaft, 4);
  }
  when = now() - when;
  printf("edwards vt4: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    ignore_result(precompute_fixed_base_wnaf(wnaft, &ext, 5));
  }
  when = now() - when;
  printf("wnaf5 pre:   %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    q448_randomize(&crand, sk);
    scalarmul_fixed_base_wnaf_vt(&ext, sk, 446, wnaft, 5);
  }
  when = now() - when;
  printf("edwards vt5: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    q448_randomize(&crand, sk);
    q448_randomize(&crand, tk);
    linear_combo_var_fixed_vt(&ext, sk, 448, tk, 448, wnaft, 5);
  }
  when = now() - when;
  printf("vt vf combo: %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    deserialize_affine(&affine, &a);
    convert_affine_to_extensible(&exta, &affine);
    twist_and_double(&ext, &exta);
    scalarmul(&ext, sk);
    untwist_and_double(&exta, &ext);
    serialize_extensible(&b, &exta);
  }
  when = now() - when;
  printf("edwards sm:  %5.1fµs\n", when * 1e6 / i);

  struct fixed_base_table_t t_5_5_18, t_3_5_30, t_8_4_14, t_5_3_30, t_15_3_10;

  while (1) {
    p448_randomize(&crand, &a);
    if (deserialize_affine(&affine, &a))
      break;
  }
  convert_affine_to_extensible(&exta, &affine);
  twist_and_double(&ext, &exta);
  when = now();
  for (i = 0; i < nbase / 10; i++) {
    if (i)
      destroy_fixed_base(&t_5_5_18);
    ignore_result(precompute_fixed_base(&t_5_5_18, &ext, 5, 5, 18, NULL));
  }
  when = now() - when;
  printf("pre(5,5,18): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    if (i)
      destroy_fixed_base(&t_3_5_30);
    ignore_result(precompute_fixed_base(&t_3_5_30, &ext, 3, 5, 30, NULL));
  }
  when = now() - when;
  printf("pre(3,5,30): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    if (i)
      destroy_fixed_base(&t_5_3_30);
    ignore_result(precompute_fixed_base(&t_5_3_30, &ext, 5, 3, 30, NULL));
  }
  when = now() - when;
  printf("pre(5,3,30): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    if (i)
      destroy_fixed_base(&t_15_3_10);
    ignore_result(precompute_fixed_base(&t_15_3_10, &ext, 15, 3, 10, NULL));
  }
  when = now() - when;
  printf("pre(15,3,10):%5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase / 10; i++) {
    if (i)
      destroy_fixed_base(&t_8_4_14);
    ignore_result(precompute_fixed_base(&t_8_4_14, &ext, 8, 4, 14, NULL));
  }
  when = now() - when;
  printf("pre(8,4,14): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    scalarmul_fixed_base(&ext, sk, 448, &t_5_5_18);
  }
  when = now() - when;
  printf("com(5,5,18): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    scalarmul_fixed_base(&ext, sk, 448, &t_3_5_30);
  }
  when = now() - when;
  printf("com(3,5,30): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    scalarmul_fixed_base(&ext, sk, 448, &t_8_4_14);
  }
  when = now() - when;
  printf("com(8,4,14): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    scalarmul_fixed_base(&ext, sk, 448, &t_5_3_30);
  }
  when = now() - when;
  printf("com(5,3,30): %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    scalarmul_fixed_base(&ext, sk, 448, &t_15_3_10);
  }
  when = now() - when;
  printf("com(15,3,10):%5.1fµs\n", when * 1e6 / i);

  printf("\nGoldilocks:\n");

  int res = goldilocks_init();
  assert(!res);

  struct goldilocks_public_key_t gpk, hpk;
  struct goldilocks_private_key_t gsk, hsk;

  when = now();
  for (i = 0; i < nbase; i++) {
    if (i & 1) {
      res = goldilocks_keygen(&gsk, &gpk);
    } else {
      res = goldilocks_keygen(&hsk, &hpk);
    }
    assert(!res);
  }
  when = now() - when;
  printf("keygen:      %5.1fµs\n", when * 1e6 / i);

  uint8_t ss1[64], ss2[64];
  int gres1 = 0, gres2 = 0;
  when = now();
  for (i = 0; i < nbase; i++) {
    if (i & 1) {
      gres1 = goldilocks_shared_secret(ss1, &gsk, &hpk);
    } else {
      gres2 = goldilocks_shared_secret(ss2, &hsk, &gpk);
    }
  }
  when = now() - when;
  printf("ecdh:        %5.1fµs\n", when * 1e6 / i);
  if (gres1 || gres2 || memcmp(ss1, ss2, 64)) {
    printf("[FAIL] %d %d\n", gres1, gres2);

    printf("sk1 = ");
    for (i = 0; i < 56; i++) {
      printf("%02x", gsk.opaque[i]);
    }
    printf("\nsk2 = ");
    for (i = 0; i < 56; i++) {
      printf("%02x", hsk.opaque[i]);
    }
    printf("\nss1 = ");
    for (i = 0; i < 56; i++) {
      printf("%02x", ss1[i]);
    }
    printf("\nss2 = ");
    for (i = 0; i < 56; i++) {
      printf("%02x", ss2[i]);
    }
    printf("\n");
  }

  uint8_t sout[56 * 2];
  const char* message = "hello world";
  size_t message_len = strlen(message);
  when = now();
  for (i = 0; i < nbase; i++) {
    res = goldilocks_sign(sout, (const unsigned char*)message, message_len, &gsk);
    assert(!res);
  }
  when = now() - when;
  printf("sign:        %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    int ver = goldilocks_verify(sout, (const unsigned char*)message, message_len, &gpk);
    assert(!ver);
  }
  when = now() - when;
  printf("verify:      %5.1fµs\n", when * 1e6 / i);

  struct goldilocks_precomputed_public_key_t* pre = NULL;
  when = now();
  for (i = 0; i < nbase; i++) {
    goldilocks_destroy_precomputed_public_key(pre);
    pre = goldilocks_precompute_public_key(&gpk);
  }
  when = now() - when;
  printf("precompute:  %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    int ver = goldilocks_verify_precomputed(
        sout, (const unsigned char*)message, message_len, pre);
    assert(!ver);
  }
  when = now() - when;
  printf("verify pre:  %5.1fµs\n", when * 1e6 / i);

  when = now();
  for (i = 0; i < nbase; i++) {
    int ret = goldilocks_shared_secret_precomputed(ss1, &gsk, pre);
    assert(!ret);
  }
  when = now() - when;
  printf("ecdh pre:    %5.1fµs\n", when * 1e6 / i);

  printf("\nTesting...\n");

  int failures = 0, successes = 0;
  for (i = 0; i < nbase / 10; i++) {
    ignore_result(goldilocks_keygen(&gsk, &gpk));
    goldilocks_sign(sout, (const unsigned char*)message, message_len, &gsk);
    res = goldilocks_verify(sout, (const unsigned char*)message, message_len, &gpk);
    if (res)
      failures++;
  }
  if (failures) {
    printf("FAIL %d/%d signature checks!\n", failures, i);
  }

  failures = 0;
  successes = 0;
  for (i = 0; i < nbase / 10; i++) {
    p448_randomize(&crand, &a);
    word_t two = 2;
    mask_t good = montgomery_ladder(&b, &a, &two, 2, 0);
    if (!good)
      continue;

    word_t x, y;
    crandom_generate(&crand, (unsigned char*)&x, sizeof(x));
    crandom_generate(&crand, (unsigned char*)&y, sizeof(y));
    x = (hword_t)x;
    y = (hword_t)y;
    word_t z = x * y;

    ignore_result(montgomery_ladder(&b, &a, &x, WORD_BITS, 0));
    ignore_result(montgomery_ladder(&c, &b, &y, WORD_BITS, 0));
    ignore_result(montgomery_ladder(&b, &a, &z, WORD_BITS, 0));

    p448_sub(&d, &b, &c);
    p448_bias(&d, 2);
    if (!p448_is_zero(&d)) {
      printf("Odd ladder validation failure %d!\n", ++failures);
      p448_print("a", &a);
      printf("x=%" PRIxWORD ", y=%" PRIxWORD ", z=%" PRIxWORD "\n", x, y, z);
      p448_print("c", &c);
      p448_print("b", &b);
      printf("\n");
    }
  }

  failures = 0;
  for (i = 0; i < nbase / 10; i++) {
    mask_t good;
    do {
      p448_randomize(&crand, &a);
      good = deserialize_affine(&affine, &a);
    } while (!good);

    convert_affine_to_extensible(&exta, &affine);
    twist_and_double(&ext, &exta);
    untwist_and_double(&exta, &ext);
    serialize_extensible(&b, &exta);
    untwist_and_double_and_serialize(&c, &ext);

    p448_sub(&d, &b, &c);
    p448_bias(&d, 2);

    if (good && !p448_is_zero(&d)) {
      printf("Iso+serial validation failure %d!\n", ++failures);
      p448_print("a", &a);
      p448_print("b", &b);
      p448_print("c", &c);
      printf("\n");
    } else if (good) {
      successes++;
    }
  }
  if (successes < i / 3) {
    printf("Iso+serial variation: only %d/%d successful.\n", successes, i);
  }

  successes = failures = 0;
  for (i = 0; i < nbase / 10; i++) {
    struct p448_t aa;
    struct tw_extensible_t exu, exv, exw;

    mask_t good;
    do {
      p448_randomize(&crand, &a);
      good = deserialize_affine(&affine, &a);
      convert_affine_to_extensible(&exta, &affine);
      twist_and_double(&ext, &exta);
    } while (!good);
    do {
      p448_randomize(&crand, &aa);
      good = deserialize_affine(&affine, &aa);
      convert_affine_to_extensible(&exta, &affine);
      twist_and_double(&exu, &exta);
    } while (!good);
    p448_randomize(&crand, &aa);

    q448_randomize(&crand, sk);
    if (i == 0 || i == 2)
      memset(&sk, 0, sizeof(sk));
    q448_randomize(&crand, tk);
    if (i == 0 || i == 1)
      memset(&tk, 0, sizeof(tk));

    copy_tw_extensible(&exv, &ext);
    copy_tw_extensible(&exw, &exu);
    scalarmul(&exv, sk);
    scalarmul(&exw, tk);
    convert_tw_extensible_to_tw_pniels(&pniels, &exw);
    add_tw_pniels_to_tw_extensible(&exv, &pniels);
    untwist_and_double(&exta, &exv);
    serialize_extensible(&b, &exta);

    ignore_result(precompute_fixed_base_wnaf(wnaft, &exu, 5));
    linear_combo_var_fixed_vt(&ext, sk, 448, tk, 448, wnaft, 5);
    untwist_and_double(&exta, &exv);
    serialize_extensible(&c, &exta);

    p448_sub(&d, &b, &c);
    p448_bias(&d, 2);

    if (!p448_is_zero(&d)) {
      printf("PreWNAF combo validation failure %d!\n", ++failures);
      p448_print("a", &a);
      p448_print("A", &aa);
      q448_print("s", sk);
      q448_print("t", tk);
      p448_print("c", &c);
      p448_print("b", &b);
      printf("\n\n");
    } else if (good) {
      successes++;
    }
  }
  if (successes < i) {
    printf("PreWNAF combo variation: only %d/%d successful.\n", successes, i);
  }

  return 0;
}
