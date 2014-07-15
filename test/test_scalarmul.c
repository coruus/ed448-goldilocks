#include "test.h"

#include <stdio.h>

#include "scalarmul.h"
#include "ec_point.h"
#include "p448.h"
#include "crandom.h"

/* 0 = succeed, 1 = inval, -1 = fail */
static int single_scalarmul_compatibility_test(const struct p448_t* base,
                                               const word_t* scalar,
                                               int nbits) {
  struct tw_extensible_t text, work;
  struct p448_t mont, ct, vl, vt;

  int ret = 0, i;
  mask_t succ, succm;

  succ = deserialize_and_twist_approx(&text, &sqrt_d_minus_1, base);

  succm = montgomery_ladder(&mont, base, scalar, nbits, 1);

  if (succ != succm) {
    youfail();
    printf("    Deserialize_and_twist_approx succ=%d, montgomery_ladder succ=%d\n",
           (int)-succ,
           (int)-succm);
    printf("    nbits = %d\n", nbits);
    p448_print("    base", base);
    scalar_print("    scal", scalar, (nbits + WORD_BITS - 1) / WORD_BITS);
    return -1;
  }

  if (!succ) {
    return 1;
  }

  struct {
    int n, t, s;
  } params[] = {{5, 5, 18}, {3, 5, 30}, {4, 4, 28}, {1, 2, 224}};
  const int nparams = sizeof(params) / sizeof(params[0]);
  struct fixed_base_table_t fbt;
  struct p448_t fbout[nparams], wout[6];
  memset_s(&fbt, sizeof(fbt), 0, sizeof(fbt));
  memset_s(&fbout, sizeof(fbout), 0, sizeof(fbout));
  memset_s(&wout, sizeof(wout), 0, sizeof(wout));

  /* compute using combs */
  for (i = 0; i < nparams; i++) {
    int n = params[i].n, t = params[i].t, s = params[i].s;
    succ = precompute_fixed_base(&fbt, &text, n, t, s, NULL);
    if (!succ) {
      youfail();
      printf("    Failed to precompute_fixed_base(%d,%d,%d)\n", n, t, s);
      continue;
    }

    succ = scalarmul_fixed_base(&work, scalar, nbits, &fbt);
    destroy_fixed_base(&fbt);
    if (!succ) {
      youfail();
      printf("    Failed to scalarmul_fixed_base(%d,%d,%d)\n", n, t, s);
      continue;
    }

    untwist_and_double_and_serialize(&fbout[i], &work);
  }

  /* compute using precomp wNAF */
  for (i = 0; i <= 5; i++) {
    struct tw_niels_t pre[1 << i];

    succ = precompute_fixed_base_wnaf(pre, &text, i);
    if (!succ) {
      youfail();
      printf("    Failed to precompute_fixed_base_wnaf(%d)\n", i);
      continue;
    }

    scalarmul_fixed_base_wnaf_vt(&work, scalar, nbits, pre, i);

    untwist_and_double_and_serialize(&wout[i], &work);
  }

  mask_t consistent = MASK_SUCCESS;

  if (nbits == 448) {
    /* window methods currently only work on 448 bits. */
    copy_tw_extensible(&work, &text);
    scalarmul(&work, scalar);
    untwist_and_double_and_serialize(&ct, &work);

    copy_tw_extensible(&work, &text);
    scalarmul_vlook(&work, scalar);
    untwist_and_double_and_serialize(&vl, &work);

    copy_tw_extensible(&work, &text);
    scalarmul_vt(&work, scalar, nbits);
    untwist_and_double_and_serialize(&vt, &work);

    /* check consistency mont vs window */
    consistent &= p448_eq(&mont, &ct);
    consistent &= p448_eq(&mont, &vl);
    consistent &= p448_eq(&mont, &vt);
  }

  /* check consistency mont vs combs */
  for (i = 0; i < nparams; i++) {
    consistent &= p448_eq(&mont, &fbout[i]);
  }

  /* check consistency mont vs wNAF */
  for (i = 0; i < 6; i++) {
    consistent &= p448_eq(&mont, &wout[i]);
  }

  /* If inconsistent, complain. */
  if (!consistent) {
    youfail();
    printf("    Failed scalarmul consistency test with nbits=%d.\n", nbits);
    p448_print("    base", base);
    scalar_print("    scal", scalar, (nbits + WORD_BITS - 1) / WORD_BITS);
    p448_print("    mont", &mont);

    for (i = 0; i < nparams; i++) {
      printf("    With n=%d, t=%d, s=%d:\n", params[i].n, params[i].t, params[i].s);
      p448_print("    out ", &fbout[i]);
    }

    for (i = 0; i < 6; i++) {
      printf("    With w=%d:\n", i);
      p448_print("    wNAF", &wout[i]);
    }

    if (nbits == 448) {
      p448_print("    ct ", &ct);
      p448_print("    vl ", &vl);
      p448_print("    vt ", &vt);
    }

    ret = -1;
  }

  return ret;
}

static int single_linear_combo_test(const struct p448_t* base1,
                                    const word_t* scalar1,
                                    int nbits1,
                                    const struct p448_t* base2,
                                    const word_t* scalar2,
                                    int nbits2) {
  struct tw_extensible_t text1, text2, working;
  struct tw_pniels_t pn;
  struct p448_t result_comb, result_combo, result_wnaf;

  mask_t succ = deserialize_and_twist_approx(&text1, &sqrt_d_minus_1, base1) &
                deserialize_and_twist_approx(&text2, &sqrt_d_minus_1, base2);
  if (!succ)
    return 1;

  struct fixed_base_table_t t1, t2;
  struct tw_niels_t wnaf[32];
  memset_s(&t1, sizeof(t1), 0, sizeof(t1));
  memset_s(&t2, sizeof(t2), 0, sizeof(t2));

  succ = precompute_fixed_base(&t1, &text1, 5, 5, 18, NULL);
  succ &= precompute_fixed_base(&t2, &text2, 6, 3, 25, NULL);
  succ &= precompute_fixed_base_wnaf(wnaf, &text2, 5);

  if (!succ) {
    destroy_fixed_base(&t1);
    destroy_fixed_base(&t2);
    return -1;
  }

  /* use the dedicated wNAF linear combo algorithm */
  copy_tw_extensible(&working, &text1);
  linear_combo_var_fixed_vt(&working, scalar1, nbits1, scalar2, nbits2, wnaf, 5);
  untwist_and_double_and_serialize(&result_wnaf, &working);

  /* use the dedicated combs algorithm */
  succ &= linear_combo_combs_vt(&working, scalar1, nbits1, &t1, scalar2, nbits2, &t2);
  untwist_and_double_and_serialize(&result_combo, &working);

  /* use two combs */
  succ &= scalarmul_fixed_base(&working, scalar1, nbits1, &t1);
  convert_tw_extensible_to_tw_pniels(&pn, &working);
  succ &= scalarmul_fixed_base(&working, scalar2, nbits2, &t2);
  add_tw_pniels_to_tw_extensible(&working, &pn);
  untwist_and_double_and_serialize(&result_comb, &working);

  mask_t consistent = MASK_SUCCESS;
  consistent &= p448_eq(&result_combo, &result_wnaf);
  consistent &= p448_eq(&result_comb, &result_wnaf);

  if (!succ || !consistent) {
    youfail();
    printf(
        "    Failed linear combo consistency test with nbits=%d,%d.\n", nbits1, nbits2);

    p448_print("    base1", base1);
    scalar_print("    scal1", scalar1, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    p448_print("    base2", base2);
    scalar_print("    scal2", scalar2, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    p448_print("    combs", &result_comb);
    p448_print("    combo", &result_combo);
    p448_print("    wNAFs", &result_wnaf);
    return -1;
  }

  destroy_fixed_base(&t1);
  destroy_fixed_base(&t2);

  return 0;
}

/* 0 = succeed, 1 = inval, -1 = fail */
static int single_scalarmul_commutativity_test(const struct p448_t* base,
                                               const word_t* scalar1,
                                               int nbits1,
                                               int ned1,
                                               const word_t* scalar2,
                                               int nbits2,
                                               int ned2) {
  struct p448_t m12, m21, tmp1, tmp2;
  mask_t succ12a = montgomery_ladder(&tmp1, base, scalar1, nbits1, ned1);
  mask_t succ12b = montgomery_ladder(&m12, &tmp1, scalar2, nbits2, ned2);

  mask_t succ21a = montgomery_ladder(&tmp2, base, scalar2, nbits2, ned2);
  mask_t succ21b = montgomery_ladder(&m21, &tmp2, scalar1, nbits1, ned1);

  mask_t succ12 = succ12a & succ12b, succ21 = succ21a & succ21b;

  if (succ12 != succ21) {
    youfail();
    printf(
        "    Failed scalarmul commutativity test with (nbits,ned) = (%d,%d), (%d,%d).\n",
        nbits1,
        ned1,
        nbits2,
        ned2);
    p448_print("    base", base);
    p448_print("    tmp1", &tmp1);
    p448_print("    tmp2", &tmp2);
    scalar_print("    sca1", scalar1, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    scalar_print("    sca2", scalar2, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    printf("    good = ((%d,%d),(%d,%d))\n",
           (int)-succ12a,
           (int)-succ12b,
           (int)-succ21a,
           (int)-succ21b);
    return -1;
  } else if (!succ12) {
    // printf("    (nbits,ned) = (%d,%d), (%d,%d).\n", nbits1,ned1,nbits2,ned2);
    // printf("    succ = (%d,%d), (%d,%d).\n", (int)-succ12a, (int)-succ12b,
    // (int)-succ21a, (int)-succ21b);
    return 1;
  }

  mask_t consistent = p448_eq(&m12, &m21);
  if (consistent) {
    return 0;
  } else {
    youfail();
    printf(
        "    Failed scalarmul commutativity test with (nbits,ned) = (%d,%d), (%d,%d).\n",
        nbits1,
        ned1,
        nbits2,
        ned2);
    p448_print("    base", base);
    scalar_print("    sca1", scalar1, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    scalar_print("    sca2", scalar2, (nbits1 + WORD_BITS - 1) / WORD_BITS);
    p448_print("    m12 ", &m12);
    p448_print("    m21 ", &m21);
    return -1;
  }
}

int test_scalarmul_commutativity() {
  int i, j, k, got;

  struct crandom_state_t crand;
  crandom_init_from_buffer(&crand, "scalarmul_commutativity_test RNG");

  for (i = 0; i <= 448; i += 7) {
    for (j = 0; j <= 448; j += 7) {
      got = 0;

      for (k = 0; k < 128 && !got; k++) {
        uint8_t ser[56];
        word_t scalar1[7], scalar2[7];
        crandom_generate(&crand, ser, sizeof(ser));
        crandom_generate(&crand, (uint8_t*)scalar1, sizeof(scalar1));
        crandom_generate(&crand, (uint8_t*)scalar2, sizeof(scalar2));

        p448_t base;
        mask_t succ = p448_deserialize(&base, ser);
        if (!succ)
          continue;

        int ret = single_scalarmul_commutativity_test(
            &base, scalar1, i, i % 3, scalar2, j, j % 3);
        got = !ret;
        if (ret == -1)
          return -1;
      }

      if (!got) {
        youfail();
        printf("    Unlikely: rejected 128 scalars in a row.\n");
        return -1;
      }
    }
  }

  return 0;
}

int test_linear_combo() {
  int i, j, k, got;

  struct crandom_state_t crand;
  crandom_init_from_buffer(&crand, "scalarmul_linear_combos_test RNG");

  for (i = 0; i <= 448; i += 7) {
    for (j = 0; j <= 448; j += 7) {
      got = 0;

      for (k = 0; k < 128 && !got; k++) {
        uint8_t ser[56];
        word_t scalar1[7], scalar2[7];
        crandom_generate(&crand, (uint8_t*)scalar1, sizeof(scalar1));
        crandom_generate(&crand, (uint8_t*)scalar2, sizeof(scalar2));

        p448_t base1;
        crandom_generate(&crand, ser, sizeof(ser));
        mask_t succ = p448_deserialize(&base1, ser);
        if (!succ)
          continue;

        p448_t base2;
        crandom_generate(&crand, ser, sizeof(ser));
        succ = p448_deserialize(&base2, ser);
        if (!succ)
          continue;

        int ret = single_linear_combo_test(&base1, scalar1, i, &base2, scalar2, j);
        got = !ret;
        if (ret == -1)
          return -1;
      }

      if (!got) {
        youfail();
        printf("    Unlikely: rejected 128 scalars in a row.\n");
        return -1;
      }
    }
  }

  return 0;
}

int test_scalarmul_compatibility() {
  int i, j, k, got;

  struct crandom_state_t crand;
  crandom_init_from_buffer(&crand, "scalarmul_compatibility_test RNG");

  for (i = 0; i <= 448; i += 7) {
    for (j = 0; j <= 20; j++) {
      got = 0;

      for (k = 0; k < 128 && !got; k++) {
        uint8_t ser[56];
        word_t scalar[7];
        crandom_generate(&crand, ser, sizeof(ser));
        crandom_generate(&crand, (uint8_t*)scalar, sizeof(scalar));

        p448_t base;
        mask_t succ = p448_deserialize(&base, ser);
        if (!succ)
          continue;

        int ret = single_scalarmul_compatibility_test(&base, scalar, i);
        got = !ret;
        if (ret == -1)
          return -1;
      }

      if (!got) {
        youfail();
        printf("    Unlikely: rejected 128 scalars in a row.\n");
        return -1;
      }
    }
  }

  return 0;
}
