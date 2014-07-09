#include "test.h"

#include <stdio.h>

#include "ec_point.h"
#include "p448.h"
#include "crandom.h"

static void failprint_ext(const struct extensible_t* a) {
  struct p448_t zi, scaled;
  p448_print("    x", &a->x);
  p448_print("    y", &a->y);
  p448_print("    z", &a->z);
  p448_inverse(&zi, &a->z);
  p448_mul(&scaled, &zi, &a->x);
  p448_print("    X", &scaled);
  p448_mul(&scaled, &zi, &a->y);
  p448_print("    Y", &scaled);
  printf("\n");
}

static void failprint_tw_ext(const struct tw_extensible_t* a) {
  failprint_ext((const struct extensible_t*)a);
}

static mask_t fail_if_different(const struct extensible_t* a,
                                const struct extensible_t* b,
                                const char* faildescr,
                                const char* adescr,
                                const char* bdescr) {
  mask_t succ = eq_extensible(a, b);

  if (!succ) {
    youfail();
    printf("    %s\n", faildescr);

    printf("\n    %s:\n", adescr);
    failprint_ext(a);

    printf("\n    %s:\n", bdescr);
    failprint_ext(b);
  }

  return succ;
}

static mask_t validate_ext(const struct extensible_t* ext,
                           int evenness,
                           const char* description) {
  mask_t succ = validate_extensible(ext), succ2;
  const char* error = "Point isn't on the curve.";
  if (evenness > 0) {
    succ2 = is_even_pt(ext);
    if (succ & ~succ2)
      error = "Point isn't even.";
    succ &= succ2;
  } else if (evenness < 0) {
    succ2 = is_even_pt(ext);
    if (succ & ~succ2)
      error = "Point is even but shouldn't be.";
    succ &= succ2;
  } /* FUTURE: quadness */

  if (~succ) {
    youfail();
    printf("    %s\n", error);
    printf("    %s\n", description);
    failprint_ext(ext);
  }

  return succ;
}

static mask_t validate_tw_ext(const struct tw_extensible_t* ext,
                              int evenness,
                              const char* description) {
  mask_t succ = validate_tw_extensible(ext), succ2;
  const char* error = "Point isn't on the twisted curve.";
  if (evenness > 0) {
    succ2 = is_even_tw(ext);
    if (succ & ~succ2)
      error = "Point isn't even.";
    succ &= succ2;
  } else if (evenness < 0) {
    succ2 = is_even_tw(ext);
    if (succ & ~succ2)
      error = "Point is even but shouldn't be.";
    succ &= succ2;
  } /* FUTURE: quadness */

  if (~succ) {
    youfail();
    printf("    %s\n", error);
    printf("    %s\n", description);
    failprint_tw_ext(ext);
  }

  return succ;
}

static mask_t fail_if_different_tw(const struct tw_extensible_t* a,
                                   const struct tw_extensible_t* b,
                                   const char* faildescr,
                                   const char* adescr,
                                   const char* bdescr) {
  return fail_if_different((const struct extensible_t*)a,
                           (const struct extensible_t*)b,
                           faildescr,
                           adescr,
                           bdescr);
}

static int add_double_test(const struct affine_t* base1, const struct affine_t* base2) {
  mask_t succ = MASK_SUCCESS;
  struct extensible_t exb;
  struct tw_extensible_t text1, text2, texta, textb;
  struct tw_pniels_t pn;

  /* Convert to ext */
  convert_affine_to_extensible(&exb, base1);
  succ &= validate_ext(&exb, 0, "base1");
  twist_and_double(&text1, &exb);
  succ &= validate_tw_ext(&text1, 2, "iso1");
  convert_affine_to_extensible(&exb, base2);
  succ &= validate_ext(&exb, 0, "base2");
  twist_and_double(&text2, &exb);
  succ &= validate_tw_ext(&text2, 2, "iso2");

  /* a + b == b + a? */
  convert_tw_extensible_to_tw_pniels(&pn, &text1);
  copy_tw_extensible(&texta, &text2);
  add_tw_pniels_to_tw_extensible(&texta, &pn);

  convert_tw_extensible_to_tw_pniels(&pn, &text2);
  copy_tw_extensible(&textb, &text1);
  add_tw_pniels_to_tw_extensible(&textb, &pn);

  succ &= fail_if_different_tw(&texta, &textb, "Addition commutativity", "a+b", "b+a");

  copy_tw_extensible(&textb, &text2);
  add_tw_pniels_to_tw_extensible(&textb, &pn);
  copy_tw_extensible(&texta, &text2);
  double_tw_extensible(&texta);

  succ &= fail_if_different_tw(&texta, &textb, "Doubling test", "2b", "b+b");

  if (~succ) {
    printf("    Bases were:\n");
    p448_print("    x1", &base1->x);
    p448_print("    y1", &base1->y);
    p448_print("    x2", &base2->x);
    p448_print("    y2", &base2->y);
  }

  return succ ? 0 : -1;
}

static int single_twisting_test(const struct affine_t* base) {
  struct extensible_t exb, ext, tmpext;
  struct tw_extensible_t text, text2;
  mask_t succ = MASK_SUCCESS;

  convert_affine_to_extensible(&exb, base);
  succ &= validate_ext(&exb, 0, "base");

  /* check: dual . iso = 4 */
  twist_and_double(&text, &exb);
  succ &= validate_tw_ext(&text, 2, "iso");
  untwist_and_double(&ext, &text);
  succ &= validate_ext(&ext, 2, "dual.iso");

  copy_extensible(&tmpext, &exb);
  double_extensible(&tmpext);
  succ &= validate_ext(&tmpext, 1, "2*base");

  double_extensible(&tmpext);
  succ &= validate_ext(&tmpext, 2, "4*base");

  succ &= fail_if_different(&ext, &tmpext, "Isogeny and dual", "Dual . iso", "4*base");

  /* check: twist and serialize */
  test_only_twist(&text, &exb);
  succ &= validate_tw_ext(&text, 0, "tot");
  mask_t evt = is_even_tw(&text), evb = is_even_pt(&exb);
  if (evt != evb) {
    youfail();
    printf(
        "    Different evenness from twist base: %d, twist: %d\n", (int)-evt, (int)-evb);

    succ = 0;
  } /* FUTURE: quadness */

  p448_t sera, serb;
  untwist_and_double_and_serialize(&sera, &text);
  copy_extensible(&tmpext, &exb);
  double_extensible(&tmpext);
  serialize_extensible(&serb, &tmpext);

  /* check that their (doubled; FUTURE?) serializations are equal */
  if (~p448_eq(&sera, &serb)) {
    youfail();
    printf("    Different serialization from twist + double ()\n");
    p448_print("    t", &sera);
    p448_print("    b", &serb);
    succ = 0;
  }

  untwist_and_double(&ext, &text);
  succ &= validate_ext(&tmpext, 1, "dual.tot");

  twist_and_double(&text2, &ext);
  succ &= validate_tw_ext(&text2, 2, "iso.dual.tot");

  double_tw_extensible(&text);
  succ &= validate_tw_ext(&text, 1, "2*tot");

  double_tw_extensible(&text);
  succ &= validate_tw_ext(&text, 2, "4*tot");

  succ &=
      fail_if_different_tw(&text, &text2, "Dual and isogeny", "4*tot", "iso.dual.tot");

  if (~succ) {
    printf("    Base was:\n");
    p448_print("    x", &base->x);
    p448_print("    y", &base->y);
  }

  return succ ? 0 : -1;
}

int test_pointops() {
  struct affine_t base, pbase;
  struct p448_t ser448;

  struct crandom_state_t crand;
  crandom_init_from_buffer(&crand, "test_pointops random initializer");

  int i, ret;
  for (i = 0; i < 1000; i++) {
    uint8_t ser[56];
    crandom_generate(&crand, ser, sizeof(ser));

    /* TODO: we need a p448 generate, which can return random or pathological. */
    mask_t succ = p448_deserialize(&ser448, ser);
    if (!succ) {
      youfail();
      printf("   Unlikely: fail at p448_deserialize\n");
      return -1;
    }

    if (i) {
      copy_affine(&pbase, &base);
    }
    elligator_2s_inject(&base, &ser448);

    if (i) {
      ret = add_double_test(&base, &pbase);
      if (ret)
        return ret;
    }

    ret = single_twisting_test(&base);
    if (ret)
      return ret;
  }

  return 0;
}
