/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_ALGO_H__
#define __P448_ALGO_H__ 1

#include "ec_point.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Out = scalar * in, encoded in inverse square root
 * format.
 *
 * nbits is the number of bits in scalar.
 *
 * The scalar is to be presented in little-endian form,
 * meaning that scalar[0] contains the least significant
 * word of the scalar.
 * 
 * If the point "in" is on the curve, the return
 * value will be set (to -1).
 *
 * If the point "in" is not on the curve, then the
 * output will be incorrect.  If the scalar is even,
 * this condition will be detected by returning 0,
 * unless the output is the identity point (0; TODO).
 * If the scalar is odd, the value returned will be
 * set (to -1; TODO).
 *
 * The input and output points are always even.
 * Therefore on a cofactor-4 curve like Goldilocks,
 * it is sufficient for security to make the scalar
 * even.  (TODO: detect when i/o has cofactor?)
 *
 * This function takes constant time, depending on
 * nbits but not on in or scalar.
 */
mask_t
p448_montgomery_ladder(
    struct p448_t *out,
    const struct p448_t *in,
    const uint64_t *scalar,
    int nbits,
    int n_extra_doubles
);

void
edwards_scalar_multiply(
    struct tw_extensible_t *working,
    const uint64_t scalar[7]
    /* TODO? int nbits */
);
    
mask_t
precompute_for_combs(
  struct tw_niels_t *out,
  const struct tw_extensible_t *const_base,
  int n,
  int t,
  int s
);
    
void
edwards_comb(
    struct tw_extensible_t *working,
    const word_t scalar[7],
    const struct tw_niels_t *table,
    int n,
    int t,
    int s
);

/* TODO: void.  int is just for diagnostic purposes. */
int
edwards_scalar_multiply_vt(
    struct tw_extensible_t *working,
    const uint64_t scalar[7]
);
    
void
edwards_scalar_multiply_vt_pre(
    struct tw_extensible_t *working,
    const uint64_t scalar[7],
    const struct tw_niels_t *precmp,
    int table_bits
);

mask_t
precompute_for_wnaf(
    struct tw_niels_t *out,
    const struct tw_extensible_t *const_base,
    int tbits
); /* TODO: attr don't ignore... */

/* TODO: void.  int is just for diagnostic purposes. */
int
edwards_combo_var_fixed_vt(
    struct tw_extensible_t *working,
    const uint64_t scalar_var[7],
    const uint64_t scalar_pre[7],
    const struct tw_niels_t *precmp,
    int table_bits_pre
);

#ifdef __cplusplus
};
#endif

#endif /* __P448_ALGO_H__ */
