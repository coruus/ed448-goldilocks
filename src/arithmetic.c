/**
 * @cond internal
 * @file field.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief High-level arithmetic routines, independent of field (except 3 mod 4).
 */

#include "field.h"
#include "ec_point.h" // TODO

void
field_inverse (
    struct field_t*       a,
    const struct field_t* x
) {
    struct field_t L0, L1;
    field_isr  (   &L0,     x );
    field_sqr  (   &L1,   &L0 );
    field_sqr  (   &L0,   &L1 );
    field_mul  (     a,     x,   &L0 );
}

mask_t
field_is_square (
    const struct field_t* x
) {
    mask_t L2, L3;
    struct field_t L0, L1;
    field_isr  (   &L0,     x );
    field_sqr  (   &L1,   &L0 );
    field_mul  (   &L0,     x,   &L1 );
    field_subw (   &L0,     1 );
    field_bias (   &L0,     1 );
       L3 = field_is_zero(   &L0 );
       L2 = field_is_zero(     x );
    return    L3 |    L2;
}

void
field_simultaneous_invert (
    struct field_t *__restrict__ out,
    const struct field_t *in,
    unsigned int n
) {
  if (n==0) {
      return;
  } else if (n==1) {
      field_inverse(out,in);
      return;
  }
  
  field_copy(&out[1], &in[0]);
  int i;
  for (i=1; i<(int) (n-1); i++) {
      field_mul(&out[i+1], &out[i], &in[i]);
  }
  field_mul(&out[0], &out[n-1], &in[n-1]);
  
  struct field_t tmp;
  field_inverse(&tmp, &out[0]);
  field_copy(&out[0], &tmp);
  
  /* at this point, out[0] = product(in[i]) ^ -1
   * out[i] = product(in[0]..in[i-1]) if i != 0
   */
  for (i=n-1; i>0; i--) {
      field_mul(&tmp, &out[i], &out[0]);
      field_copy(&out[i], &tmp);
      
      field_mul(&tmp, &out[0], &in[i]);
      field_copy(&out[0], &tmp);
  }
}
