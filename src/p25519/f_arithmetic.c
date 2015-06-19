/**
 * @cond internal
 * @file f_arithmetic.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief Field-specific arithmetic.
 */

#include "field.h"

const field_a_t SQRT_MINUS_ONE = {FIELD_LITERAL( // FIXME goes elsewhere?
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d
)};
    
static const field_a_t ONE = {FIELD_LITERAL( // FIXME copy-pasted
    1,0,0,0,0
)}; 

// ARCH MAGIC FIXME copy-pasted from decaf_fast.c
static mask_t gf_eq(const field_a_t a, const field_a_t b) {
    field_a_t c;
    field_sub(c,a,b);
    field_strong_reduce(c);
    mask_t ret=0;
    int i;
    for (i=0; i<5; i++) { ret |= c->limb[i]; }
    return ((__uint128_t)ret - 1) >> 64;
}

/* Guarantee: a^2 x = 0 if x = 0; else a^2 x = 1 or SQRT_MINUS_ONE; */
void 
field_isr (
    field_a_t a,
    const field_a_t x
) {
    field_a_t st[3], tmp1, tmp2;
    const struct { unsigned char sh, idx; } ops[] = {
        {1,2},{1,2},{3,1},{6,0},{1,2},{12,1},{25,1},{25,1},{50,0},{125,0},{2,2},{1,2}
    };
    st[0][0] = st[1][0] = st[2][0] = x[0];
    unsigned int i;
    for (i=0; i<sizeof(ops)/sizeof(ops[0]); i++) {
        field_sqrn(tmp1, st[1^i&1], ops[i].sh);
        field_mul(tmp2, tmp1, st[ops[i].idx]);
        st[i&1][0] = tmp2[0];
    }
    
    mask_t mask = gf_eq(st[1],ONE) | gf_eq(st[1],SQRT_MINUS_ONE);
    
    // ARCH MAGIC FIXME: should be cond_sel
    for (i=0; i<5; i++) tmp1->limb[i] = (ONE->limb[i]            &  mask)
                                      | (SQRT_MINUS_ONE->limb[i] & ~mask);
    field_mul(a,tmp1,st[0]);
}
