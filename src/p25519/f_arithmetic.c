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

extern field_a_t ONE; // TODO

static const field_a_t SQRT_MINUS_ONE = FIELD_LITERAL( // FIXME goes elsewhere?
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d
);

void 
field_isr (
    field_a_t a,
    const field_a_t x
) {
    field_a_t st[3], tmp1, tmp2;
    const struct { unsigned char sh, idx } ops[] = {
        {1,2},{1,2},{3,1},{6,0},{1,2},{12,1},{25,1},{25,1},{50,0},{125,0},{2,2},{1,2}
    };
    field_cpy(st[0],x);
    field_cpy(st[1],x);
    field_cpy(st[2],x);
    int i;
    for (i=0; i<sizeof(ops)/sizeof(ops[0]); i++) {
        field_sqrn(tmp1, st[1^i&1], ops[i].sh);
        field_mul(tmp2, tmp1, st[ops[i].idx]);
        field_cpy(st[i&1], tmp2);
    }
    
    mask_t m = field_eq(st[1], ONE);
    cond_sel(tmp1,SQRT_MINUS_ONE,ONE,m);
    field_mul(a,tmp1,st[0]);
};

void 
field_isr (
    field_a_t a,
    const field_a_t x
) {
    field_a_t st[3], tmp1, tmp2;
    const struct { unsigned char sh, idx } ops[] = {
        {1,2},{1,2},{3,1},{6,0},{1,2},{12,1},{25,1},{25,1},{50,0},{125,0},{2,2},{1,2}
    };
    field_cpy(st[0],x);
    field_cpy(st[1],x);
    field_cpy(st[2],x);
    int i;
    for (i=0; i<sizeof(ops)/sizeof(ops[0]); i++) {
        field_sqrn(tmp1, st[1^i&1], ops[i].sh);
        field_mul(tmp2, tmp1, st[ops[i].idx]);
        field_cpy(st[i&1], tmp2);
    }
    
    mask_t m = field_eq(st[1], ONE);
}
