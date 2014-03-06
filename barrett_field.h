/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __BARRETT_FIELD_H__
#define __BARRETT_FIELD_H__ 1

#include "word.h"

#ifdef __cplusplus
extern "C" {
#endif

void
barrett_reduce(
    word_t *a,
    int nwords_a,
    word_t a_carry,
    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
);
    
/*
 * out = a+(c&mask), with carry returned.
 * #out must equal #a (HACK?)
 */
word_t
add_nr_ext_packed(
    word_t *out,
    const word_t *a,
    int nwords_a,
    const word_t *c,
    int nwords_c,
    word_t mask
);
    
word_t
sub_nr_ext_packed(
    word_t *out,
    const word_t *a,
    int nwords_a,
    const word_t *c,
    int nwords_c,
    word_t mask
);
    
void
barrett_negate (
    word_t *a,
    int nwords_a,
    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
);

/*
 * If doMac, accum = accum + a*b mod p.
 * Otherwise, accum = a*b mod p.
 *
 * This function is not __restrict__; you may pass accum,
 * a, b, etc all from the same location.
 */
void
barrett_mul_or_mac(
    word_t *accum,
    int nwords_accum,

    const word_t *a,
    int nwords_a,

    const word_t *b,
    int nwords_b,

    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift,
    
    mask_t doMac
);
    
static inline void
barrett_mul(
    word_t *out,
    int nwords_out,

    const word_t *a,
    int nwords_a,

    const word_t *b,
    int nwords_b,

    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
) {
    barrett_mul_or_mac(out,nwords_out,a,nwords_a,b,nwords_b,p_lo,nwords_p,nwords_lo,p_shift,0);
}
    
static inline void
barrett_mac(
    word_t *out,
    int nwords_out,

    const word_t *a,
    int nwords_a,

    const word_t *b,
    int nwords_b,

    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
) {
    barrett_mul_or_mac(out,nwords_out,a,nwords_a,b,nwords_b,p_lo,nwords_p,nwords_lo,p_shift,-1);
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __BARRETT_FIELD_H__ */
