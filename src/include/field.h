/**
 * @file field.h
 * @brief Generic field header.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __FIELD_H__
#define __FIELD_H__

#include "constant_time.h"
#include "f_field.h"
#include <string.h>

/** @brief Bytes in a field element */
#define FIELD_BYTES          (1+(FIELD_BITS-1)/8)

/** @brief Words in a field element */
#define FIELD_WORDS          (1+(FIELD_BITS-1)/sizeof(word_t))

/* TODO: standardize notation */
/** @brief The number of words in the Goldilocks field. */
#define GOLDI_FIELD_WORDS DIV_CEIL(FIELD_BITS,WORD_BITS)

/** @brief The number of bits in the Goldilocks curve's cofactor (cofactor=4). */
#define COFACTOR_BITS 2

/** @brief The number of bits in a Goldilocks scalar. */
#define SCALAR_BITS (FIELD_BITS - COFACTOR_BITS)

/** @brief The number of bytes in a Goldilocks scalar. */
#define SCALAR_BYTES (1+(SCALAR_BITS)/8)

/** @brief The number of words in the Goldilocks field. */
#define SCALAR_WORDS WORDS_FOR_BITS(SCALAR_BITS)

/**
 * @brief For GMP tests: little-endian representation of the field modulus.
 */
extern const uint8_t FIELD_MODULUS[FIELD_BYTES];

/**
 * Copy one field element to another.
 */
static inline void
__attribute__((unused,always_inline))        
field_copy (
    struct field_t *__restrict__ a,
    const struct field_t *__restrict__ b
) {
    memcpy(a,b,sizeof(*a));
}

/**
 * Negate a in place if doNegate.
 */
static inline void
__attribute__((unused,always_inline)) 
field_cond_neg(
    field_t *a,
    mask_t doNegate
) {
	struct field_t negated;
    field_neg(&negated, a);
    field_bias(&negated, 2);
	constant_time_select(a, &negated, a, sizeof(negated), doNegate);
}

/**
 * Returns 1/sqrt(+- x).
 * 
 * The Legendre symbol of the result is the same as that of the
 * input.
 * 
 * If x=0, returns 0.
 */
void
field_isr (
    struct field_t*       a,
    const struct field_t* x
);
    
/**
 * Batch inverts out[i] = 1/in[i]
 * 
 * If any input is zero, all the outputs will be zero.
 */     
void
field_simultaneous_invert (
    struct field_t *__restrict__ out,
    const struct field_t *in,
    unsigned int n
);

/**
 * Returns 1/x.
 * 
 * If x=0, returns 0.
 */
void
field_inverse (
    struct field_t*       a,
    const struct field_t* x
);

/**
 * Returns -1 if a==b, 0 otherwise.
 */
mask_t
field_eq (
    const struct field_t *a,
    const struct field_t *b
);
    
/**
 * Square x, n times.
 */
static __inline__ void
__attribute__((unused,always_inline))
field_sqrn (
    field_t *__restrict__ y,
    const field_t *x,
    int n
) {
    field_t tmp;
    assert(n>0);
    if (n&1) {
        field_sqr(y,x);
        n--;
    } else {
        field_sqr(&tmp,x);
        field_sqr(y,&tmp);
        n-=2;
    }
    for (; n; n-=2) {
        field_sqr(&tmp,y);
        field_sqr(y,&tmp);
    }
}

static __inline__ mask_t
__attribute__((unused,always_inline))
field_low_bit (const field_t *f) {
    struct field_t red;
    field_copy(&red,f);
    field_strong_reduce(&red);
    return -(1&red.limb[0]);
}

static __inline__ mask_t
__attribute__((unused,always_inline))
field_make_nonzero (field_t *f) {
    mask_t z = field_is_zero(f);
    field_addw( f, -z );
    return z;
}

#endif // __FIELD_H__
