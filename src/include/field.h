/**
 * @file field.h
 * @brief Field switch code.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */
#ifndef __FIELD_H__
#define __FIELD_H__

#include "constant_time.h"
#include <string.h>

#include "p448.h"
#define FIELD_BITS           448
#define field_t              p448_t
#define field_mul            p448_mul
#define field_sqr            p448_sqr
#define field_add            p448_add
#define field_sub            p448_sub
#define field_mulw           p448_mulw
#define field_addw           p448_addw
#define field_subw           p448_subw
#define field_neg            p448_neg
#define field_set_ui         p448_set_ui
#define field_bias           p448_bias
#define field_cond_neg       p448_cond_neg
#define field_inverse        p448_inverse
#define field_eq             p448_eq
#define field_isr            p448_isr
#define field_simultaneous_invert p448_simultaneous_invert
#define field_weak_reduce    p448_weak_reduce
#define field_strong_reduce  p448_strong_reduce
#define field_serialize      p448_serialize
#define field_deserialize    p448_deserialize
#define field_is_zero        p448_is_zero

/** @brief Bytes in a field element */
#define FIELD_BYTES          (1+(FIELD_BITS-1)/8)

/** @brief Words in a field element */
#define FIELD_WORDS          (1+(FIELD_BITS-1)/sizeof(word_t))

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

#endif /* __FIELD_H__ */
