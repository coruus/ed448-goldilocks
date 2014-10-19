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

#include "p448.h"

#define FIELD_BITS           448
#define FIELD_BYTES          (1+(FIELD_BITS-1)/8)
#define FIELD_WORDS          (1+(FIELD_BITS-1)/sizeof(word_t))

/**
 * @brief For GMP tests: little-endian representation of the field modulus.
 */
extern const uint8_t FIELD_MODULUS[FIELD_BYTES];

#define field_t              p448_t
#define field_mul            p448_mul
#define field_sqr            p448_sqr
#define field_sqrn           p448_sqrn
#define field_add            p448_add
#define field_sub            p448_sub
#define field_mulw           p448_mulw
#define field_addw           p448_addw
#define field_subw           p448_subw
#define field_neg            p448_neg
#define field_set_ui         p448_set_ui
#define field_bias           p448_bias
#define field_copy           p448_copy
#define field_mask           p448_mask
#define field_weak_reduce    p448_weak_reduce
#define field_strong_reduce  p448_strong_reduce
#define field_cond_swap      p448_cond_swap
#define field_cond_neg       p448_cond_neg
#define field_serialize      p448_serialize
#define field_deserialize    p448_deserialize
#define field_eq             p448_eq
#define field_is_zero        p448_is_zero

#endif /* __FIELD_H__ */
