/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.h
 * @author Mike Hamburg
 * @brief A group of prime order p.
 *
 * The Decaf library implements cryptographic operations on a an elliptic curve
 * group of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Ed448-Goldilocks) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases, except that
 * decaf_decode can fail because not every sequence of bytes is a valid group
 * element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses.
 */
#ifndef __DECAF_H__
#define __DECAF_H__ 1

#include <stdint.h>

typedef uint64_t decaf_word_t, decaf_bool_t;
#define DECAF_LIMBS (512/8/sizeof(decaf_word_t))
#define DECAF_SER_BYTES 56
typedef struct decaf_point_s {
    decaf_word_t x[DECAF_LIMBS],y[DECAF_LIMBS],z[DECAF_LIMBS],t[DECAF_LIMBS];
} decaf_point_t[1];

static const decaf_bool_t DECAF_SUCCESS = -(decaf_bool_t)1, DECAF_FAILURE = 0;

const decaf_point_t decaf_identity;

#ifdef __cplusplus
extern "C" {
#endif
    
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))

void decaf_encode (
    uint8_t ser[DECAF_SER_BYTES],
    const decaf_point_t pt
) API_VIS NONNULL2;
    
decaf_bool_t decaf_decode (
    decaf_point_t pt,
    const uint8_t ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) API_VIS WARN_UNUSED NONNULL2;
    
void decaf_add (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_point_t c
) API_VIS NONNULL3;
    
void decaf_copy (
    decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL2;
    
decaf_bool_t decaf_eq (
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS WARN_UNUSED NONNULL2;
    
void decaf_sub (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_point_t c
) API_VIS NONNULL3;
    
void decaf_add_sub (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_point_t c,
    decaf_bool_t do_sub
) API_VIS NONNULL3;

void decaf_scalarmul (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_word_t *scalar,
    unsigned int scalar_words
) API_VIS NONNULL3;
    
#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL2
#undef NONNULL3

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __DECAF_H__ */
