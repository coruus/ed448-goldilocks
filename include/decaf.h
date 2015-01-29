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

/* TODO: perfield, so when 25519 hits this will change */
#define DECAF_FIELD_BITS 448
#define DECAF_LIMBS (512/8/sizeof(decaf_word_t))

/** Number of bytes in a serialized point.  One less bit than you'd think. */
#define DECAF_SER_BYTES ((DECAF_FIELD_BITS+6)/8)

/** Twisted Edwards (-1,d-1) extended homogeneous coordinates */
typedef struct decaf_point_s {
    decaf_word_t x[DECAF_LIMBS],y[DECAF_LIMBS],z[DECAF_LIMBS],t[DECAF_LIMBS];
} decaf_point_t[1];

static const decaf_bool_t DECAF_TRUE = -(decaf_bool_t)1, DECAF_FALSE = 0;

/** NB Success is -1, failure is 0.  TODO: see if people would rather the reverse. */
static const decaf_bool_t DECAF_SUCCESS = DECAF_TRUE, DECAF_FAILURE = DECAF_FALSE;

/** The identity point on the curve. */
const decaf_point_t decaf_identity;

/** An arbitrarily chosen base point on the curve.  TODO: define */
const decaf_point_t decaf_basepoint;

#ifdef __cplusplus
extern "C" {
#endif

/* Goldilocks' build flags default to hidden and stripping executables. */
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))

/**
 * @brief Encode a point as a sequence of bytes.
 *
 * @param [out] ser The byte representation of the point.
 * @param [in] pt The point to encode.
 */
void decaf_encode (
    uint8_t ser[DECAF_SER_BYTES],
    const decaf_point_t pt
) API_VIS NONNULL2;

/**
 * @brief Decode a point from a sequence of bytes.
 *
 * Every point has a unique encoding, so not every
 * sequence of bytes is a valid encoding.  If an invalid
 * encoding is given, the output is undefined.
 *
 * @param [out] pt The decoded point.
 * @param [in] ser The serialized version of the point.
 * @retval DECAF_SUCCESS The decoding succeeded.
 * @retval DECAF_FAILURE The decoding didn't succeed, because
 * ser does not represent a point.
 */
decaf_bool_t decaf_decode (
    decaf_point_t pt,
    const uint8_t ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) API_VIS WARN_UNUSED NONNULL2;

/**
 * @brief Copy a point.  The input and output may alias,
 * in which case this function does nothing.
 *
 * @param [out] a A copy of the point.
 * @param [in] b Any point.
 */
void decaf_copy (
    decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL2;

/**
 * @brief Test whether two points are equal.  If yes, return
 * DECAF_TRUE, else return DECAF_FALSE.
 *
 * @param [in] a A point.
 * @param [in] b Another point.
 * @retval DECAF_TRUE The points are equal.
 * @retval DECAF_FALSE The points are not equal.
 */
decaf_bool_t decaf_eq (
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS WARN_UNUSED NONNULL2;

/**
 * @brief Add two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The sum a+b.
 * @param [in] a An addend.
 * @param [in] b An addend.
 */
void decaf_add (
    decaf_point_t sum,
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL3;

/**
 * @brief Subtract two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The difference a-b.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void decaf_sub (
    decaf_point_t diff,
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL3;

/**
 * @brief Multiply a base point by a scalar.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multilpy by.
 * @param [in] scalar_words The number of words in the scalar [TODO]
 */
void decaf_scalarmul (
    decaf_point_t scaled,
    const decaf_point_t base,
    const decaf_word_t *scalar,
    unsigned int scalar_words
) API_VIS NONNULL3;
    
/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] point The number to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
decaf_bool_t decaf_valid (
    const decaf_point_t toTest
) API_VIS WARN_UNUSED NONNULL1;

/**
 * @brief Almost-Elligator-like hash to curve.
 *
 * Call this function with the output of a hash to make a hash to the curve.
 *
 * This function runs Elligator2 on the decaf Jacobi quartic model.  It then
 * uses the isogeny to put the result in twisted Edwards form.  As a result,
 * it is safe (cannot produce points of order 4), and would be compatible with
 * hypothetical other implementations of Decaf using a Montgomery or untwisted
 * Edwards model.
 *
 * Unlike Elligator, this function may be up to 4:1 on [0,(p-1)/2]:
 *   A factor of 2 due to the isogeny.
 *   A factor of 2 because we quotient out the 2-torsion.
 * // TODO: check that it isn't more, especially for the identity point.
 *
 * This function isn't quite indifferentiable from a random oracle.
 * However, it is suitable for many protocols, including SPEKE and SPAKE2 EE. 
 * Furthermore, calling it twice with independent seeds and adding the results
 * is indifferentiable from a random oracle.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */
void decaf_nonuniform_map_to_curve (
    decaf_point_t pt,
    const unsigned char hashed_data[DECAF_SER_BYTES]
) API_VIS NONNULL2;

/**
 * @brief Indifferentiable hash function encoding to curve.
 *
 * Equivalent to calling decaf_nonuniform_map_to_curve twice and adding.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */ 
void decaf_uniform_map_to_curve (
    decaf_point_t pt,
    const unsigned char hashed_data[2*DECAF_SER_BYTES]
) API_VIS NONNULL2;
    
#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL2
#undef NONNULL3

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __DECAF_H__ */
