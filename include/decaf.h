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

/* Goldilocks' build flags default to hidden and stripping executables. */
#define API_VIS __attribute__((visibility("default")))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
#define NONNULL5 __attribute__((nonnull(1,2,3,4,5)))

/** Types of internal words.  TODO: ARCH: make 32-bit clean */
typedef uint64_t decaf_word_t, decaf_bool_t;

/* TODO: prefix all these operations and factor to support multiple curves. */

/* TODO: perfield, so when 25519 hits this will change */
#define DECAF_FIELD_BITS 448
#define DECAF_LIMBS (1 + (512-1)/8/sizeof(decaf_word_t))
#define DECAF_SCALAR_LIMBS (1 + (448-3)/8/sizeof(decaf_word_t))

/** Number of bytes in a serialized point.  One less bit than you'd think. */
#define DECAF_SER_BYTES ((DECAF_FIELD_BITS+6)/8)

/** Number of bytes in a serialized scalar.  Two less bits than you'd think. */
#define DECAF_SCALAR_BYTES ((DECAF_FIELD_BITS+5)/8)

/** Twisted Edwards (-1,d-1) extended homogeneous coordinates */
typedef struct decaf_point_s {
    decaf_word_t x[DECAF_LIMBS],y[DECAF_LIMBS],z[DECAF_LIMBS],t[DECAF_LIMBS];
} decaf_point_t[1];

/** Scalar is stored packed, because we don't need the speed. */
typedef struct decaf_scalar_s {
    decaf_word_t limb[DECAF_SCALAR_LIMBS];
} decaf_scalar_t[1];

/** DECAF_TRUE = -1 so that DECAF_TRUE & x = x */
static const decaf_bool_t DECAF_TRUE = -(decaf_bool_t)1, DECAF_FALSE = 0;

/** NB Success is -1, failure is 0.  TODO: see if people would rather the reverse. */
static const decaf_bool_t DECAF_SUCCESS = -(decaf_bool_t)1 /*DECAF_TRUE*/,
	DECAF_FAILURE = 0 /*DECAF_FALSE*/;

/** The prime p, for debugging purposes.
 * TODO: prevent this scalar from actually being used for non-debugging purposes?
 */
const decaf_scalar_t decaf_scalar_p API_VIS;

/** A scalar equal to 1. */
const decaf_scalar_t decaf_scalar_one API_VIS;

/** A scalar equal to 0. */
const decaf_scalar_t decaf_scalar_zero API_VIS;

/** The identity point on the curve. */
const decaf_point_t decaf_point_identity API_VIS;

/**
 * An arbitrarily chosen base point on the curve.
 * Equal to Ed448-Goldilocks base point defined by DJB, except of course that
 * it's on the twist in this case.  TODO: choose a base point with nice encoding?
 */
const decaf_point_t decaf_point_base API_VIS;

#ifdef __cplusplus
extern "C" {
#endif
    
/* TODO: scalar invert? */

/**
 * @brief Read a scalar from wire format or from bytes.
 *
 * Return DECAF_SUCCESS if the scalar was in reduced form.  This
 * function is not WARN_UNUSED because eg challenges in signatures
 * may need to be longer.
 *
 * TODO: create a decode long function, and make this WARN_UNUSED.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [out] out Deserialized form.
 */
decaf_bool_t decaf_scalar_decode (
    decaf_scalar_t s,
    const unsigned char ser[DECAF_SER_BYTES]
) API_VIS NONNULL2;
    
/**
 * @brief Serialize a scalar to wire format.
 *
 * @param [out] ser Serialized form of a scalar.
 * @param [in] s Deserialized scalar.
 */
void decaf_scalar_encode (
    unsigned char ser[DECAF_SER_BYTES],
    const decaf_scalar_t s
) API_VIS NONNULL2;
        
/**
 * @brief Add two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a+b.
 */
void decaf_scalar_add (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) API_VIS NONNULL3;

/**
 * @brief Compare two scalars.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @retval DECAF_TRUE The scalars are equal.
 * @retval DECAF_FALSE The scalars are not equal.
 */    
decaf_bool_t decaf_scalar_eq (
    const decaf_scalar_t a,
    const decaf_scalar_t b
) API_VIS WARN_UNUSED NONNULL2;

/**
 * @brief Subtract two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a-b.
 */  
void decaf_scalar_sub (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) API_VIS NONNULL3;

/**
 * @brief Multiply two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a*b.
 */  
void decaf_scalar_mul (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) API_VIS NONNULL3;

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */  
void decaf_scalar_copy (
    decaf_scalar_t out,
    const decaf_scalar_t a
) API_VIS NONNULL2;

/**
 * @brief Encode a point as a sequence of bytes.
 *
 * @param [out] ser The byte representation of the point.
 * @param [in] pt The point to encode.
 */
void decaf_point_encode (
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
decaf_bool_t decaf_point_decode (
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
void decaf_point_copy (
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
decaf_bool_t decaf_point_eq (
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
void decaf_point_add (
    decaf_point_t sum,
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL3;

/**
 * @brief Double a point.  Equivalent to
 * decaf_point_add(two_a,a,a), but potentially faster.
 *
 * @param [out] sum The sum a+a.
 * @param [in] a A point.
 */
void decaf_point_double (
    decaf_point_t two_a,
    const decaf_point_t a
) API_VIS NONNULL2;

/**
 * @brief Subtract two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The difference a-b.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void decaf_point_sub (
    decaf_point_t diff,
    const decaf_point_t a,
    const decaf_point_t b
) API_VIS NONNULL3;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multilpy by.
 */
void decaf_point_scalarmul (
    decaf_point_t scaled,
    const decaf_point_t base,
    const decaf_scalar_t scalar
) API_VIS NONNULL3;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*base1 + scalar2*base2.
 *
 * Equivalent to two calls to decaf_point_scalarmul, but may be
 * faster.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base1 A first point to be scaled.
 * @param [in] scalar1 A first scalar to multilpy by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multilpy by.
 * @TODO: test
 */
void decaf_point_double_scalarmul (
    decaf_point_t combo,
    const decaf_point_t base1,
    const decaf_scalar_t scalar1,
    const decaf_point_t base2,
    const decaf_scalar_t scalar2
) API_VIS NONNULL5;

/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] point The number to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
decaf_bool_t decaf_point_valid (
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
 * Negating the input (mod q) results in the same point.  Inverting the input
 * (mod q) results in the negative point.  This is the same as Elligator.
 *
 * This function isn't quite indifferentiable from a random oracle.
 * However, it is suitable for many protocols, including SPEKE and SPAKE2 EE. 
 * Furthermore, calling it twice with independent seeds and adding the results
 * is indifferentiable from a random oracle.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */
void decaf_point_from_hash_nonuniform (
    decaf_point_t pt,
    const unsigned char hashed_data[DECAF_SER_BYTES]
) API_VIS NONNULL2;

/**
 * @brief Indifferentiable hash function encoding to curve.
 *
 * Equivalent to calling decaf_point_from_hash_nonuniform twice and adding.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 */ 
void decaf_point_from_hash_uniform (
    decaf_point_t pt,
    const unsigned char hashed_data[2*DECAF_SER_BYTES]
) API_VIS NONNULL2;
    
/* TODO: functions to invert point_from_hash?? */
    
#undef API_VIS
#undef WARN_UNUSED
#undef NONNULL1
#undef NONNULL2
#undef NONNULL3
#undef NONNULL5

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __DECAF_H__ */
