/**
 * @file decaf.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p.
 *
 * The Decaf library implements cryptographic operations on a an elliptic curve
 * group of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Ed448-Goldilocks) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases, except that
 * decaf_448_decode can fail because not every sequence of bytes is a valid group
 * element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_448_base_double_scalarmul_non_secret.
 *
 * This library may support multiple curves eventually.  The Ed448-Goldilocks
 * specific identifiers are prefixed with DECAF_448 or decaf_448.
 */
#ifndef __DECAF_448_H__
#define __DECAF_448_H__ 1

#include <stdint.h>
#include <sys/types.h>

/* Goldilocks' build flags default to hidden and stripping executables. */
/** @cond internal */
#if defined(DOXYGEN) && !defined(__attribute__)
#define __attribute__((x))
#endif
#define API_VIS __attribute__((visibility("default")))
#define NOINLINE  __attribute__((noinline))
#define WARN_UNUSED __attribute__((warn_unused_result))
#define NONNULL1 __attribute__((nonnull(1)))
#define NONNULL2 __attribute__((nonnull(1,2)))
#define NONNULL3 __attribute__((nonnull(1,2,3)))
#define NONNULL4 __attribute__((nonnull(1,2,3,4)))
#define NONNULL5 __attribute__((nonnull(1,2,3,4,5)))

/* Internal word types */
#if (defined(__ILP64__) || defined(__amd64__) || defined(__x86_64__) || (((__UINT_FAST32_MAX__)>>30)>>30)) \
	 && !defined(DECAF_FORCE_32_BIT)
#define DECAF_WORD_BITS 64
typedef uint64_t decaf_word_t, decaf_bool_t;
typedef __uint128_t decaf_dword_t;
#else
#define DECAF_WORD_BITS 32
typedef uint32_t decaf_word_t, decaf_bool_t;
typedef uint64_t decaf_dword_t;
#endif

#define DECAF_448_LIMBS (512/DECAF_WORD_BITS)
#define DECAF_448_SCALAR_BITS 446
#define DECAF_448_SCALAR_LIMBS (448/DECAF_WORD_BITS)

/** Galois field element internal structure */
typedef struct gf_s {
    decaf_word_t limb[DECAF_448_LIMBS];
} __attribute__((aligned(32))) gf_s, gf[1];
/** @endcond */

/** Number of bytes in a serialized point. */
#define DECAF_448_SER_BYTES 56

/** Number of bytes in a serialized scalar. */
#define DECAF_448_SCALAR_BYTES 56

/** Twisted Edwards (-1,d-1) extended homogeneous coordinates */
typedef struct decaf_448_point_s { /**@cond internal*/gf x,y,z,t;/**@endcond*/ } decaf_448_point_t[1];

/** Precomputed table based on a point.  Can be trivial implementation. */
struct decaf_448_precomputed_s;

/** Precomputed table based on a point.  Can be trivial implementation. */
typedef struct decaf_448_precomputed_s decaf_448_precomputed_s; 

/** Size and alignment of precomputed point tables. */
extern const size_t sizeof_decaf_448_precomputed_s API_VIS, alignof_decaf_448_precomputed_s API_VIS;

/** Scalar is stored packed, because we don't need the speed. */
typedef struct decaf_448_scalar_s {
    /** @cond internal */
    decaf_word_t limb[DECAF_448_SCALAR_LIMBS];
    /** @endcond */
} decaf_448_scalar_t[1];

/** DECAF_TRUE = -1 so that DECAF_TRUE & x = x */
static const decaf_bool_t DECAF_TRUE = -(decaf_bool_t)1, DECAF_FALSE = 0;

/** NB Success is -1, failure is 0.  TODO: see if people would rather the reverse. */
static const decaf_bool_t DECAF_SUCCESS = -(decaf_bool_t)1 /*DECAF_TRUE*/,
	DECAF_FAILURE = 0 /*DECAF_FALSE*/;

/** A scalar equal to 1. */
extern const decaf_448_scalar_t decaf_448_scalar_one API_VIS;

/** A scalar equal to 0. */
extern const decaf_448_scalar_t decaf_448_scalar_zero API_VIS;

/** The identity point on the curve. */
extern const decaf_448_point_t decaf_448_point_identity API_VIS;

/**
 * An arbitrarily chosen base point on the curve.
 * Equal to Ed448-Goldilocks base point defined by DJB, except of course that
 * it's on the twist in this case.  TODO: choose a base point with nice encoding?
 */
extern const decaf_448_point_t decaf_448_point_base API_VIS;

/** Precomputed table for the base point on the curve. */
extern const struct decaf_448_precomputed_s *decaf_448_precomputed_base API_VIS;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read a scalar from wire format or from bytes.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [out] out Deserialized form.
 *
 * @retval DECAF_SUCCESS The scalar was correctly encoded.
 * @retval DECAF_FAILURE The scalar was greater than the modulus,
 * and has been reduced modulo that modulus.
 */
decaf_bool_t decaf_448_scalar_decode (
    decaf_448_scalar_t out,
    const unsigned char ser[DECAF_448_SCALAR_BYTES]
) API_VIS WARN_UNUSED NONNULL2 NOINLINE;

/**
 * @brief Read a scalar from wire format or from bytes.  Reduces mod
 * scalar prime.
 *
 * @param [in] ser Serialized form of a scalar.
 * @param [in] ser_len Length of serialized form.
 * @param [out] out Deserialized form.
 */
void decaf_448_scalar_decode_long (
    decaf_448_scalar_t out,
    const unsigned char *ser,
    size_t ser_len
) API_VIS NONNULL2 NOINLINE;
    
/**
 * @brief Serialize a scalar to wire format.
 *
 * @param [out] ser Serialized form of a scalar.
 * @param [in] s Deserialized scalar.
 */
void decaf_448_scalar_encode (
    unsigned char ser[DECAF_448_SCALAR_BYTES],
    const decaf_448_scalar_t s
) API_VIS NONNULL2 NOINLINE NOINLINE;
        
/**
 * @brief Add two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a+b.
 */
void decaf_448_scalar_add (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) API_VIS NONNULL3 NOINLINE;

/**
 * @brief Compare two scalars.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @retval DECAF_TRUE The scalars are equal.
 * @retval DECAF_FALSE The scalars are not equal.
 */    
decaf_bool_t decaf_448_scalar_eq (
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) API_VIS WARN_UNUSED NONNULL2 NOINLINE;

/**
 * @brief Subtract two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a-b.
 */  
void decaf_448_scalar_sub (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) API_VIS NONNULL3 NOINLINE;

/**
 * @brief Multiply two scalars.  The scalars may use the same memory.
 * @param [in] a One scalar.
 * @param [in] b Another scalar.
 * @param [out] out a*b.
 */  
void decaf_448_scalar_mul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) API_VIS NONNULL3 NOINLINE;

/**
 * @brief Invert a scalar.  When passed zero, return 0.  The input and output may alias.
 * @param [in] a A scalar.
 * @param [out] out 1/a.
 * @return DECAF_TRUE The input is nonzero.
 */  
decaf_bool_t decaf_448_scalar_invert (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Copy a scalar.  The scalars may use the same memory, in which
 * case this function does nothing.
 * @param [in] a A scalar.
 * @param [out] out Will become a copy of a.
 */
static inline void NONNULL2 decaf_448_scalar_copy (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    *out = *a;
}

/**
 * @brief Set a scalar to an integer.
 * @param [in] a An integer.
 * @param [out] out Will become equal to a.
 * @todo Make inline?
 */  
void decaf_448_scalar_set(
    decaf_448_scalar_t out,
    decaf_word_t a
) API_VIS NONNULL1;

/**
 * @brief Encode a point as a sequence of bytes.
 *
 * @param [out] ser The byte representation of the point.
 * @param [in] pt The point to encode.
 */
void decaf_448_point_encode (
    uint8_t ser[DECAF_448_SER_BYTES],
    const decaf_448_point_t pt
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Decode a point from a sequence of bytes.
 *
 * Every point has a unique encoding, so not every
 * sequence of bytes is a valid encoding.  If an invalid
 * encoding is given, the output is undefined.
 *
 * @param [out] pt The decoded point.
 * @param [in] ser The serialized version of the point.
 * @param [in] allow_identity DECAF_TRUE if the identity is a legal input.
 * @retval DECAF_SUCCESS The decoding succeeded.
 * @retval DECAF_FAILURE The decoding didn't succeed, because
 * ser does not represent a point.
 */
decaf_bool_t decaf_448_point_decode (
    decaf_448_point_t pt,
    const uint8_t ser[DECAF_448_SER_BYTES],
    decaf_bool_t allow_identity
) API_VIS WARN_UNUSED NONNULL2 NOINLINE;

/**
 * @brief Copy a point.  The input and output may alias,
 * in which case this function does nothing.
 *
 * @param [out] a A copy of the point.
 * @param [in] b Any point.
 */
static inline void NONNULL2 decaf_448_point_copy (
    decaf_448_point_t a,
    const decaf_448_point_t b
) {
    *a=*b;
}

/**
 * @brief Test whether two points are equal.  If yes, return
 * DECAF_TRUE, else return DECAF_FALSE.
 *
 * @param [in] a A point.
 * @param [in] b Another point.
 * @retval DECAF_TRUE The points are equal.
 * @retval DECAF_FALSE The points are not equal.
 */
decaf_bool_t decaf_448_point_eq (
    const decaf_448_point_t a,
    const decaf_448_point_t b
) API_VIS WARN_UNUSED NONNULL2 NOINLINE;

/**
 * @brief Add two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] sum The sum a+b.
 * @param [in] a An addend.
 * @param [in] b An addend.
 */
void decaf_448_point_add (
    decaf_448_point_t sum,
    const decaf_448_point_t a,
    const decaf_448_point_t b
) API_VIS NONNULL3;

/**
 * @brief Double a point.  Equivalent to
 * decaf_448_point_add(two_a,a,a), but potentially faster.
 *
 * @param [out] two_a The sum a+a.
 * @param [in] a A point.
 */
void decaf_448_point_double (
    decaf_448_point_t two_a,
    const decaf_448_point_t a
) API_VIS NONNULL2;

/**
 * @brief Subtract two points to produce a third point.  The
 * input points and output point can be pointers to the same
 * memory.
 *
 * @param [out] diff The difference a-b.
 * @param [in] a The minuend.
 * @param [in] b The subtrahend.
 */
void decaf_448_point_sub (
    decaf_448_point_t diff,
    const decaf_448_point_t a,
    const decaf_448_point_t b
) API_VIS NONNULL3;
    
/**
 * @brief Negate a point to produce another point.  The input
 * and output points can use the same memory.
 *
 * @param [out] nega The negated input point
 * @param [in] a The input point.
 */
void decaf_448_point_negate (
   decaf_448_point_t nega,
   const decaf_448_point_t a
) API_VIS NONNULL2;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 */
void decaf_448_point_scalarmul (
    decaf_448_point_t scaled,
    const decaf_448_point_t base,
    const decaf_448_scalar_t scalar
) API_VIS NONNULL3 NOINLINE;

/**
 * @brief Multiply a base point by a scalar: scaled = scalar*base.
 * This function operates directly on serialized forms.
 *
 * @warning This function is experimental.  It may not be supported
 * long-term.
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 * @param [in] allow_identity Allow the input to be the identity.
 * @param [in] short_circuit Allow a fast return if the input is illegal.
 *
 * @retval DECAF_SUCCESS The scalarmul succeeded.
 * @retval DECAF_FAILURE The scalarmul didn't succeed, because
 * base does not represent a point.
 */
decaf_bool_t decaf_448_direct_scalarmul (
    uint8_t scaled[DECAF_448_SER_BYTES],
    const uint8_t base[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) API_VIS NONNULL3 WARN_UNUSED NOINLINE;

/**
 * @brief Precompute a table for fast scalar multiplication.
 * Some implementations do not include precomputed points; for
 * those implementations, this implementation simply copies the
 * point.
 *
 * @param [out] a A precomputed table of multiples of the point.
 * @param [in] b Any point.
 */
void decaf_448_precompute (
    decaf_448_precomputed_s *a,
    const decaf_448_point_t b
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Multiply a precomputed base point by a scalar:
 * scaled = scalar*base.
 * Some implementations do not include precomputed points; for
 * those implementations, this function is the same as
 * decaf_448_point_scalarmul
 *
 * @param [out] scaled The scaled point base*scalar
 * @param [in] base The point to be scaled.
 * @param [in] scalar The scalar to multiply by.
 *
 * @todo precomputed dsmul? const or variable time?
 */
void decaf_448_precomputed_scalarmul (
    decaf_448_point_t scaled,
    const decaf_448_precomputed_s *base,
    const decaf_448_scalar_t scalar
) API_VIS NONNULL3 NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*base1 + scalar2*base2.
 *
 * Equivalent to two calls to decaf_448_point_scalarmul, but may be
 * faster.
 *
 * @param [out] combo The linear combination scalar1*base1 + scalar2*base2.
 * @param [in] base1 A first point to be scaled.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 */
void decaf_448_point_double_scalarmul (
    decaf_448_point_t combo,
    const decaf_448_point_t base1,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) API_VIS NONNULL5 NOINLINE;

/**
 * @brief Multiply two base points by two scalars:
 * scaled = scalar1*decaf_448_point_base + scalar2*base2.
 *
 * Otherwise equivalent to decaf_448_point_double_scalarmul, but may be
 * faster at the expense of being variable time.
 *
 * @param [out] combo The linear combination scalar1*base + scalar2*base2.
 * @param [in] scalar1 A first scalar to multiply by.
 * @param [in] base2 A second point to be scaled.
 * @param [in] scalar2 A second scalar to multiply by.
 *
 * @warning: This function takes variable time, and may leak the scalars
 * used.  It is designed for signature verification.
 */
void decaf_448_base_double_scalarmul_non_secret (
    decaf_448_point_t combo,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) API_VIS NONNULL4 NOINLINE;

/**
 * @brief Test that a point is valid, for debugging purposes.
 *
 * @param [in] toTest The point to test.
 * @retval DECAF_TRUE The point is valid.
 * @retval DECAF_FALSE The point is invalid.
 */
decaf_bool_t decaf_448_point_valid (
    const decaf_448_point_t toTest
) API_VIS WARN_UNUSED NONNULL1 NOINLINE;

/**
 * @brief 2-torque a point, for debugging purposes.
 *
 * @param [out] q The point to torque.
 * @param [in] p The point to torque.
 */
void decaf_448_point_debugging_2torque (
     decaf_448_point_t q,
     const decaf_448_point_t p
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Almost-Elligator-like hash to curve.
 *
 * Call this function with the output of a hash to make a hash to the curve.
 *
 * This function runs Elligator2 on the decaf_448 Jacobi quartic model.  It then
 * uses the isogeny to put the result in twisted Edwards form.  As a result,
 * it is safe (cannot produce points of order 4), and would be compatible with
 * hypothetical other implementations of Decaf using a Montgomery or untwisted
 * Edwards model.
 *
 * Unlike Elligator, this function may be up to 4:1 on [0,(p-1)/2]:
 *   A factor of 2 due to the isogeny.
 *   A factor of 2 because we quotient out the 2-torsion.
 *
 * This makes it about 8:1 overall.
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
 * @return A "hint" value which can be used to help invert the encoding.
 */
unsigned char
decaf_448_point_from_hash_nonuniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[DECAF_448_SER_BYTES]
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Inverse of elligator-like hash to curve.
 *
 * This function writes to the buffer, to make it so that
 * decaf_448_point_from_hash_nonuniform(buffer) = pt,hint
 * if possible.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] hint The hint value returned from 
 *   decaf_448_point_from_hash_nonuniform.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The pt isn't the image of 
 *    decaf_448_point_from_hash_nonuniform with the given hint.
 *
 * @warning The hinting system is subject to change, especially in corner cases.
 * @warning FIXME The hinting system doesn't work for certain inputs which have many 0xFF.
 */
decaf_bool_t
decaf_448_invert_elligator_nonuniform (
    unsigned char recovered_hash[DECAF_448_SER_BYTES],
    const decaf_448_point_t pt,
    unsigned char hint
) API_VIS NONNULL2 NOINLINE WARN_UNUSED;

/**
 * @brief Inverse of elligator-like hash to curve, uniform.
 *
 * This function modifies the first DECAF_448_SER_BYTES of the
 * buffer, to make it so that
 * decaf_448_point_from_hash_uniform(buffer) = pt,hint
 * if possible.
 *
 * @param [out] recovered_hash Encoded data.
 * @param [in] pt The point to encode.
 * @param [in] hint The hint value returned from 
 *   decaf_448_point_from_hash_nonuniform.
 *
 * @retval DECAF_SUCCESS The inverse succeeded.
 * @retval DECAF_FAILURE The pt isn't the image of 
 *    decaf_448_point_from_hash_uniform with the given hint.
 *
 * @warning The hinting system is subject to change, especially in corner cases.
 * @warning FIXME The hinting system doesn't work for certain inputs which have many 0xFF.
 */
decaf_bool_t
decaf_448_invert_elligator_uniform (
    unsigned char recovered_hash[2*DECAF_448_SER_BYTES],
    const decaf_448_point_t pt,
    unsigned char hint
) API_VIS NONNULL2 NOINLINE WARN_UNUSED;

/**
 * @brief Indifferentiable hash function encoding to curve.
 *
 * Equivalent to calling decaf_448_point_from_hash_nonuniform twice and adding.
 *
 * @param [in] hashed_data Output of some hash function.
 * @param [out] pt The data hashed to the curve.
 * @return A "hint" value which can be used to help invert the encoding.
 */ 
unsigned char decaf_448_point_from_hash_uniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[2*DECAF_448_SER_BYTES]
) API_VIS NONNULL2 NOINLINE;

/**
 * @brief Overwrite data with zeros.  Uses memset_s if available.
 */
void decaf_bzero (
   void *data,
   size_t size
) NONNULL1 API_VIS NOINLINE;

/**
 * @brief Compare two buffers, returning DECAF_TRUE if they are equal.
 */
decaf_bool_t decaf_memeq (
   const void *data1,
   const void *data2,
   size_t size
) NONNULL2 WARN_UNUSED API_VIS NOINLINE;

/**
 * @brief Overwrite scalar with zeros.
 */
void decaf_448_scalar_destroy (
  decaf_448_scalar_t scalar
) NONNULL1 API_VIS;

/**
 * @brief Overwrite point with zeros.
 * @todo Use this internally.
 */
void decaf_448_point_destroy (
  decaf_448_point_t point
) NONNULL1 API_VIS;

/**
 * @brief Overwrite point with zeros.
 * @todo Use this internally.
 */
void decaf_448_precomputed_destroy (
  decaf_448_precomputed_s *pre
) NONNULL1 API_VIS;

/* TODO: functions to invert point_from_hash?? */

#undef API_VIS
#undef WARN_UNUSED
#undef NOINLINE
#undef NONNULL1
#undef NONNULL2
#undef NONNULL3
#undef NONNULL4
#undef NONNULL5

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __DECAF_448_H__ */
