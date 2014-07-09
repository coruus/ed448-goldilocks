/**
 * @file scalarmul.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __P448_ALGO_H__
#define __P448_ALGO_H__ 1

#include "ec_point.h"
#include "intrinsics.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A precomputed table for fixed-base scalar multiplication.
 *
 * This uses a signed combs format.
 */
struct fixed_base_table_t {
  /** Comb tables containing multiples of the base point. */
  struct tw_niels_t* table;

  /** Adjustments to the scalar in even and odd cases, respectively. */
  word_t scalar_adjustments[2 * (448 / WORD_BITS)]; /* MAGIC */

  /** The number of combs in the table. */
  unsigned int n;

  /** The number of teeth in each comb. */
  unsigned int t;

  /** The spacing between the teeth. */
  unsigned int s;

  /** If nonzero, the table was malloc'd by precompute_for_combs. */
  unsigned int own_table;
};

/**
 * Full Montgomery ladder in inverse square root format.
 *
 * Out = [2^n_extra_doubles * scalar] * in, where
 * scalar is little-endian and has length $nbits$ bits.
 *
 * If the scalar is even and/or n_extra_doubles >= 1,
 * then this function will reject points which are not
 * on the curve by returning MASK_FAILURE.
 *
 * This function will also reject multiplies which output
 * the identity or the point of order 2.  It may be worth
 * revisiting this decision in the FUTURE.  The idea is that
 * this can only happen when: the input is the identity or the
 * point of order 2; or the input is the point of order 4 on
 * the twist; or the scalar is 0 or a multiple of the curve
 * order; or the scalar is a multiple of the twist order and
 * the input point is on the twist.
 *
 * This function takes constant time with respect to $*in$
 * and $*scalar$, but not of course with respect to nbits or
 * n_extra_doubles.
 *
 * For security, we recommend setting n_extra_doubles = 1.
 * Because the cofactor of Goldilocks is 4 and input points
 * are always even (when on the curve), this will cancel the
 * cofactor.
 *
 * @param [out] out The output point.
 * @param [in] in The base point.
 * @param [in] scalar The scalar's little-endian representation.
 * @param [in] nbits The number of bits in the scalar.  Note that
 * unlike in Curve25519, we do not require the top bit to be set.
 * @param [in] n_extra_doubles The number of extra doubles to do at
 * the end.
 *
 * @retval MASK_SUCCESS The operation was successful.
 * @retval MASK_FAILURE The input point was invalid, or the output
 * would be the identity or the point of order 2.
 */
mask_t montgomery_ladder(struct p448_t* out,
                         const struct p448_t* in,
                         const word_t* scalar,
                         unsigned int nbits,
                         unsigned int n_extra_doubles)
    __attribute__((warn_unused_result));

/**
 * Scalar multiply a twisted Edwards-form point.
 *
 * This function takes constant time.
 *
 * Currently the scalar is always exactly 448 bits long.
 *
 * @param [inout] working The point to multply.
 * @param [in] scalar The scalar, in little-endian form.
 */
void scalarmul(struct tw_extensible_t* working,
               const word_t scalar[448 / WORD_BITS] /* MAGIC */
                                                    /* TODO? int nbits */
               );

/**
 * Scalar multiply a twisted Edwards-form point.  Use the same
 * algorithm as scalarmul(), but uses variable array indices.
 *
 * Currently the scalar is always exactly 448 bits long.
 *
 * @warning This function uses variable array indices,
 * so it is insecure against cache-timing attacks.  It is intended
 * for microbenchmarking, to see how much constant-time arithmetic
 * costs us.
 *
 * @param [inout] working The point to multply.
 * @param [in] scalar The scalar, in little-endian form.
 */
void scalarmul_vlook(struct tw_extensible_t* working,
                     const word_t scalar[448 / WORD_BITS] /* MAGIC */
                                                          /* TODO? int nbits */
                     );

/**
 * Precompute a table to accelerate fixed-point scalar
 * multiplication using the "multiple signed combs" approach.
 *
 * This function computes $n$ "comb" tables, each containing
 * 2^(t-1) points in tw_niels_t format.  You must have
 * n * t * s >= 446 for complete coverage.
 *
 * The scalar multiplication algorithm may adjust the scalar by
 * a multiple of q.  Therefore, we strongly recommend to use base
 * points in the q-torsion group (i.e. doubly even points).
 *
 * @param [out] out The table to compute.
 * @param [in] base The base point.
 * @param [in] n The number of combs in the table.
 * @param [in] t The number of teeth in each comb.
 * @param [in] s The spacing between the teeth.
 * @param [out] prealloc An optional preallocated array containing
 * space for n<<(t-1) values of type tw_niels_t.
 *
 * @retval MASK_SUCCESS Success.
 * @retval MASK_FAILURE Failure, most likely because we are out
 * of memory.
 */
mask_t precompute_fixed_base(struct fixed_base_table_t* out,
                             const struct tw_extensible_t* base,
                             unsigned int n,
                             unsigned int t,
                             unsigned int s,
                             struct tw_niels_t* prealloc)
    __attribute__((warn_unused_result));

/**
 * Destroy a fixed-base table.  Frees any memory that we allocated
 * for the combs.
 *
 * @param [in] table The table to destroy.
 */
void destroy_fixed_base(struct fixed_base_table_t* table);

/**
 * Scalar multiplication with precomputation.  Set working to
 * to [scalar] * Base, where Base is the base point passed to
 * precompute_for_combs().
 *
 * The scalar may be adjusted by a multiple of q, so this routine
 * can be wrong by a cofactor if the base has cofactor components.
 *
 * @param [out] out The output point.
 * @param [in] scalar The scalar.
 * @param [in] nbits The number of bits in the scalar.  Must be <= n*t*s.
 * @param [in] table The precomputed table.
 *
 * @retval MASK_SUCCESS Success.
 * @retval MASK_FAILURE Failure, because n*t*s < nbits
 */
mask_t scalarmul_fixed_base(struct tw_extensible_t* out,
                            const word_t* scalar,
                            unsigned int nbits,
                            const struct fixed_base_table_t* table);

/**
 * Variable-time scalar multiplication.
 *
 * @warning This function takes variable time.  It is intended for
 * microbenchmarking.
 *
 * @param [inout] working The input and output point.
 * @param [in] scalar The scalar.
 */
void scalarmul_vt(struct tw_extensible_t* working,
                  const word_t scalar[448 / WORD_BITS] /* MAGIC */
                  );

/**
 * Precompute a table to accelerate fixed-point scalar
 * multiplication (and, more importantly, linear combos)
 * using the "windowed non-adjacent form" approach.
 *
 * @param [out] out The output table.  Must have room for 1<<i entries.
 * @param [in] base The base point.
 * @param [in] tbits The number of bits to put in the table.
 *
 * @retval MASK_SUCCESS Success.
 * @retval MASK_FAILURE Failure, most likely because we are out
 * of memory.
 */
mask_t precompute_fixed_base_wnaf(struct tw_niels_t* out,
                                  const struct tw_extensible_t* base,
                                  unsigned int tbits) __attribute__((warn_unused_result));

/**
 * Variable-time scalar multiplication with precomputed WNAF
 * tables.
 *
 * @warning This function takes variable time.  It is intended for
 * microbenchmarking.
 *
 * @param [out] out The output point.
 * @param [in] scalar The scalar.
 * @param [in] nbits The number of bits in the scalar.
 * @param [in] precmp The precomputed WNAF table.
 * @param [in] table_bits The number of bits in the WNAF table.
 */
void scalarmul_fixed_base_wnaf_vt(struct tw_extensible_t* out,
                                  const word_t* scalar,
                                  unsigned int nbits,
                                  const struct tw_niels_t* precmp,
                                  unsigned int table_bits);

/**
 * Variable-time scalar linear combination of two points: one
 * variable, and one fixed (with fixed-base WNAF tables)
 *
 * @warning This function takes variable time.  It is intended for
 * signature verification.
 *
 * @param [inout] working The output point, and also the variable input.
 * @param [in] scalar_var The scalar for the variable input.
 * @param [in] nbits_var The number of bits in scalar_var.
 * @param [in] scalar_pre The scalar for the fixed input.
 * @param [in] nbits_pre The number of bits in scalar_pre.
 * @param [in] precmp The precomputed WNAF table.
 * @param [in] table_bits_pre The number of bits in the WNAF table.
 */
void linear_combo_var_fixed_vt(struct tw_extensible_t* working,
                               const word_t scalar_var[448 / WORD_BITS], /* MAGIC */
                               unsigned int nbits_var,
                               const word_t scalar_pre[448 / WORD_BITS], /* MAGIC */
                               unsigned int nbits_pre,
                               const struct tw_niels_t* precmp,
                               unsigned int table_bits_pre);

/**
 * Variable-time scalar linear combination of two fixed points.
 *
 * @warning This function takes variable time.  It is intended for
 * signature verification.
 *
 * @param [out] working The output point.
 * @param [in] scalar1 The first scalar.
 * @param [in] nbits1 The number of bits in the first scalar.
 * @param [in] table1 The first precomputed table.
 * @param [in] scalar2 The second scalar.
 * @param [in] nbits1 The number of bits in the second scalar.
 * @param [in] table1 The second precomputed table.
 *
 * @retval MASK_SUCCESS Success.
 * @retval MASK_FAILURE Failure, because eg the tables are too small.
 */
mask_t linear_combo_combs_vt(struct tw_extensible_t* out,
                             const word_t scalar1[448 / WORD_BITS],
                             unsigned int nbits1,
                             const struct fixed_base_table_t* table1,
                             const word_t scalar2[448 / WORD_BITS],
                             unsigned int nbits2,
                             const struct fixed_base_table_t* table2);

#ifdef __cplusplus
};
#endif

#endif /* __P448_ALGO_H__ */
