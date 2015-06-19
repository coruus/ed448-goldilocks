/**
 * @file decaf_config.h
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief Configuration for decaf_fast.c
 */
#ifndef __DECAF_255_CONFIG_H__
#define __DECAF_255_CONFIG_H__ 1

/**
 * Use the Montgomery ladder for direct scalarmul.
 *
 * The Montgomery ladder is faster than Edwards scalarmul, but providing
 * the features Decaf supports (cofactor elimination, twist rejection)
 * makes it complicated and adds code.  Removing the ladder saves a few
 * kilobytes at the cost of perhaps 5-10% overhead in direct scalarmul
 * time.
 */
#define DECAF_USE_MONTGOMERY_LADDER 1

/** The number of comb tables for fixed base scalarmul. */
#define DECAF_COMBS_N 3

/** The number of teeth per comb for fixed base scalarmul. */
#define DECAF_COMBS_T 5

/** The comb spacing fixed base scalarmul. */
#define DECAF_COMBS_S 17

/** Performance tuning: the width of the fixed window for scalar mul. */
#define DECAF_WINDOW_BITS 4

/**
 * The number of bits used for the precomputed table in variable-time
 * double scalarmul.
 */
#define DECAF_WNAF_FIXED_TABLE_BITS 5

/**
 * Performance tuning: bits used for the variable table in variable-time
 * double scalarmul.
 */
#define DECAF_WNAF_VAR_TABLE_BITS 3


#endif /* __DECAF_255_CONFIG_H__ */
