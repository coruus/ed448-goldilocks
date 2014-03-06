/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __WORD_H__
#define __WORD_H__

#include <stdint.h>

typedef uint64_t word_t;
typedef __uint128_t dword_t;
typedef int64_t sword_t;
typedef __int128_t dsword_t;

static const int WORD_BITS = sizeof(word_t) * 8;

/* TODO: vector width for procs like ARM; gcc support */
typedef uint64_t mask_t, vecmask_t __attribute__((ext_vector_type(4)));

static const mask_t MASK_FAILURE = 0, MASK_SUCCESS = -1;

/* FIXME this only works on clang */
typedef uint64_t uint64x2_t __attribute__((ext_vector_type(2)));
typedef int64_t  int64x2_t __attribute__((ext_vector_type(2)));
typedef uint64_t uint64x4_t __attribute__((ext_vector_type(4)));
typedef int64_t  int64x4_t __attribute__((ext_vector_type(4)));
typedef uint32_t uint32x4_t __attribute__((ext_vector_type(4)));
typedef int32_t  int32x4_t __attribute__((ext_vector_type(4)));
typedef uint32_t uint32x8_t __attribute__((ext_vector_type(8)));
typedef int32_t  int32x8_t __attribute__((ext_vector_type(8)));

#if __AVX2__
typedef uint32x8_t big_register_t;
typedef uint64x4_t uint64xn_t;
#elif __SSE2__ || __ARM_NEON__
typedef uint32x4_t big_register_t;
typedef uint64x2_t uint64xn_t;
#elif _WIN64 || __amd64__ || __X86_64__ || __aarch64__
typedef uint64_t big_register_t, uint64xn_t;
#else
typedef uint64_t uint64xn_t;
typedef uint32_t big_register_t;
#endif


#if __AVX2__ || __SSE2__ || __ARM_NEON__
static __inline__ big_register_t
br_is_zero(big_register_t x) {
    return (big_register_t)(x == (big_register_t)0);
}
#else
#error "TODO: constant-time equality on vectorless platforms"
#endif

#endif /* __WORD_H__ */
