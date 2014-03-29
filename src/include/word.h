/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __WORD_H__
#define __WORD_H__

/* for posix_memalign */
#define _XOPEN_SOURCE 600

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

#if (__SIZEOF_INT128__ == 16 && __SIZEOF_SIZE_T__ == 8 && (__SIZEOF_LONG__==8 || __POINTER_WIDTH__==64) && !GOLDI_FORCE_32_BIT)
/* It's a 64-bit machine if:
 * // limits.h thinks so
 * __uint128_t exists
 * size_t is 64 bits
 * Either longs are 64-bits (doesn't happen on Windows)
 *   or pointers are 64-bits (doesn't happen on 32/64 arches)
 * FUTURE: validate this hack on more architectures.
 */
typedef uint32_t hword_t;
typedef uint64_t word_t;
typedef __uint128_t dword_t;
typedef int32_t hsword_t;
typedef int64_t sword_t;
typedef __int128_t dsword_t;
#define PRIxWORD PRIx64
#define PRIxWORDfull "%016" PRIx64
#define PRIxWORD58   "%014" PRIx64
#define U64LE(x) x##ull
#define U58LE(x) x##ull
#else
typedef uint16_t hword_t;
typedef uint32_t word_t;
typedef uint64_t dword_t;
typedef int16_t hsword_t;
typedef int32_t sword_t;
typedef int64_t dsword_t;
#define PRIxWORD PRIx32
#define PRIxWORDfull "%08" PRIx32
#define PRIxWORD58   "%07" PRIx32
#define U64LE(x) (x##ull)&((1ull<<32)-1), (x##ull)>>32
#define U58LE(x) (x##ull)&((1ull<<28)-1), (x##ull)>>28
#endif

#define WORD_BITS (sizeof(word_t) * 8)

/* TODO: vector width for procs like ARM; gcc support */
typedef word_t mask_t, vecmask_t __attribute__((ext_vector_type(4)));

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
typedef uint32x8_t uint32xn_t;
#elif __SSE2__ || __ARM_NEON__
typedef uint32x4_t big_register_t;
typedef uint64x2_t uint64xn_t;
typedef uint32x4_t uint32xn_t;
#elif _WIN64 || __amd64__ || __X86_64__ || __aarch64__
typedef uint64_t big_register_t, uint64xn_t;
typedef uint32_t uint32xn_t;
#else
typedef uint64_t uint64xn_t;
typedef uint32_t uint32xn_t;
typedef uint32_t big_register_t;
#endif


#if __AVX2__ || __SSE2__ || __ARM_NEON__
static __inline__ big_register_t
br_is_zero(big_register_t x) {
    return (big_register_t)(x == (big_register_t)0);
}
#else
static __inline__ mask_t
br_is_zero(word_t x) {
    return (((dword_t)x) - 1)>>WORD_BITS;
}
#endif



/**
 * Allocate memory which is sufficiently aligned to be used for the
 * largest vector on the system (for now that's a big_register_t).
 *
 * Man malloc says that it does this, but at least for AVX2 on MacOS X,
 * it's lying.
 *
 * @param size The size of the region to allocate.
 * @return A suitable pointer, which can be free'd with free(),
 * or NULL if no memory can be allocated.
 */
static __inline__ void *
malloc_vector (
    size_t size
) __attribute__((always_inline, unused));

void *
malloc_vector(size_t size) {
    void *out = NULL;
    
    int ret = posix_memalign(&out, sizeof(big_register_t), size);
    
    if (ret) {
        return NULL;
    } else {
        return out;
    }
}

#endif /* __WORD_H__ */
