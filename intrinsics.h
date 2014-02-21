/* Copyright (c) 2011 Stanford University.
 * Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/* cRandom intrinsics header. */

#ifndef __CRANDOM_INTRINSICS_H__
#define __CRANDOM_INTRINSICS_H__ 1

#include <sys/types.h>

#include <immintrin.h>

#define INTRINSIC \
  static __inline__ __attribute__((__gnu_inline__, __always_inline__))

#define GEN    1
#define SSE2   2
#define SSSE3  4
#define AESNI  8
#define XOP    16
#define AVX    32
#define AVX2   64

INTRINSIC u_int64_t rdtsc() {
  u_int64_t out = 0;
# if (defined(__i386__) || defined(__x86_64__))
    __asm__ __volatile__ ("rdtsc" : "=A"(out));
# endif
  return out;
}

INTRINSIC u_int64_t opacify(u_int64_t x) {
  __asm__ volatile("mov %0, %0" : "+r"(x));
  return x;
}

#ifdef __AVX2__
#  define MIGHT_HAVE_AVX2 1
#  ifndef MUST_HAVE_AVX2
#    define MUST_HAVE_AVX2 0
#  endif
#else
#  define MIGHT_HAVE_AVX2 0
#  define MUST_HAVE_AVX2  0
#endif

#ifdef __AVX__
#  define MIGHT_HAVE_AVX 1
#  ifndef MUST_HAVE_AVX
#    define MUST_HAVE_AVX MUST_HAVE_AVX2
#  endif
#else
#  define MIGHT_HAVE_AVX 0
#  define MUST_HAVE_AVX  0
#endif

#ifdef __SSSE3__
#  define MIGHT_HAVE_SSSE3 1
#  ifndef MUST_HAVE_SSSE3
#    define MUST_HAVE_SSSE3 MUST_HAVE_AVX
#  endif
#else
#  define MIGHT_HAVE_SSSE3 0
#  define MUST_HAVE_SSSE3 0
#endif

#ifdef __SSE2__
#  define MIGHT_HAVE_SSE2 1
#  ifndef MUST_HAVE_SSE2
#    define MUST_HAVE_SSE2 MUST_HAVE_SSSE3
#  endif
   typedef __m128i ssereg;
#  define pslldq _mm_slli_epi32
#  define pshufd _mm_shuffle_epi32

INTRINSIC ssereg sse2_rotate(int r, ssereg a) {
  return _mm_slli_epi32(a, r) ^ _mm_srli_epi32(a, 32-r);
}

#else
#  define MIGHT_HAVE_SSE2 0
#  define MUST_HAVE_SSE2  0
#endif

#ifdef __AES__
/* don't include intrinsics file, because not all platforms have it */
#  define MIGHT_HAVE_AESNI 1
#  ifndef MUST_HAVE_AESNI
#    define MUST_HAVE_AESNI 0
#  endif

INTRINSIC ssereg aeskeygenassist(int rc, ssereg x) {
  ssereg out;
  __asm__("aeskeygenassist %2, %1, %0" : "=x"(out) : "x"(x), "g"(rc));
  return out;
}

INTRINSIC ssereg aesenc(ssereg subkey, ssereg block) {
  ssereg out = block;
  __asm__("aesenc %1, %0" : "+x"(out) : "x"(subkey));
  return out;
}

INTRINSIC ssereg aesenclast(ssereg subkey, ssereg block) {
  ssereg out = block;
  __asm__("aesenclast %1, %0" : "+x"(out) : "x"(subkey));
  return out;
}

#else
#  define MIGHT_HAVE_AESNI 0
#  define MUST_HAVE_AESNI 0
#endif

#ifdef __XOP__
/* don't include intrinsics file, because not all platforms have it */
#  define MIGHT_HAVE_XOP 1
#  ifndef MUST_HAVE_XOP
#    define MUST_HAVE_XOP 0
#  endif
INTRINSIC ssereg xop_rotate(int amount, ssereg x) {
  ssereg out;
  __asm__ ("vprotd %1, %2, %0" : "=x"(out) : "x"(x), "g"(amount));
  return out;
}
#else
#  define MIGHT_HAVE_XOP 0
#  define MUST_HAVE_XOP 0
#endif

#define MIGHT_MASK \
  ( SSE2  * MIGHT_HAVE_SSE2   \
  | SSSE3 * MIGHT_HAVE_SSSE3  \
  | AESNI * MIGHT_HAVE_AESNI  \
  | XOP   * MIGHT_HAVE_XOP    \
  | AVX   * MIGHT_HAVE_AVX    \
  | AVX2  * MIGHT_HAVE_AVX2)

#define MUST_MASK \
  ( SSE2  * MUST_HAVE_SSE2   \
  | SSSE3 * MUST_HAVE_SSSE3  \
  | AESNI * MUST_HAVE_AESNI  \
  | XOP   * MUST_HAVE_XOP    \
  | AVX   * MUST_HAVE_AVX    \
  | AVX2  * MUST_HAVE_AVX2 )

#define MIGHT_HAVE(feature) ((MIGHT_MASK & feature) == feature)
#define MUST_HAVE(feature) ((MUST_MASK & feature) == feature)

#ifdef __cplusplus
#  define extern_c extern "C"
#else
#  define extern_c
#endif

extern_c
unsigned int crandom_detect_features();

#ifndef likely
#  define likely(x)       __builtin_expect((x),1)
#  define unlikely(x)     __builtin_expect((x),0)
#endif

extern volatile unsigned int crandom_features;
INTRINSIC int HAVE(unsigned int feature) {
  unsigned int features;
  if (!MIGHT_HAVE(feature)) return 0;
  if (MUST_HAVE(feature))   return 1;
  features = crandom_features;
  if (unlikely(!features))
    crandom_features = features = crandom_detect_features();
  return likely((features & feature) == feature);
}

#endif /* __CRANDOM_INTRINSICS_H__ */
