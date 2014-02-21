/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __X86_64_ARITH_H__
#define __X86_64_ARITH_H__

#include <stdint.h>

/* TODO: non x86-64 versions of these.
 * TODO: autogenerate
 */

static __inline__ __uint128_t widemul(const uint64_t *a, const uint64_t *b) {
  #ifndef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rax;"
       "mulq %[b];"
       : [c]"=a"(c), [d]"=d"(d)
       : [b]"m"(*b), [a]"m"(*a)
       : "cc");
  return (((__uint128_t)(d))<<64) | c;
  #else
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx;"
       "mulx %[b], %[c], %[d];"
       : [c]"=r"(c), [d]"=r"(d)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx");
  return (((__uint128_t)(d))<<64) | c;
  #endif
}

static __inline__ __uint128_t widemul_rm(uint64_t a, const uint64_t *b) {
  #ifndef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rax;"
       "mulq %[b];"
       : [c]"=a"(c), [d]"=d"(d)
       : [b]"m"(*b), [a]"r"(a)
       : "cc");
  return (((__uint128_t)(d))<<64) | c;
  #else
  uint64_t c,d;
  __asm__ volatile
      ("mulx %[b], %[c], %[d];"
       : [c]"=r"(c), [d]"=r"(d)
       : [b]"m"(*b), [a]"d"(a));
  return (((__uint128_t)(d))<<64) | c;
  #endif
}

static __inline__ __uint128_t widemul2(const uint64_t *a, const uint64_t *b) {
  #ifndef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rax; "
       "addq %%rax, %%rax; "
       "mulq %[b];"
       : [c]"=a"(c), [d]"=d"(d)
       : [b]"m"(*b), [a]"m"(*a)
       : "cc");
  return (((__uint128_t)(d))<<64) | c;
  #else
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx;"
       "leaq (,%%rdx,2), %%rdx;"
       "mulx %[b], %[c], %[d];"
       : [c]"=r"(c), [d]"=r"(d)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx");
  return (((__uint128_t)(d))<<64) | c;
  #endif
}

static __inline__ void mac(__uint128_t *acc, const uint64_t *a, const uint64_t *b) {
  uint64_t lo = *acc, hi = *acc>>64;
  
  #ifdef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx; "
       "mulx %[b], %[c], %[d]; "
       "addq %[c], %[lo]; "
       "adcq %[d], %[hi]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx", "cc");
  #else
  __asm__ volatile
      ("movq %[a], %%rax; "
       "mulq %[b]; "
       "addq %%rax, %[lo]; "
       "adcq %%rdx, %[hi]; "
       : [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rax", "rdx", "cc");
  #endif
  
  *acc = (((__uint128_t)(hi))<<64) | lo;
}

static __inline__ void mac_rm(__uint128_t *acc, uint64_t a, const uint64_t *b) {
  uint64_t lo = *acc, hi = *acc>>64;
  
  #ifdef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("mulx %[b], %[c], %[d]; "
       "addq %[c], %[lo]; "
       "adcq %[d], %[hi]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"d"(a)
       : "cc");
  #else
  __asm__ volatile
      ("movq %[a], %%rax; "
       "mulq %[b]; "
       "addq %%rax, %[lo]; "
       "adcq %%rdx, %[hi]; "
       : [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"r"(a)
       : "rax", "rdx", "cc");
  #endif
  
  *acc = (((__uint128_t)(hi))<<64) | lo;
}

static __inline__ void mac2(__uint128_t *acc, const uint64_t *a, const uint64_t *b) {
  uint64_t lo = *acc, hi = *acc>>64;
  
  #ifdef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx; "
       "addq %%rdx, %%rdx; "
       "mulx %[b], %[c], %[d]; "
       "addq %[c], %[lo]; "
       "adcq %[d], %[hi]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx", "cc");
  #else
  __asm__ volatile
      ("movq %[a], %%rax; "
       "addq %%rax, %%rax; "
       "mulq %[b]; "
       "addq %%rax, %[lo]; "
       "adcq %%rdx, %[hi]; "
       : [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rax", "rdx", "cc");
  #endif
  
  *acc = (((__uint128_t)(hi))<<64) | lo;
}

static __inline__ void msb(__uint128_t *acc, const uint64_t *a, const uint64_t *b) {
  uint64_t lo = *acc, hi = *acc>>64;
  #ifdef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx; "
       "mulx %[b], %[c], %[d]; "
       "subq %[c], %[lo]; "
       "sbbq %[d], %[hi]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx", "cc");
  #else
  __asm__ volatile
      ("movq %[a], %%rax; "
       "mulq %[b]; "
       "subq %%rax, %[lo]; "
       "sbbq %%rdx, %[hi]; "
       : [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rax", "rdx", "cc");
  #endif
  *acc = (((__uint128_t)(hi))<<64) | lo;
}

static __inline__ void msb2(__uint128_t *acc, const uint64_t *a, const uint64_t *b) {
  uint64_t lo = *acc, hi = *acc>>64;
  #ifdef __BMI2__
  uint64_t c,d;
  __asm__ volatile
      ("movq %[a], %%rdx; "
       "addq %%rdx, %%rdx; "
       "mulx %[b], %[c], %[d]; "
       "subq %[c], %[lo]; "
       "sbbq %[d], %[hi]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx", "cc");
  #else
  __asm__ volatile
      ("movq %[a], %%rax; "
       "addq %%rax, %%rax; "
       "mulq %[b]; "
       "subq %%rax, %[lo]; "
       "sbbq %%rdx, %[hi]; "
       : [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rax", "rdx", "cc");
  #endif
  *acc = (((__uint128_t)(hi))<<64) | lo;
  
}

static __inline__ void mrs(__uint128_t *acc, const uint64_t *a, const uint64_t *b) {
  uint64_t c,d, lo = *acc, hi = *acc>>64;
  __asm__ volatile
      ("movq %[a], %%rdx; "
       "mulx %[b], %[c], %[d]; "
       "subq %[lo], %[c]; "
       "sbbq %[hi], %[d]; "
       : [c]"=r"(c), [d]"=r"(d), [lo]"+r"(lo), [hi]"+r"(hi)
       : [b]"m"(*b), [a]"m"(*a)
       : "rdx", "cc");
  *acc = (((__uint128_t)(d))<<64) | c;
}

static __inline__ __uint128_t widemulu(uint64_t a, uint64_t b) {
  return ((__uint128_t)(a)) * b;
}

static __inline__ __int128_t widemuls(int64_t a, int64_t b) {
  return ((__int128_t)(a)) * b;
}
 
static __inline__ uint64_t opacify(uint64_t x) {
  __asm__ volatile("" : "+r"(x));
  return x;
}

static __inline__ mask_t is_zero(uint64_t x) {
  __asm__ volatile("neg %0; sbb %0, %0;" : "+r"(x));
  return ~x;
}

#endif /* __X86_64_ARITH_H__ */
