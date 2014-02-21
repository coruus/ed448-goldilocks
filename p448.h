/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P448_H__
#define __P448_H__ 1

#include <stdint.h>
#include <assert.h>

#include "word.h"

typedef struct p448_t {
  uint64_t limb[8];
} __attribute__((aligned(32))) p448_t;

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p448_set_ui(p448_t *out,
            uint64_t x)
    __attribute__((unused,always_inline));
           
static __inline__ void
p448_cond_swap(p448_t *a,
               p448_t *b,
               mask_t do_swap)
    __attribute__((unused,always_inline));

static __inline__ void
p448_add(p448_t *out,
         const p448_t *a,
         const p448_t *b)
    __attribute__((unused,always_inline));
             
static __inline__ void
p448_sub(p448_t *out,
         const p448_t *a,
         const p448_t *b)
    __attribute__((unused,always_inline));
             
static __inline__ void
p448_neg(p448_t *out,
         const p448_t *a)
    __attribute__((unused,always_inline));
            
static __inline__ void
p448_cond_neg(p448_t *a,
              mask_t doNegate)
   __attribute__((unused,always_inline));

static __inline__ void
p448_addw(p448_t *a,
          uint64_t x)
    __attribute__((unused,always_inline));
             
static __inline__ void
p448_subw(p448_t *a,
          uint64_t x)
    __attribute__((unused,always_inline));
             
static __inline__ void
p448_copy(p448_t *out, const p448_t *a)
    __attribute__((unused,always_inline));
             
static __inline__ void
p448_weak_reduce(p448_t *inout)
    __attribute__((unused,always_inline));
             
void
p448_strong_reduce(p448_t *inout);

mask_t
p448_is_zero(const p448_t *in);
             
static __inline__ void
p448_bias(p448_t *inout, int amount)
    __attribute__((unused,always_inline));
         
void
p448_mul(p448_t *__restrict__ out,
         const p448_t *a,
         const p448_t *b);

void
p448_mulw(p448_t *__restrict__ out,
          const p448_t *a,
          uint64_t b);

void
p448_sqr(p448_t *__restrict__ out,
         const p448_t *a);
         
static __inline__ void
p448_sqrn(p448_t *__restrict__ y, const p448_t *x, int n)
    __attribute__((unused,always_inline));

void
p448_set_ui(p448_t *out,
            uint64_t x) {
    int i;
    out->limb[0] = x;
    for (i=1; i<8; i++) {
      out->limb[i] = 0;
    }
}
            
void
p448_cond_swap(p448_t *a, p448_t *b, mask_t doswap) {
  big_register_t *aa = (big_register_t*)a;
  big_register_t *bb = (big_register_t*)b;
  big_register_t m = doswap;
  
  unsigned int i;
  for (i=0; i<sizeof(*a)/sizeof(*aa); i++) {
      big_register_t x = m & (aa[i]^bb[i]);
      aa[i] ^= x;
      bb[i] ^= x;
  }
}

void
p448_add(p448_t *out, const p448_t *a, const p448_t *b) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    */
}

void
p448_sub(p448_t *out, const p448_t *a, const p448_t *b) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = ((const uint64xn_t*)a)[i] - ((const uint64xn_t*)b)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = a->limb[i] - b->limb[i];
    }
    */
}

void
p448_neg(p448_t *out, const p448_t *a) {
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)out)[i] = -((const uint64xn_t*)a)[i];
    }
    /*
    unsigned int i;
    for (i=0; i<sizeof(*out)/sizeof(out->limb[0]); i++) {
        out->limb[i] = -a->limb[i];
    }
    */
}

void
p448_cond_neg(
    p448_t *a,
    mask_t doNegate
) {
    unsigned int i;
    struct p448_t negated;
    big_register_t *aa = (big_register_t *)a;
    big_register_t *nn = (big_register_t*)&negated;
    big_register_t m = doNegate;
    
    p448_neg(&negated, a);
    p448_bias(&negated, 2);
    
    for (i=0; i<sizeof(*a)/sizeof(*aa); i++) {
        aa[i] = (aa[i] & ~m) | (nn[i] & m);
    }
}

void
p448_addw(p448_t *a, uint64_t x) {
  a->limb[0] += x;
}
             
void
p448_subw(p448_t *a, uint64_t x) {
  a->limb[0] -= x;
}

void
p448_copy(p448_t *out, const p448_t *a) {
  *out = *a;
}

void
p448_bias(p448_t *a, int amt) {
    uint64_t co1 = ((1ull<<56)-1)*amt, co2 = co1-amt;
    uint64x4_t lo = {co1,co1,co1,co1}, hi = {co2,co1,co1,co1};
    uint64x4_t *aa = (uint64x4_t*) a;
    aa[0] += lo;
    aa[1] += hi;
}

void
p448_weak_reduce(p448_t *a) {
    /* TODO: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull<<56) - 1;
    uint64_t tmp = a->limb[7] >> 56;
    int i;
    a->limb[4] += tmp;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}

void p448_sqrn(p448_t *__restrict__ y, const p448_t *x, int n) {
    p448_t tmp;
    assert(n>0);
    if (n&1) {
        p448_sqr(y,x);
        n--;
    } else {
        p448_sqr(&tmp,x);
        p448_sqr(y,&tmp);
        n-=2;
    }
    for (; n; n-=2) {
        p448_sqr(&tmp,y);
        p448_sqr(y,&tmp);
    }
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P448_H__ */
