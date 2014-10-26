/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "p521.h"

typedef uint64x4_t uint64x3_t; /* fit it in a vector register */
static const uint64x3_t mask58 = { (1ull<<58) - 1, (1ull<<58) - 1, (1ull<<58) - 1, 0 };

typedef struct {
  uint64x3_t lo, hi;
} hexad_t;

/* Currently requires CLANG.  Sorry. */
static inline uint64x3_t timesW (uint64x3_t u) {
  return u.zxyw + u.zwww;
}

/* Store three vectors.  Currently requries AVX2 (TODO: remove) */
static const uint64x4_t ls_mask_3 = { -1ull, -1ull, -1ull, 0 };
static void store3 (uint64_t *x, uint64x3_t v) {
  _mm256_maskstore_epi64((long long *) x, ls_mask_3, v);
}

static __inline__ uint64_t is_zero(uint64_t a) {
    /* let's hope the compiler isn't clever enough to optimize this. */
    return (((__uint128_t)a)-1)>>64;
}

static __inline__ __uint128_t widemul(
    const uint64_t a,
    const uint64_t b
) {
    return ((__uint128_t)a) * ((__uint128_t)b);
}

static inline __uint128_t widemulu(const uint64_t a, const uint64_t b) {
    return ((__uint128_t)(a)) * b;
}

static inline __int128_t widemuls(const int64_t a, const int64_t b) {
    return ((__int128_t)(a)) * b;
}
 
/* This is a trick to prevent terrible register allocation by hiding things from clang's optimizer */
static inline uint64_t opacify(uint64_t x) {
    __asm__ volatile("" : "+r"(x));
    return x;
}

static inline void hexad_mul (
  hexad_t *hex,
  const uint64_t *a,
  const uint64_t *b
) {
    __uint128_t xu, xv, xw;

    uint64_t tmp = opacify(a[2]);
    xw = widemulu(tmp, b[0]);
    tmp <<= 1;
    xu = widemulu(tmp, b[1]);
    xv = widemulu(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemulu(tmp, b[1]);
    xv += widemulu(tmp, b[0]);
    tmp <<= 1;
    xu += widemulu(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemulu(tmp, b[0]);
    xv += widemulu(tmp, b[1]);
    xw += widemulu(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hi = hi<<6 | lo>>58;
    lo &= mask58;

    hex->lo = lo;
    hex->hi = hi;
}

static inline void hexad_mul_signed (
  hexad_t *hex,
  const int64_t *a,
  const int64_t *b
) {
    __int128_t xu, xv, xw;

    int64_t tmp = opacify(a[2]);
    xw = widemuls(tmp, b[0]);
    tmp <<= 1;
    xu = widemuls(tmp, b[1]);
    xv = widemuls(tmp, b[2]);

    tmp = opacify(a[1]);
    xw += widemuls(tmp, b[1]);
    xv += widemuls(tmp, b[0]);
    tmp <<= 1;
    xu += widemuls(tmp, b[2]);

    tmp = opacify(a[0]);
    xu += widemuls(tmp, b[0]);
    xv += widemuls(tmp, b[1]);
    xw += widemuls(tmp, b[2]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hi = hi<<6 | lo>>58;
    lo &= mask58;

    hex->lo = lo;
    hex->hi = hi;
}

static inline void hexad_sqr (
  hexad_t *hex,
  const uint64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemulu(tmp, a[0]);
    xv = widemulu(tmp, a[2]);
    tmp <<= 1;
    xu = widemulu(tmp, a[1]);

    tmp = a[1];
    xw += widemulu(tmp, a[1]);
    tmp <<= 1;
    xv += widemulu(tmp, a[0]);

    tmp = a[0];
    xu += widemulu(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hi = hi<<6 | lo>>58;
    lo &= mask58;

    hex->lo = lo;
    hex->hi = hi;
}

static inline void hexad_sqr_signed (
  hexad_t *hex,
  const int64_t *a
) {
    __uint128_t xu, xv, xw;

    int64_t tmp = a[2];
    tmp <<= 1;
    xw = widemuls(tmp, a[0]);
    xv = widemuls(tmp, a[2]);
    tmp <<= 1;
    xu = widemuls(tmp, a[1]);

    tmp = a[1];
    xw += widemuls(tmp, a[1]);
    tmp <<= 1;
    xv += widemuls(tmp, a[0]);

    tmp = a[0];
    xu += widemuls(tmp, a[0]);

    uint64x3_t
    lo = { (uint64_t)(xu), (uint64_t)(xv), (uint64_t)(xw), 0 },
    hi = { (uint64_t)(xu>>64), (uint64_t)(xv>>64), (uint64_t)(xw>>64), 0 };

    hi = hi<<6 | lo>>58;
    lo &= mask58;

    hex->lo = lo;
    hex->hi = hi;
}



void
p521_mul (
    p521_t *__restrict__ cs,
    const p521_t *as,
    const p521_t *bs
) {
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb, *b = bs->limb;

  hexad_t ad, be, cf, abde, bcef, acdf;
  hexad_mul(&ad, &a[0], &b[0]);
  hexad_mul(&be, &a[3], &b[3]);
  hexad_mul(&cf, &a[6], &b[6]);
  
  uint64_t amt = 32;
  uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };

  uint64x3_t t0 = cf.lo + be.hi, t1 = ad.lo + timesW(cf.hi) + vhi, t2 = ad.hi + be.lo;

  int64_t ta[3], tb[3];
  // it seems to be faster not to vectorize these loops
  for (int i=0; i<3; i++) {
    ta[i] = a[i]-a[i+3];
    tb[i] = b[i]-b[i+3];
  }
  hexad_mul_signed(&abde,ta,tb);

  for (int i=0; i<3; i++) {
    ta[i] = a[i+3]-a[i+6];
    tb[i] = b[i+3]-b[i+6];
  }
  hexad_mul_signed(&bcef,ta,tb);

  for (int i=0; i<3; i++) {
    ta[i] = a[i]-a[i+6];
    tb[i] = b[i]-b[i+6];
  }
  hexad_mul_signed(&acdf,ta,tb);

  uint64x3_t ot0 = t1 + timesW(t0 + t2 - acdf.hi - bcef.lo);
  uint64x3_t ot1 = t1 + t2 - abde.lo + timesW(t0 - bcef.hi);
  uint64x3_t ot2 = t1 + t2 + t0 - abde.hi - acdf.lo + vhi2;
  
  uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
  uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
  uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);
  
  store3(&c[0], out0);
  store3(&c[3], out1);
  store3(&c[6], out2);
}


void
p521_sqr (
    p521_t *__restrict__ cs,
    const p521_t *as
) {
    uint64_t *c = cs->limb;
    const uint64_t *a = as->limb;

  hexad_t ad, be, cf, abde, bcef, acdf;
  hexad_sqr(&ad, &a[0]);
  hexad_sqr(&be, &a[3]);
  hexad_sqr(&cf, &a[6]);
  
  uint64_t amt = 32;
  uint64x3_t vhi = { amt*((1ull<<58)-1), amt*((1ull<<58)-1), amt*((1ull<<58)-1), 0 },
    vhi2 = { 0, 0, -amt<<57, 0 };

  uint64x3_t t0 = cf.lo + be.hi, t1 = ad.lo + timesW(cf.hi) + vhi, t2 = ad.hi + be.lo;

  int64_t ta[3];
  // it seems to be faster not to vectorize these loops
  for (int i=0; i<3; i++) {
    ta[i] = a[i]-a[i+3];
  }
  hexad_sqr_signed(&abde,ta);

  for (int i=0; i<3; i++) {
    ta[i] = a[i+3]-a[i+6];
  }
  hexad_sqr_signed(&bcef,ta);

  for (int i=0; i<3; i++) {
    ta[i] = a[i]-a[i+6];
  }
  hexad_sqr_signed(&acdf,ta);

  uint64x3_t ot0 = t1 + timesW(t0 + t2 - acdf.hi - bcef.lo);
  uint64x3_t ot1 = t1 + t2 - abde.lo + timesW(t0 - bcef.hi);
  uint64x3_t ot2 = t1 + t2 + t0 - abde.hi - acdf.lo + vhi2;
  
  uint64x3_t out0 = (ot0 & mask58) + timesW(ot2>>58);
  uint64x3_t out1 = (ot1 & mask58) + (ot0>>58);
  uint64x3_t out2 = (ot2 & mask58) + (ot1>>58);
  
  store3(&c[0], out0);
  store3(&c[3], out1);
  store3(&c[6], out2);
}

void
p521_mulw (
    p521_t *__restrict__ cs,
    const p521_t *as,
    uint64_t b
) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum3 = 0, accum6 = 0;
    uint64_t mask = (1ull<<58) - 1;  

    int i;
    for (i=0; i<3; i++) {
        accum0 += widemul(b, a[LIMBPERM(i)]);
        accum3 += widemul(b, a[LIMBPERM(i+3)]);
        accum6 += widemul(b, a[LIMBPERM(i+6)]);
        c[LIMBPERM(i)]   = accum0 & mask; accum0 >>= 58;
        c[LIMBPERM(i+3)] = accum3 & mask; accum3 >>= 58;
        if (i==2) { 
            c[LIMBPERM(i+6)] = accum6 & (mask>>1); accum6 >>= 57;
        } else {
            c[LIMBPERM(i+6)] = accum6 & mask; accum6 >>= 58;
        }
    }
    
    accum0 += c[LIMBPERM(3)];
    c[LIMBPERM(3)] = accum0 & mask;
    c[LIMBPERM(4)] += accum0 >> 58;

    accum3 += c[LIMBPERM(6)];
    c[LIMBPERM(6)] = accum3 & mask;
    c[LIMBPERM(7)] += accum3 >> 58;

    accum6 += c[LIMBPERM(0)];
    c[LIMBPERM(0)] = accum6 & mask;
    c[LIMBPERM(1)] += accum6 >> 58;
}


void
p521_strong_reduce (
    p521_t *a
) {
    uint64_t mask = (1ull<<58)-1, mask2 = (1ull<<57)-1;

    /* first, clear high */
    __int128_t scarry = a->limb[LIMBPERM(8)]>>57;
    a->limb[LIMBPERM(8)] &= mask2;

    /* now the total is less than 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    int i;
    for (i=0; i<9; i++) {
        scarry = scarry + a->limb[LIMBPERM(i)] - ((i==8) ? mask2 : mask);
        a->limb[LIMBPERM(i)] = scarry & ((i==8) ? mask2 : mask);
        scarry >>= (i==8) ? 57 : 58;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^521
    * so let's add back in p.  will carry back off the top for 2^521.
    */

    assert(is_zero(scarry) | is_zero(scarry+1));

    uint64_t scarry_mask = scarry & mask;
    __uint128_t carry = 0;

    /* add it back */
    for (i=0; i<9; i++) {
        carry = carry + a->limb[LIMBPERM(i)] + ((i==8)?(scarry_mask>>1):scarry_mask);
        a->limb[LIMBPERM(i)] = carry & ((i==8) ? mask>>1 : mask);
        carry >>= (i==8) ? 57 : 58;
    }

    assert(is_zero(carry + scarry));
}

mask_t
p521_is_zero (
    const struct p521_t *a
) {
    struct p521_t b;
    p521_copy(&b,a);
    p521_strong_reduce(&b);

    uint64_t any = 0;
    int i;
    for (i=0; i<9; i++) {
        any |= b.limb[i];
    }
    return is_zero(any);
}

void
p521_serialize (
    uint8_t *serial,
    const struct p521_t *x
) {
    int i,k=0;
    p521_t red;
    p521_copy(&red, x);
    p521_strong_reduce(&red);
    
    uint64_t r=0;
    int bits = 0;
    for (i=0; i<9; i++) {
        r |= red.limb[LIMBPERM(i)] << bits;
        for (bits += 58; bits >= 8; bits -= 8) {
            serial[k++] = r;
            r >>= 8;
        }
        assert(bits <= 6);
    }
    assert(bits);
    serial[k++] = r;
}

mask_t
p521_deserialize (
    p521_t *x,
    const uint8_t serial[LIMBPERM(66)]
) {
    int i,k=0,bits=0;
    __uint128_t out = 0;
    uint64_t mask = (1ull<<58)-1;
    for (i=0; i<9; i++) {
        out >>= 58;
        for (; bits<58; bits+=8) {
            out |= ((__uint128_t)serial[k++])<<bits;
        }
        x->limb[LIMBPERM(i)] = out & mask;
        bits -= 58;
    }
    
    /* Check for reduction.  First, high has to be < 2^57 */
    mask_t good = is_zero(out>>57);
    
    uint64_t and = -1ull;
    for (i=0; i<8; i++) {
        and &= x->limb[i];
    }
    and &= (2*out+1);
    good &= is_zero((and+1)>>58);
    
    return good;
}
