/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.c
 * @author Mike Hamburg
 * @brief Decaf high-level functions.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include "decaf.h"
#include <string.h>
#include <assert.h>

#define WBITS DECAF_WORD_BITS

#if WBITS == 64
#define LBITS 56
typedef __int128_t decaf_sdword_t;
#define LIMB(x) (x##ull)
#define SC_LIMB(x) (x##ull)
#elif WBITS == 32
typedef int64_t decaf_sdword_t;
#define LBITS 28
#define LIMB(x) (x##ull)&((1ull<<LBITS)-1), (x##ull)>>LBITS
#define SC_LIMB(x) (x##ull)&((1ull<<32)-1), (x##ull)>>32
#else
#error "Only supporting 32- and 64-bit platforms right now"
#endif

#define sv static void
#define snv static void __attribute__((noinline))
#define siv static inline void __attribute__((always_inline))
static const gf ZERO = {{{0}}}, ONE = {{{1}}}, TWO = {{{2}}};

#define LMASK ((((decaf_word_t)1)<<LBITS)-1)
#if WBITS == 64
static const gf P = {{{ LMASK, LMASK, LMASK, LMASK, LMASK-1, LMASK, LMASK, LMASK }}};
#else
static const gf P = {{{ LMASK,   LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK,
		      LMASK-1, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK }}};
#endif
static const int EDWARDS_D = -39081;

const decaf_448_scalar_t decaf_448_scalar_p = {{{
    SC_LIMB(0x2378c292ab5844f3),
    SC_LIMB(0x216cc2728dc58f55),
    SC_LIMB(0xc44edb49aed63690),
    SC_LIMB(0xffffffff7cca23e9),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0x3fffffffffffffff)
}}}, decaf_448_scalar_one = {{{1}}}, decaf_448_scalar_zero = {{{0}}};

static const decaf_448_scalar_t decaf_448_scalar_r2 = {{{
    SC_LIMB(0xe3539257049b9b60),
    SC_LIMB(0x7af32c4bc1b195d9),
    SC_LIMB(0x0d66de2388ea1859),
    SC_LIMB(0xae17cf725ee4d838),
    SC_LIMB(0x1a9cc14ba3c47c44),
    SC_LIMB(0x2052bcb7e4d070af),
    SC_LIMB(0x3402a939f823b729)
}}};

static const decaf_word_t DECAF_MONTGOMERY_FACTOR = (decaf_word_t)(0x3bd440fae918bc5ull);

#define FIELD_LITERAL(a,b,c,d,e,f,g,h) {{LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e),LIMB(f),LIMB(g),LIMB(h)}}

const decaf_448_point_t decaf_448_point_base = {{
    {FIELD_LITERAL(0x00fffffffffffffe,0x00ffffffffffffff,0x00ffffffffffffff,0x00ffffffffffffff,
                   0x0000000000000003,0x0000000000000000,0x0000000000000000,0x0000000000000000)},
    {FIELD_LITERAL(0x0081e6d37f752992,0x003078ead1c28721,0x00135cfd2394666c,0x0041149c50506061,
                   0x0031d30e4f5490b3,0x00902014990dc141,0x0052341b04c1e328,0x0014237853c10a1b)},
    {FIELD_LITERAL(0x00fffffffffffffb,0x00ffffffffffffff,0x00ffffffffffffff,0x00ffffffffffffff,
                   0x00fffffffffffffe,0x00ffffffffffffff,0x00ffffffffffffff,0x00ffffffffffffff)},
    {FIELD_LITERAL(0x008f205b70660415,0x00881c60cfd3824f,0x00377a638d08500d,0x008c66d5d4672615,
                   0x00e52fa558e08e13,0x0087770ae1b6983d,0x004388f55a0aa7ff,0x00b4d9a785cf1a91)}
}};


struct decaf_448_precomputed_s { decaf_448_point_t p[1]; };

/* FIXME: restore */
const struct decaf_448_precomputed_s *decaf_448_precomputed_base =
    (const struct decaf_448_precomputed_s *)decaf_448_point_base;

const size_t sizeof_decaf_448_precomputed_s = sizeof(struct decaf_448_precomputed_s);
const size_t alignof_decaf_448_precomputed_s = 32;

#ifdef __clang__
#if 100*__clang_major__ + __clang_minor__ > 305
#define VECTORIZE _Pragma("clang loop unroll(disable) vectorize(enable) vectorize_width(8)")
#endif
#endif

#ifndef VECTORIZE
#define VECTORIZE
#endif

#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)) || defined(DECAF_FORCE_UNROLL)
    #if DECAF_448_LIMBS==8
    #define FOR_LIMB_U(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #elif DECAF_448_LIMBS==16
    #define FOR_LIMB_U(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #else
    #define FOR_LIMB_U(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}
    #endif
#else
#define FOR_LIMB_U(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}
#endif
    

#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}

/* TODO: figure out why this horribly degrades speed if you use it */
#define FOR_LIMB_V(i,op) { unsigned int i=0; VECTORIZE for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}

/** Copy x = y */
siv gf_cpy(gf x, const gf y) { FOR_LIMB_U(i, x->limb[i] = y->limb[i]); }

/** Mostly-unoptimized multiply (PERF), but at least it's unrolled. */
snv gf_mul (gf c, const gf a, const gf b) {
    gf aa;
    gf_cpy(aa,a);
    
    decaf_dword_t accum[DECAF_448_LIMBS] = {0};
    FOR_LIMB_U(i, {
        FOR_LIMB_U(j,{ accum[(i+j)%DECAF_448_LIMBS] += (decaf_dword_t)b->limb[i] * aa->limb[j]; });
        aa->limb[(DECAF_448_LIMBS-1-i)^(DECAF_448_LIMBS/2)] += aa->limb[DECAF_448_LIMBS-1-i];
    });
    
    accum[DECAF_448_LIMBS-1] += accum[DECAF_448_LIMBS-2] >> LBITS;
    accum[DECAF_448_LIMBS-2] &= LMASK;
    accum[DECAF_448_LIMBS/2] += accum[DECAF_448_LIMBS-1] >> LBITS;
    FOR_LIMB_U(j,{
        accum[j] += accum[(j-1)%DECAF_448_LIMBS] >> LBITS;
        accum[(j-1)%DECAF_448_LIMBS] &= LMASK;
    });
    FOR_LIMB_U(j, c->limb[j] = accum[j] );
}

/** No dedicated square (PERF) */
#define gf_sqr(c,a) gf_mul(c,a,a)

/** Inverse square root using addition chain. */
snv gf_isqrt(gf y, const gf x) {
    int i;
#define STEP(s,m,n) gf_mul(s,m,c); gf_cpy(c,s); for (i=0;i<n;i++) gf_sqr(c,c);
    gf a, b, c;
    gf_sqr ( c,   x );
    STEP(b,x,1);
    STEP(b,x,3);
    STEP(a,b,3);
    STEP(a,b,9);
    STEP(b,a,1);
    STEP(a,x,18);
    STEP(a,b,37);
    STEP(b,a,37);
    STEP(b,a,111);
    STEP(a,b,1);
    STEP(b,x,223);
    gf_mul(y,a,c);
}

/** Weak reduce mod p. */
siv gf_reduce(gf x) {
    x->limb[DECAF_448_LIMBS/2] += x->limb[DECAF_448_LIMBS-1] >> LBITS;
    FOR_LIMB_U(j,{
        x->limb[j] += x->limb[(j-1)%DECAF_448_LIMBS] >> LBITS;
        x->limb[(j-1)%DECAF_448_LIMBS] &= LMASK;
    });
}

/** Add mod p.  Conservatively always weak-reduce. (PERF) */
sv gf_add ( gf x, const gf y, const gf z ) {
    FOR_LIMB_U(i, x->limb[i] = y->limb[i] + z->limb[i] );
    gf_reduce(x);
}

/** Subtract mod p.  Conservatively always weak-reduce. (PERF) */
sv gf_sub ( gf x, const gf y, const gf z ) {
    FOR_LIMB_U(i, x->limb[i] = y->limb[i] - z->limb[i] + 2*P->limb[i] );
    gf_reduce(x);
}

/** Constant time, x = is_z ? z : y */
sv cond_sel(gf x, const gf y, const gf z, decaf_bool_t is_z) {
    FOR_LIMB_U(i, x->limb[i] = (y->limb[i] & ~is_z) | (z->limb[i] & is_z) );
}

/** Constant time, if (neg) x=-x; */
siv cond_neg(gf x, decaf_bool_t neg) {
    gf y;
    gf_sub(y,ZERO,x);
    cond_sel(x,x,y,neg);
}

/** Constant time, if (swap) (x,y) = (y,x); */
sv cond_swap(gf x, gf_s *__restrict__ y, decaf_bool_t swap) {
    FOR_LIMB_U(i, {
        decaf_word_t s = (x->limb[i] ^ y->limb[i]) & swap;
        x->limb[i] ^= s;
        y->limb[i] ^= s;
    });
}

/**
 * Mul by signed int.  Not constant-time WRT the sign of that int.
 * Just uses a full mul (PERF)
 */
siv gf_mlw(gf a, const gf b, int w) {
    if (w>0) {
        gf ww = {{{w}}};
        gf_mul(a,b,ww);
    } else {
        gf ww = {{{-w}}};
        gf_mul(a,b,ww);
        gf_sub(a,ZERO,a);
    }
}

/** Canonicalize */
snv gf_canon ( gf a ) {
    gf_reduce(a);

    /* subtract p with borrow */
    decaf_sdword_t carry = 0;
    FOR_LIMB(i, {
        carry = carry + a->limb[i] - P->limb[i];
        a->limb[i] = carry & LMASK;
        carry >>= LBITS;
    });
    
    decaf_bool_t addback = carry;
    carry = 0;

    /* add it back */
    FOR_LIMB(i, {
        carry = carry + a->limb[i] + (P->limb[i] & addback);
        a->limb[i] = carry & LMASK;
        carry >>= LBITS;
    });
}

/** Compare a==b */
static decaf_word_t __attribute__((noinline)) gf_eq(const gf a, const gf b) {
    gf c;
    gf_sub(c,a,b);
    gf_canon(c);
    decaf_word_t ret=0;
    FOR_LIMB(i, ret |= c->limb[i] );
    /* Hope the compiler is too dumb to optimize this, thus noinline */
    return ((decaf_dword_t)ret - 1) >> WBITS;
}

/** Return high bit of x = low bit of 2x mod p */
static decaf_word_t hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_canon(y);
    return -(y->limb[0]&1);
}

/* a = use_c ? c : b */
sv decaf_448_cond_sel (
    decaf_448_point_t a,
    const decaf_448_point_t b,
    const decaf_448_point_t c,
    decaf_bool_t use_c
) {
    cond_sel(a->x, b->x, c->x, use_c);
    cond_sel(a->y, b->y, c->y, use_c);
    cond_sel(a->z, b->z, c->z, use_c);
    cond_sel(a->t, b->t, c->t, use_c);
}

/** {extra,accum} - sub +? p
 * Must have extra <= 1
 */
snv decaf_448_subx(
    decaf_448_scalar_t out,
    const decaf_word_t accum[DECAF_448_SCALAR_LIMBS],
    const decaf_448_scalar_t sub,
    const decaf_448_scalar_t p,
    decaf_word_t extra
) {
    decaf_sdword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + accum[i]) - sub->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_bool_t borrow = chain+extra; /* = 0 or -1 */
    
    chain = 0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
}

snv decaf_448_montmul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    unsigned int i,j;
    decaf_word_t accum[DECAF_448_SCALAR_LIMBS+1] = {0};
    decaf_word_t hi_carry = 0;
    
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        decaf_word_t mand = a->limb[i];
        const decaf_word_t *mier = b->limb;
        
        decaf_dword_t chain = 0;
        for (j=0; j<DECAF_448_SCALAR_LIMBS; j++) {
            chain += ((decaf_dword_t)mand)*mier[j] + accum[j];
            accum[j] = chain;
            chain >>= WBITS;
        }
        accum[j] = chain;
        
        mand = accum[0] * DECAF_MONTGOMERY_FACTOR;
        chain = 0;
        mier = decaf_448_scalar_p->limb;
        for (j=0; j<DECAF_448_SCALAR_LIMBS; j++) {
            chain += (decaf_dword_t)mand*mier[j] + accum[j];
            if (j) accum[j-1] = chain;
            chain >>= WBITS;
        }
        chain += accum[j];
        chain += hi_carry;
        accum[j-1] = chain;
        hi_carry = chain >> WBITS;
    }
    
    decaf_448_subx(out, accum, decaf_448_scalar_p, decaf_448_scalar_p, hi_carry);
}

void decaf_448_scalar_mul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    decaf_448_montmul(out,a,b);
    decaf_448_montmul(out,out,decaf_448_scalar_r2);
}

decaf_bool_t decaf_448_scalar_invert (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    decaf_448_scalar_t b, ma;
    int i;
    decaf_448_montmul(b,decaf_448_scalar_one,decaf_448_scalar_r2);
    decaf_448_montmul(ma,a,decaf_448_scalar_r2);
    for (i=DECAF_448_SCALAR_BITS-1; i>=0; i--) {
        decaf_448_montmul(b,b,b);
            
        decaf_word_t w = decaf_448_scalar_p->limb[i/WBITS];
        if (i<WBITS) {
            assert(w >= 2);
            w-=2;
        }
        if (1 & w>>(i%WBITS)) {
            decaf_448_montmul(b,b,ma);
        }
    }

    decaf_448_montmul(out,b,decaf_448_scalar_one);
    decaf_448_scalar_destroy(b);
    decaf_448_scalar_destroy(ma);
    return ~decaf_448_scalar_eq(out,decaf_448_scalar_zero);
}

void decaf_448_scalar_sub (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    decaf_448_subx(out, a->limb, b, decaf_448_scalar_p, 0);
}

void decaf_448_scalar_add (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + b->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_448_subx(out, out->limb, decaf_448_scalar_p, decaf_448_scalar_p, chain);
}

void decaf_448_scalar_set (
    decaf_448_scalar_t out,
    decaf_word_t w
) {
    memset(out,0,sizeof(decaf_448_scalar_t));
    out->limb[0] = w;
}

decaf_bool_t decaf_448_scalar_eq (
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    int i;
    decaf_word_t diff = 0;
    for(i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        diff |= a->limb[i] ^ b->limb[i];
    }
    return (((decaf_dword_t)diff)-1)>>WBITS;
}

/* *** API begins here *** */    

/** identity = (0,1) */
const decaf_448_point_t decaf_448_point_identity = {{{{{0}}},{{{1}}},{{{1}}},{{{0}}}}};

void decaf_448_point_encode( unsigned char ser[DECAF_448_SER_BYTES], const decaf_448_point_t p ) {
    /* Can shave off one mul here; not important but makes consistent with paper */
    gf a, b, c, d;
    gf_mlw ( a, p->y, 1-EDWARDS_D ); 
    gf_mul ( c, a, p->t ); 
    gf_mul ( a, p->x, p->z ); 
    gf_sub ( d, c, a ); 
    gf_add ( a, p->z, p->y ); 
    gf_sub ( b, p->z, p->y ); 
    gf_mul ( c, b, a );
    gf_mlw ( b, c, -EDWARDS_D );
    gf_isqrt ( a, b );
    gf_mlw ( b, a, -EDWARDS_D ); 
    gf_mul ( c, b, a );
    gf_mul ( a, c, d );
    gf_add ( d, b, b );  
    gf_mul ( c, d, p->z );   
    cond_neg ( b, ~hibit(c) ); 
    gf_mul ( c, b, p->y ); 
    gf_add ( a, a, c );
    cond_neg ( a, hibit(a) );
    
    gf_canon(a);
    int k=0, bits=0;
    decaf_dword_t buf=0;
    FOR_LIMB(i, {
        buf |= (decaf_dword_t)a->limb[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==DECAF_448_LIMBS-1) && k<DECAF_448_SER_BYTES; bits-=8, buf>>=8) {
            ser[k++]=buf;
        }
    });
}

/**
 * Deserialize a bool, return TRUE if < p.
 */
static decaf_bool_t gf_deser(gf s, const unsigned char ser[DECAF_448_SER_BYTES]) {
    unsigned int i, k=0, bits=0;
    decaf_dword_t buf=0;
    for (i=0; i<DECAF_448_SER_BYTES; i++) {
        buf |= (decaf_dword_t)ser[i]<<bits;
        for (bits += 8; (bits>=LBITS || i==DECAF_448_SER_BYTES-1) && k<DECAF_448_LIMBS; bits-=LBITS, buf>>=LBITS) {
            s->limb[k++] = buf & LMASK;
        }
    }
    
    decaf_sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + s->limb[i] - P->limb[i]) >> WBITS );
    return accum;
}
    
/* Constant-time add or subtract */
snv decaf_448_point_add_sub (
    decaf_448_point_t p,
    const decaf_448_point_t q,
    const decaf_448_point_t r,
    decaf_bool_t do_sub
) {
    /* Twisted Edward formulas, complete when 4-torsion isn't involved */
    gf a, b, c, d;
    gf_sub ( b, q->y, q->x );
    gf_sub ( c, r->y, r->x );
    gf_add ( d, r->y, r->x );
    cond_swap(c,d,do_sub);
    gf_mul ( a, c, b );
    gf_add ( b, q->y, q->x );
    gf_mul ( p->y, d, b );
    gf_mul ( b, r->t, q->t );
    gf_mlw ( p->x, b, 2-2*EDWARDS_D );
    gf_add ( b, a, p->y );
    gf_sub ( c, p->y, a );
    gf_mul ( a, q->z, r->z );
    gf_add ( a, a, a );
    gf_add ( p->y, a, p->x );
    gf_sub ( a, a, p->x );
    cond_swap(a,p->y,do_sub);
    gf_mul ( p->z, a, p->y );
    gf_mul ( p->x, p->y, c );
    gf_mul ( p->y, a, b );
    gf_mul ( p->t, b, c );
}   
    
decaf_bool_t decaf_448_point_decode (
    decaf_448_point_t p,
    const unsigned char ser[DECAF_448_SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, a, b, c, d, e;
    decaf_bool_t succ = gf_deser(s, ser), zero = gf_eq(s, ZERO);
    succ &= allow_identity | ~zero;
    succ &= ~hibit(s);
    gf_sqr ( a, s );
    gf_sub ( p->z, ONE, a );
    gf_sqr ( b, p->z ); 
    gf_mlw ( c, a, 4-4*EDWARDS_D );
    gf_add ( c, c, b );
    gf_mul ( b, c, a );
    gf_isqrt ( d, b );
    gf_sqr ( e, d );
    gf_mul ( a, e, b );
    gf_add ( a, a, ONE );
    succ &= ~gf_eq ( a, ZERO );
    gf_mul ( b, c, d );
    cond_neg ( d, hibit(b) );
    gf_add ( p->x, s, s );
    gf_mul ( c, d, s );
    gf_sub ( b, TWO, p->z );
    gf_mul ( a, b, c );
    gf_mul ( p->y,a,p->z );
    gf_mul ( p->t,p->x,a );
    p->y->limb[0] -= zero;
    /* TODO: do something safe if ~succ? */
    return succ;
}

void decaf_448_point_sub(decaf_448_point_t a, const decaf_448_point_t b, const decaf_448_point_t c) {
    decaf_448_point_add_sub(a,b,c,-1);
}
    
void decaf_448_point_add(decaf_448_point_t a, const decaf_448_point_t b, const decaf_448_point_t c) {
    decaf_448_point_add_sub(a,b,c,0);
}

/* No dedicated point double yet (PERF) */
void decaf_448_point_double(decaf_448_point_t a, const decaf_448_point_t b) {
    decaf_448_point_add(a,b,b);
}

void decaf_448_point_negate (
   decaf_448_point_t nega,
   const decaf_448_point_t a
) {
    gf_sub(nega->x, ZERO, a->x);
    gf_cpy(nega->y, a->y);
    gf_cpy(nega->z, a->z);
    gf_sub(nega->t, ZERO, a->t);
}

decaf_bool_t decaf_448_scalar_decode(
    decaf_448_scalar_t s,
    const unsigned char ser[DECAF_448_SER_BYTES]
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
    
    decaf_sdword_t accum = 0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - decaf_448_scalar_p->limb[i]) >> WBITS;
    }
    
    decaf_448_scalar_mul(s,s,decaf_448_scalar_one); /* ham-handed reduce */
    
    return accum;
}

void decaf_bzero (
    void *s,
    size_t size
) {
#ifdef __STDC_LIB_EXT1__
    memset_s(s, size, 0, size);
#else
    volatile uint8_t *destroy = (volatile uint8_t *)s;
    unsigned i;
    for (i=0; i<size; i++) {
        destroy[i] = 0;
    }
#endif
}


void decaf_448_scalar_destroy (
    decaf_448_scalar_t scalar
) {
    decaf_bzero(scalar, sizeof(decaf_448_scalar_t));
}

static inline void ignore_result ( decaf_bool_t boo ) {
    (void)boo;
}

void decaf_448_scalar_decode_long(
    decaf_448_scalar_t s,
    const unsigned char *ser,
    size_t ser_len
) {
    if (ser_len == 0) {
        decaf_448_scalar_copy(s, decaf_448_scalar_zero);
        return;
    }
    
    size_t i;
    unsigned char tmp[DECAF_448_SER_BYTES] = {0};
    decaf_448_scalar_t t1, t2;

    i = ser_len - (ser_len%DECAF_448_SER_BYTES);
    if (i==ser_len) i -= DECAF_448_SER_BYTES;
        
    memcpy(tmp, ser+i, ser_len - i);
    ignore_result( decaf_448_scalar_decode(t1, tmp) );
    decaf_bzero(tmp, sizeof(tmp));
    
    while (i) {
        i -= DECAF_448_SER_BYTES;
        decaf_448_montmul(t1,t1,decaf_448_scalar_r2);
        ignore_result( decaf_448_scalar_decode(t2, ser+i) );
        decaf_448_scalar_add(t1, t1, t2);
    }

    decaf_448_scalar_copy(s, t1);
    decaf_448_scalar_destroy(t1);
    decaf_448_scalar_destroy(t2);
}

void decaf_448_scalar_encode(
    unsigned char ser[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t s
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            ser[k] = s->limb[i] >> (8*j);
        }
    }
}

void decaf_448_point_scalarmul (
    decaf_448_point_t a,
    const decaf_448_point_t b,
    const decaf_448_scalar_t scalar
) {
    /* w=2 signed window uses about 1.5 adds per bit.
     * I figured a few extra lines was worth the 25% speedup.
     */
    decaf_448_point_t w,b3,tmp;
    decaf_448_point_double(w,b);
    /* b3 = b*3 */
    decaf_448_point_add(b3,w,b);
    int i;
    for (i=DECAF_448_SCALAR_BITS &~ 1; i>0; i-=2) {
        decaf_word_t bits = scalar->limb[i/WBITS]>>(i%WBITS);
        decaf_448_cond_sel(tmp,b,b3,((bits^(bits>>1))&1)-1);
        decaf_448_point_double(w,w);
        decaf_448_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        decaf_448_point_double(w,w);
    }
    decaf_448_point_add_sub(w,w,b,((scalar->limb[0]>>1)&1)-1);
    /* low bit is special because fo signed window */
    decaf_448_cond_sel(tmp,b,decaf_448_point_identity,-(scalar->limb[0]&1));
    decaf_448_point_sub(a,w,tmp);
}

void decaf_448_point_double_scalarmul (
    decaf_448_point_t a,
    const decaf_448_point_t b,
    const decaf_448_scalar_t scalarb,
    const decaf_448_point_t c,
    const decaf_448_scalar_t scalarc
) {
    /* w=2 signed window uses about 1.5 adds per bit.
     * I figured a few extra lines was worth the 25% speedup.
     * NB: if adapting this function to scalarmul by a
     * possibly-odd number of unmasked bits, may need to mask.
     */
    decaf_448_point_t w,b3,c3,tmp;
    decaf_448_point_double(w,b);
    decaf_448_point_double(tmp,c);
    /* b3 = b*3 */
    decaf_448_point_add(b3,w,b);
    decaf_448_point_add(c3,tmp,c);
    decaf_448_point_add(w,w,tmp);
    int i;
    for (i=DECAF_448_SCALAR_BITS &~ 1; i>0; i-=2) {
        decaf_448_point_double(w,w);
        decaf_word_t bits = scalarb->limb[i/WBITS]>>(i%WBITS);
        decaf_448_cond_sel(tmp,b,b3,((bits^(bits>>1))&1)-1);
        decaf_448_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        bits = scalarc->limb[i/WBITS]>>(i%WBITS);
        decaf_448_cond_sel(tmp,c,c3,((bits^(bits>>1))&1)-1);
        decaf_448_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        decaf_448_point_double(w,w);
    }
    decaf_448_point_add_sub(w,w,b,((scalarb->limb[0]>>1)&1)-1);
    decaf_448_point_add_sub(w,w,c,((scalarc->limb[0]>>1)&1)-1);
    /* low bit is special because of signed window */
    decaf_448_cond_sel(tmp,b,decaf_448_point_identity,-(scalarb->limb[0]&1));
    decaf_448_point_sub(w,w,tmp);
    decaf_448_cond_sel(tmp,c,decaf_448_point_identity,-(scalarc->limb[0]&1));
    decaf_448_point_sub(a,w,tmp);
}

decaf_bool_t decaf_448_point_eq ( const decaf_448_point_t p, const decaf_448_point_t q ) {
    /* equality mod 2-torsion compares x/y */
    gf a, b;
    gf_mul ( a, p->y, q->x );
    gf_mul ( b, q->y, p->x );
    return gf_eq(a,b);
}


/** Inverse square root using addition chain. */
static decaf_bool_t gf_isqrt_chk(gf y, const gf x, decaf_bool_t allow_zero) {
    gf tmp0, tmp1;
    gf_isqrt(y,x);
    gf_sqr(tmp0,y);
    gf_mul(tmp1,tmp0,x);
    return gf_eq(tmp1,ONE) | (allow_zero & gf_eq(tmp1,ZERO));
}

unsigned char decaf_448_point_from_hash_nonuniform (
    decaf_448_point_t p,
    const unsigned char ser[DECAF_448_SER_BYTES]
) {
    gf r0,r,a,b,c,dee,D,N,rN,e;
    decaf_bool_t over = ~gf_deser(r0,ser);
    decaf_bool_t sgn_r0 = hibit(r0);
    gf_canon(r0);
    gf_sqr(a,r0);
    gf_sub(r,ZERO,a); /*gf_mlw(r,a,QUADRATIC_NONRESIDUE);*/
    gf_mlw(dee,ONE,EDWARDS_D);
    gf_mlw(c,r,EDWARDS_D);
    
    /* Compute D := (dr+a-d)(dr-ar-d) with a=1 */
    gf_sub(a,c,dee);
    gf_add(a,a,ONE);
    decaf_bool_t special_identity_case = gf_eq(a,ZERO);
    gf_sub(b,c,r);
    gf_sub(b,b,dee);
    gf_mul(D,a,b);
    
    /* compute N := (r+1)(a-2d) */
    gf_add(a,r,ONE);
    gf_mlw(N,a,1-2*EDWARDS_D);
    
    /* e = +-1/sqrt(+-ND) */
    gf_mul(rN,r,N);
    gf_mul(a,rN,D);
    
    decaf_bool_t square = gf_isqrt_chk(e,a,DECAF_FALSE);
    decaf_bool_t r_is_zero = gf_eq(r,ZERO);
    square |= r_is_zero;
    square |= special_identity_case;
    
    /* b <- t/s */
    cond_sel(c,r0,r,square); /* r? = sqr ? r : 1 */
    /* In two steps to avoid overflow on 32-bit arch */
    gf_mlw(a,c,1-2*EDWARDS_D);
    gf_mlw(b,a,1-2*EDWARDS_D);
    gf_sub(c,r,ONE);
    gf_mul(a,b,c); /* = r? * (r-1) * (a-2d)^2 with a=1 */
    gf_mul(b,a,e);
    cond_neg(b,~square);
    cond_sel(c,r0,ONE,square);
    gf_mul(a,e,c);
    gf_mul(c,a,D); /* 1/s except for sign.  FUTURE: simplify using this. */
    gf_sub(b,b,c);

    /* a <- s = e * N * (sqr ? r : r0)
     * e^2 r N D = 1
     * 1/s =  1/(e * N * (sqr ? r : r0)) = e * D * (sqr ? 1 : r0)
     */
    gf_mul(a,N,r0);
    cond_sel(rN,a,rN,square);
    gf_mul(a,rN,e);
    gf_mul(c,a,b);
    
    /* Normalize/negate */
    decaf_bool_t neg_s = hibit(a)^~square;
    cond_neg(a,neg_s); /* ends up negative if ~square */
    decaf_bool_t sgn_t_over_s = hibit(b)^neg_s;
    sgn_t_over_s &= ~gf_eq(N,ZERO);
    sgn_t_over_s |= gf_eq(D,ZERO);
    
    /* b <- t */
    cond_sel(b,c,ONE,gf_eq(c,ZERO)); /* 0,0 -> 1,0 */

    /* isogenize */
    gf_sqr(c,a); /* s^2 */
    gf_add(a,a,a); /* 2s */
    gf_add(e,c,ONE);
    gf_mul(p->t,a,e); /* 2s(1+s^2) */
    gf_mul(p->x,a,b); /* 2st */
    gf_sub(a,ONE,c);
    gf_mul(p->y,e,a); /* (1+s^2)(1-s^2) */
    gf_mul(p->z,a,b); /* (1-s^2)t */
    
    return (~square & 1) | (sgn_t_over_s & 2) | (sgn_r0 & 4) | (over & 8);
}

/* TODO: source these impls instead of copy-pasting them */
decaf_bool_t
decaf_448_invert_elligator_nonuniform (
    unsigned char recovered_hash[DECAF_448_SER_BYTES],
    const decaf_448_point_t p,
    unsigned char hint
) {
    decaf_bool_t sgn_s = -(hint & 1),
        sgn_t_over_s = -(hint>>1 & 1),
        sgn_r0 = -(hint>>2 & 1);
    gf a, b, c, d;
    gf_mlw ( a, p->y, 1-EDWARDS_D );
    gf_mul ( c, a, p->t ); 
    gf_mul ( a, p->x, p->z ); 
    gf_sub ( d, c, a );
    gf_add ( a, p->z, p->y ); 
    gf_sub ( b, p->z, p->y ); 
    gf_mul ( c, b, a );
    gf_mlw ( b, c, -EDWARDS_D );
    gf_isqrt ( a, b );
    gf_mlw ( b, a, -EDWARDS_D ); 
    gf_mul ( c, b, a );
    gf_mul ( a, c, d );
    gf_add ( d, b, b );
    gf_mul ( c, d, p->z );
    cond_neg ( b, sgn_t_over_s^~hibit(c) ); 
    cond_neg ( c, sgn_t_over_s^~hibit(c) ); 
    gf_mul ( d, b, p->y ); 
    gf_add ( a, a, d );
    cond_neg( a, hibit(a)^sgn_s);
    
    /* ok, s = a; c = -t/s */
    gf_mul(b,c,a);
    gf_sub(b,ONE,b); /* t+1 */
    gf_sqr(c,a); /* s^2 */
    {   /* identity adjustments */
        /* in case of identity, currently c=0, t=0, b=1, will encode to 1 */
        /* if hint is 0, -> 0 */
        /* if hint is to neg t/s, then go to infinity, effectively set s to 1 */
        decaf_bool_t is_identity = gf_eq(p->x,ZERO);
        cond_sel(c,c,ONE,is_identity & sgn_t_over_s);
        cond_sel(b,b,ZERO,is_identity & ~sgn_t_over_s & ~sgn_s); /* identity adjust */
        
    }
    gf_mlw(d,c,2*EDWARDS_D-1); /* $d = (2d-a)s^2 */
    gf_add(a,b,d); /* num? */
    gf_sub(d,b,d); /* den? */
    gf_mul(b,a,d); /* n*d */
    cond_sel(a,d,a,sgn_s);
    decaf_bool_t succ = gf_isqrt_chk(c,b,DECAF_TRUE);
    gf_mul(b,a,c);
    cond_neg(b, sgn_r0^hibit(b));
    
    succ &= ~(gf_eq(b,ZERO) & sgn_r0);
    
    gf_canon(b);
    int k=0, bits=0;
    decaf_dword_t buf=0;
    FOR_LIMB(i, {
        buf |= (decaf_dword_t)b->limb[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==DECAF_448_LIMBS-1) && k<DECAF_448_SER_BYTES; bits-=8, buf>>=8) {
            recovered_hash[k++]=buf;
        }
    });
    return succ;
}

void decaf_448_point_debugging_torque (
    decaf_448_point_t q,
    const decaf_448_point_t p
) {
    gf_sub(q->x,ZERO,p->x);
    gf_sub(q->y,ZERO,p->y);
    gf_cpy(q->z,p->z);
    gf_cpy(q->t,p->t);
}

unsigned char decaf_448_point_from_hash_uniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[2*DECAF_448_SER_BYTES]
) {
    decaf_448_point_t pt2;
    unsigned char ret1 =
        decaf_448_point_from_hash_nonuniform(pt,hashed_data);
    unsigned char ret2 =
        decaf_448_point_from_hash_nonuniform(pt2,&hashed_data[DECAF_448_SER_BYTES]);
    decaf_448_point_add(pt,pt,pt2);
    return ret1 | (ret2<<4);
}

decaf_bool_t decaf_448_invert_elligator_uniform (
    unsigned char partial_hash[2*DECAF_448_SER_BYTES],
    const decaf_448_point_t p,
    unsigned char hint
) {
    decaf_448_point_t pt2;
    decaf_448_point_from_hash_nonuniform(pt2,&partial_hash[DECAF_448_SER_BYTES]);
    decaf_448_point_sub(pt2,p,pt2);
    return decaf_448_invert_elligator_nonuniform(partial_hash,pt2,hint);
}

decaf_bool_t decaf_448_point_valid (
    const decaf_448_point_t p
) {
    gf a,b,c;
    gf_mul(a,p->x,p->y);
    gf_mul(b,p->z,p->t);
    decaf_bool_t out = gf_eq(a,b);
    gf_sqr(a,p->x);
    gf_sqr(b,p->y);
    gf_sub(a,b,a);
    gf_sqr(b,p->t);
    gf_mlw(c,b,1-EDWARDS_D);
    gf_sqr(b,p->z);
    gf_sub(b,b,c);
    out &= gf_eq(a,b);
    out &= ~gf_eq(p->z,ZERO);
    return out;
}

void decaf_448_precompute (
    decaf_448_precomputed_s *a,
    const decaf_448_point_t b
) {
    decaf_448_point_copy(a->p[0],b);
}

decaf_bool_t decaf_448_direct_scalarmul (
    uint8_t scaled[DECAF_448_SER_BYTES],
    const uint8_t base[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) {
    decaf_448_point_t basep;
    decaf_bool_t succ = decaf_448_point_decode(basep, base, allow_identity);
    if (short_circuit & ~succ) return succ;
    decaf_448_point_scalarmul(basep, basep, scalar);
    decaf_448_point_encode(scaled, basep);
    return succ;
}

void decaf_448_precomputed_scalarmul (
    decaf_448_point_t a,
    const decaf_448_precomputed_s *b,
    const decaf_448_scalar_t scalar
) {
    decaf_448_point_scalarmul(a,b->p[0],scalar);
}

void decaf_448_base_double_scalarmul_non_secret (
    decaf_448_point_t combo,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) {
    decaf_448_point_double_scalarmul(combo, decaf_448_point_base, scalar1, base2, scalar2);
}

void decaf_448_point_destroy (
  decaf_448_point_t point
) {
    decaf_bzero(point, sizeof(decaf_448_point_t));
}

decaf_bool_t decaf_memeq (
   const void *data1_,
   const void *data2_,
   size_t size
) {
    const unsigned char *data1 = (const unsigned char *)data1_;
    const unsigned char *data2 = (const unsigned char *)data2_;
    unsigned char ret = 0;
    for (; size; size--, data1++, data2++) {
        ret |= *data1 ^ *data2;
    }
    return (((decaf_dword_t)ret) - 1) >> 8;
}

void decaf_448_precomputed_destroy (
  decaf_448_precomputed_s *pre
) {
    decaf_bzero(pre, sizeof_decaf_448_precomputed_s);
}
