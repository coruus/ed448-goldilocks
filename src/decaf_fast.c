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
#include "field.h"

#include "ec_point.h" // REMOVE!

#define WBITS DECAF_WORD_BITS

#if WBITS == 64
#define LBITS 56
typedef __uint128_t decaf_dword_t;
typedef __int128_t decaf_sdword_t;
#define LIMB(x) (x##ull)
#define SC_LIMB(x) (x##ull)
#elif WBITS == 32
typedef uint64_t decaf_dword_t;
typedef int64_t decaf_sdword_t;
#define LBITS 28
#define LIMB(x) (x##ull)&((1ull<<LBITS)-1), (x##ull)>>LBITS
#define SC_LIMB(x) (x##ull)&((1ull<<32)-1), (x##ull)>>32
#else
#error "Only supporting 32- and 64-bit platforms right now"
#endif

static const int QUADRATIC_NONRESIDUE = -1;

#define sv static void
typedef decaf_word_t gf[DECAF_448_LIMBS] __attribute__((aligned(32)));
static const gf ZERO = {0}, ONE = {1}, TWO = {2};

#define LMASK ((((decaf_word_t)1)<<LBITS)-1)
#if WBITS == 64
static const gf P = { LMASK, LMASK, LMASK, LMASK, LMASK-1, LMASK, LMASK, LMASK };
#else
static const gf P = { LMASK,   LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK,
		      LMASK-1, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK, LMASK };
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

/** base = twist of Goldilocks base point (~,19). */

const decaf_448_point_t decaf_448_point_base = {{
    { LIMB(0xb39a2d57e08c7b),LIMB(0xb38639c75ff281),
      LIMB(0x2ec981082b3288),LIMB(0x99fe8607e5237c),
      LIMB(0x0e33fbb1fadd1f),LIMB(0xe714f67055eb4a),
      LIMB(0xc9ae06d64067dd),LIMB(0xf7be45054760fa) },
    { LIMB(0xbd8715f551617f),LIMB(0x8c17fbeca8f5fc),
      LIMB(0xaae0eec209c06f),LIMB(0xce41ad80cbe6b8),
      LIMB(0xdf360b5c828c00),LIMB(0xaf25b6bbb40e3b),
      LIMB(0x8ed37f0ce4ed31),LIMB(0x72a1c3214557b9) },
    { 1 },
    { LIMB(0x97ca9c8ed8bde9),LIMB(0xf0b780da83304c),
      LIMB(0x0d79c0a7729a69),LIMB(0xc18d3f24aebc1c),
      LIMB(0x1fbb5389b3fda5),LIMB(0xbb24f674635948),
      LIMB(0x723a55709a3983),LIMB(0xe1c0107a823dd4) }
}};

struct decaf_448_precomputed_s {
    decaf_448_point_t p[1];
};

const struct decaf_448_precomputed_s *decaf_448_precomputed_base =
    (const struct decaf_448_precomputed_s *)decaf_448_point_base;

const size_t sizeof_decaf_448_precomputed_s = sizeof(struct decaf_448_precomputed_s);
const size_t alignof_decaf_448_precomputed_s = 32;

#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)) || defined(DECAF_FORCE_UNROLL)
    #if DECAF_448_LIMBS==8
    #define FOR_LIMB(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #elif DECAF_448_LIMBS==16
    #define FOR_LIMB(i,op) { unsigned int i=0; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
       op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
    }
    #else
    #define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}
    #endif
#else
#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}
#endif

/** Copy x = y */
sv gf_cpy(gf x, const gf y) { FOR_LIMB(i, x[i] = y[i]); }

/** Mostly-unoptimized multiply (PERF), but at least it's unrolled. */
static inline void gf_mul (gf c, const gf a, const gf b) {
    field_mul((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** No dedicated square (PERF) */
static inline void gf_sqr (gf c, const gf a) {
    field_sqr((field_t *)c, (const field_t *)a);
}

/** Inverse square root using addition chain. */
sv gf_isqrt(gf y, const gf x) {
    field_isr((field_t *)y, (const field_t *)x);
}

/** Add mod p.  Conservatively always weak-reduce. (PERF) */
static inline void gf_add ( gf c, const gf a, const gf b ) {
    field_add((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Subtract mod p.  Conservatively always weak-reduce. (PERF) */
static inline void gf_sub ( gf c, const gf a, const gf b ) {
    field_sub((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Add mod p.  Conservatively always weak-reduce. (PERF) */
static inline void gf_bias ( gf c, int amt) {
    field_bias((field_t *)c, amt);
}

/** Subtract mod p.  Bias by 2 and don't reduce  */
static inline void gf_sub_nr ( gf c, const gf a, const gf b ) {
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_sub_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
    gf_bias(c, 2);
}

/** Subtract mod p. Bias by amt but don't reduce.  */
static inline void gf_sub_nr_x ( gf c, const gf a, const gf b, int amt ) {
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_sub_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
    gf_bias(c, amt);
}

/** Add mod p.  Don't reduce. */
static inline void gf_add_nr ( gf c, const gf a, const gf b ) {
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_add_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Constant time, x = is_z ? z : y */
sv cond_sel(gf x, const gf y, const gf z, decaf_bool_t is_z) {
    FOR_LIMB(i, x[i] = (y[i] & ~is_z) | (z[i] & is_z) );
}

/** Constant time, if (neg) x=-x; */
sv cond_neg(gf x, decaf_bool_t neg) {
    gf y;
    gf_sub(y,ZERO,x);
    cond_sel(x,x,y,neg);
}

/** Constant time, if (swap) (x,y) = (y,x); */
sv cond_swap(gf x, gf y, decaf_bool_t swap) {
    FOR_LIMB(i, {
        decaf_word_t s = (x[i] ^ y[i]) & swap;
        x[i] ^= s;
        y[i] ^= s;
    });
}

/**
 * Mul by signed int.  Not constant-time WRT the sign of that int.
 * Just uses a full mul (PERF)
 */
static inline void gf_mlw(gf c, const gf a, int w) {
    if (w>0) {
        field_mulw((field_t *)c, (const field_t *)a, w);
    } else {
        field_mulw((field_t *)c, (const field_t *)a, -w);
        gf_sub(c,ZERO,c);
    }
}

/** Canonicalize */
static inline void gf_canon ( gf a ) {
    field_strong_reduce((field_t *)a);
}

/** Compare a==b */
static decaf_word_t __attribute__((noinline)) gf_eq(const gf a, const gf b) {
    gf c;
    gf_sub(c,a,b);
    gf_canon(c);
    decaf_word_t ret=0;
    FOR_LIMB(i, ret |= c[i] );
    /* Hope the compiler is too dumb to optimize this, thus noinline */
    return ((decaf_dword_t)ret - 1) >> WBITS;
}

/** Return high bit of x = low bit of 2x mod p */
static decaf_word_t hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_canon(y);
    return -(y[0]&1);
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
sv decaf_448_subx(
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

sv decaf_448_montmul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b,
    const decaf_448_scalar_t p,
    decaf_word_t montgomery_factor
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
        
        mand = accum[0] * montgomery_factor;
        chain = 0;
        mier = p->limb;
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
    
    decaf_448_subx(out, accum, p, p, hi_carry);
}

void decaf_448_scalar_mul (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    decaf_448_montmul(out,a,b,decaf_448_scalar_p,DECAF_MONTGOMERY_FACTOR);
    decaf_448_montmul(out,out,decaf_448_scalar_r2,decaf_448_scalar_p,DECAF_MONTGOMERY_FACTOR);
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

void decaf_448_scalar_copy (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        out->limb[i] = a->limb[i];
    }
}

decaf_bool_t decaf_448_scalar_eq (
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t b
) {
    decaf_word_t diff = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        diff |= a->limb[i] ^ b->limb[i];
    }
    return (((decaf_dword_t)diff)-1)>>WBITS;
}

/* *** API begins here *** */    

/** identity = (0,1) */
const decaf_448_point_t decaf_448_point_identity = {{{0},{1},{1},{0}}};

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
    int i, k=0, bits=0;
    decaf_dword_t buf=0;
    for (i=0; i<DECAF_448_LIMBS; i++) {
        buf |= (decaf_dword_t)a[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==DECAF_448_LIMBS-1) && k<DECAF_448_SER_BYTES; bits-=8, buf>>=8) {
            ser[k++]=buf;
        }
    }
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
            s[k++] = buf & LMASK;
        }
    }
    
    decaf_sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + s[i] - P[i]) >> WBITS );
    return accum;
}
    
/* Constant-time add or subtract */
sv decaf_448_point_add_sub (
    decaf_448_point_t p,
    const decaf_448_point_t q,
    const decaf_448_point_t r,
    decaf_bool_t do_sub
) {
    /* Twisted Edward formulas, complete when 4-torsion isn't involved */
    gf a, b, c, d;
    gf_sub_nr ( b, q->y, q->x );
    gf_sub_nr ( c, r->y, r->x );
    gf_add_nr ( d, r->y, r->x );
    cond_swap(c,d,do_sub);
    gf_mul ( a, c, b );
    gf_add_nr ( b, q->y, q->x );
    gf_mul ( p->y, d, b );
    gf_mul ( b, r->t, q->t );
    gf_mlw ( p->x, b, 2-2*EDWARDS_D );
    gf_add_nr ( b, a, p->y );
    gf_sub_nr ( c, p->y, a );
    gf_mul ( a, q->z, r->z );
    gf_add_nr ( a, a, a );
    gf_add_nr ( p->y, a, p->x );
    gf_sub_nr ( a, a, p->x );
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
    p->y[0] -= zero;
    /* TODO: do something safe if ~succ? */
    return succ;
}

void decaf_448_point_sub (
    decaf_448_point_t p,
    const decaf_448_point_t q,
    const decaf_448_point_t r
) {
    gf a, b, c, d;
    gf_sub_nr ( b, q->y, q->x );
    gf_sub_nr ( d, r->y, r->x );
    gf_add_nr ( c, r->y, r->x );
    gf_mul ( a, c, b );
    gf_add_nr ( b, q->y, q->x );
    gf_mul ( p->y, d, b );
    gf_mul ( b, r->t, q->t );
    gf_mlw ( p->x, b, 2-2*EDWARDS_D );
    gf_add_nr ( b, a, p->y );
    gf_sub_nr ( c, p->y, a );
    gf_mul ( a, q->z, r->z );
    gf_add_nr ( a, a, a );
    gf_sub_nr ( p->y, a, p->x );
    gf_add_nr ( a, a, p->x );
    gf_mul ( p->z, a, p->y );
    gf_mul ( p->x, p->y, c );
    gf_mul ( p->y, a, b );
    gf_mul ( p->t, b, c );
}
    
void decaf_448_point_add (
    decaf_448_point_t p,
    const decaf_448_point_t q,
    const decaf_448_point_t r
) {
    gf a, b, c, d;
    gf_sub_nr ( b, q->y, q->x );
    gf_sub_nr ( c, r->y, r->x );
    gf_add_nr ( d, r->y, r->x );
    gf_mul ( a, c, b );
    gf_add_nr ( b, q->y, q->x );
    gf_mul ( p->y, d, b );
    gf_mul ( b, r->t, q->t );
    gf_mlw ( p->x, b, 2-2*EDWARDS_D );
    gf_add_nr ( b, a, p->y );
    gf_sub_nr ( c, p->y, a );
    gf_mul ( a, q->z, r->z );
    gf_add_nr ( a, a, a );
    gf_add_nr ( p->y, a, p->x );
    gf_sub_nr ( a, a, p->x );
    gf_mul ( p->z, a, p->y );
    gf_mul ( p->x, p->y, c );
    gf_mul ( p->y, a, b );
    gf_mul ( p->t, b, c );
}

/* No dedicated point double yet (PERF) */
void decaf_448_point_double(decaf_448_point_t p, const decaf_448_point_t q) {
    gf a, b, c, d;
    gf_sqr ( c, q->x );
    gf_sqr ( a, q->y );
    gf_add_nr ( d, c, a );
    gf_add_nr ( p->t, q->y, q->x );
    gf_sqr ( b, p->t );
    gf_sub_nr_x ( b, b, d, 3 );
    gf_sub_nr ( p->t, a, c );
    gf_sqr ( p->x, q->z );
    gf_add_nr ( p->z, p->x, p->x );
    gf_sub_nr_x ( a, p->z, p->t, 4 );
    gf_mul ( p->x, a, b );
    gf_mul ( p->z, p->t, a );
    gf_mul ( p->y, p->t, d );
    gf_mul ( p->t, b, d );
}

void decaf_448_point_copy (
    decaf_448_point_t a,
    const decaf_448_point_t b
) {
    gf_cpy(a->x, b->x);
    gf_cpy(a->y, b->y);
    gf_cpy(a->z, b->z);
    gf_cpy(a->t, b->t);
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
        decaf_448_montmul(t1,t1,decaf_448_scalar_r2,decaf_448_scalar_p,DECAF_MONTGOMERY_FACTOR);
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

void decaf_448_point_from_hash_nonuniform (
    decaf_448_point_t p,
    const unsigned char ser[DECAF_448_SER_BYTES]
) {
    gf r,urr,a,b,c,dee,e,ur2_d,udr2_1;
    (void)gf_deser(r,ser);
    gf_canon(r);
    gf_sqr(a,r);
    gf_mlw(urr,a,QUADRATIC_NONRESIDUE);
    gf_mlw(dee,ONE,EDWARDS_D);
    gf_add(a,urr,ONE);
    gf_sub(ur2_d,dee,urr);
    gf_mul(c,a,ur2_d);
    gf_mlw(b,urr,-EDWARDS_D);
    gf_add(udr2_1,b,ONE);
    gf_mul(a,c,udr2_1);
    gf_mlw(c,a,EDWARDS_D+1);
    gf_isqrt(b,c); /* FIELD: if 5 mod 8, multiply result by u. */
    gf_sqr(a,b);
    gf_mul(e,a,c);
    decaf_bool_t square = gf_eq(e,ONE);
    gf_mul(a,b,r);
    cond_sel(b,a,b,square);
    gf_mlw(a,b,EDWARDS_D+1);
    cond_swap(ur2_d,udr2_1,~square);
    gf_mul(e,ur2_d,a);
    cond_neg(e,hibit(e)^square);
    gf_mul(b,udr2_1,a);
    gf_sqr(c,b);
    gf_sqr(a,e);
    gf_sub(a,ONE,a);
    gf_add(e,e,e);
    gf_add(b,dee,c);
    gf_sub(c,dee,c);
    gf_mul(p->x,e,c);
    gf_mul(p->z,a,c);
    gf_mul(p->y,b,a);
    gf_mul(p->t,b,e);
}

void decaf_448_point_from_hash_uniform (
    decaf_448_point_t pt,
    const unsigned char hashed_data[2*DECAF_448_SER_BYTES]
) {
    decaf_448_point_t pt2;
    decaf_448_point_from_hash_nonuniform(pt,hashed_data);
    decaf_448_point_from_hash_nonuniform(pt2,&hashed_data[DECAF_448_SER_BYTES]);
    decaf_448_point_add(pt,pt,pt2);
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

void decaf_448_precomputed_scalarmul (
    decaf_448_point_t a,
    const decaf_448_precomputed_s *b,
    const decaf_448_scalar_t scalar
) {
    decaf_448_point_scalarmul(a,b->p[0],scalar);
}

decaf_bool_t decaf_448_direct_scalarmul (
    uint8_t scaled[DECAF_448_SER_BYTES],
    const uint8_t base[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) {
    (void)short_circuit;
    gf s0, x0, xa, za, xd, zd, xs, zs;
    decaf_bool_t succ = gf_deser ( s0, base );
    succ &= allow_identity |~ gf_eq( s0, ZERO);
    succ &= ~hibit(s0);

    gf_sqr ( xa, s0 );
    gf_cpy ( x0, xa );
    gf_cpy ( za, ONE );
    gf_cpy ( xd, ONE );
    gf_cpy ( zd, ZERO );
    
    int i,j;
    decaf_bool_t pflip = 0;
    for (j=448-1; j>=0; j--) { /* TODO: DECAF_SCALAR_BITS */
        decaf_bool_t flip = -((scalar->limb[j/WORD_BITS]>>(j%WORD_BITS))&1);;
        cond_swap(xa,xd,flip^pflip);
        cond_swap(za,zd,flip^pflip);
        gf_add_nr ( xs, xa, za );
        gf_sub_nr ( zs, xa, za );
        gf_add_nr ( xa, xd, zd );
        gf_sub_nr ( za, xd, zd );
        gf_mul ( xd, xa, zs );
        gf_mul ( zd, xs, za );
        gf_add_nr ( xs, xd, zd );
        gf_sub_nr ( zd, xd, zd );
        gf_mul ( zs, zd, s0 );
        gf_sqr ( zd, xa );
        gf_sqr ( xa, za );
        gf_sub_nr ( za, zd, xa );
        gf_mul ( xd, xa, zd );
        gf_mlw ( zd, za, 1-EDWARDS_D );
        gf_add_nr ( xa, xa, zd );
        gf_mul ( zd, xa, za );
        gf_sqr ( xa, xs );
        gf_sqr ( za, zs );
        pflip = flip;
    }
    cond_swap(xa,xd,pflip);
    cond_swap(za,zd,pflip);
    
    /* OK, time to reserialize! */
    gf xz_d, xz_a, den, L0, L1, L2, L3, out; /* TODO: simplify */
    mask_t zcase, output_zero, sflip, za_zero;
    gf_mul(xz_d, xd, zd);
    gf_mul(xz_a, xa, za);
    output_zero = gf_eq(xz_d, ZERO);
    za_zero = gf_eq(za, ZERO);
    cond_sel(xz_d, xz_d, ONE, output_zero); /* make xz_d always nonzero */
    zcase = output_zero | gf_eq(xz_a, ZERO);

    /* Curve test in zcase */
    gf_cpy(L0,x0);
    gf_add(L0,L0,ONE);
    gf_sqr(L1,L0);
    gf_mlw(L0,x0,-4*EDWARDS_D);
    gf_add(L1,L1,L0);
    cond_sel(xz_a,xz_a,L1,zcase);

    /* Compute denominator */
    gf_mul(L0, x0, xz_d);
    gf_mlw(L2, L0, 4);
    gf_mul(L1, L2, xz_a);
    gf_isqrt(den, L1);

    /* Check squareness */
    gf_sqr(L2, den);
    gf_mul(L0, L1, L2);
    gf_add(L0, L0, ONE);
    succ &= ~hibit(s0) & ~gf_eq(L0, ZERO);

    /* Compute y/x */
    gf_mul(L1, x0, xd);
    gf_sub(L1, zd, L1);
    gf_mul(L0, za, L1); /* L0 = "opq" */
    gf_mul(L1, x0, zd);
    gf_sub(L1, L1, xd);
    gf_mul(L2, xa, L1); /* L2 = "pqr" */

    gf_sub(L1, L0, L2);
    gf_add(L0, L0, L2);
    gf_mul(L2, L1, den); /* L2 = y0 / x0 */
    gf_mul(L1, L0, den); /* L1 = yO / xO */
    sflip = hibit(L1) ^ hibit(L2) ^ za_zero;
    cond_sel(L0, xd, zd, sflip); /* L0 = "times" */
    /* OK, done with y-coordinates */

    /* OK, now correct for swappage */
    gf_add(den,den,den);
    gf_mul(L1,den,s0);
    gf_sqr(L2,L1);
    gf_mul(L3,L2,xz_a);
    cond_sel(den,L1,L3,pflip|zcase);

    /* compute the output */
    gf_mul(L1,L0,den);

    cond_sel(L2,zs,s0,zcase); /* zs, but s0 in zcase */
    gf_mul(L0,L1,L2);

    cond_sel(L3,xd,zd,za_zero);
    cond_sel(L2,xs,L3,zcase); /* xs, but zq or qq in zcase */
    gf_mul(out,L0,L2);

    cond_sel(out,out,ZERO,output_zero);
    cond_neg(out,hibit(out));
    //
    // /* TODO: resubroutineize? */
    gf_canon(out);
    int k=0, bits=0;
    decaf_dword_t buf=0;
    for (i=0; i<DECAF_448_LIMBS; i++) {
        buf |= (decaf_dword_t)out[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==DECAF_448_LIMBS-1) && k<DECAF_448_SER_BYTES; bits-=8, buf>>=8) {
            scaled[k++]=buf;
        }
    }

    return succ;
}

