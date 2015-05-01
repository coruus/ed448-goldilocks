/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.c
 * @author Mike Hamburg
 * @brief Decaf high-level functions.
 */

#define _XOPEN_SOURCE 600 /* for posix_memalign */
#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#include "decaf.h"
#include <string.h>
#include "field.h"
#include "decaf_448_config.h"

#define WBITS DECAF_WORD_BITS

/* Rename table for eventual factoring into .c.inc, MSR ECC style */
#define SCALAR_LIMBS DECAF_448_SCALAR_LIMBS
#define SCALAR_BITS DECAF_448_SCALAR_BITS
#define NLIMBS DECAF_448_LIMBS
#define API_NS(_id) decaf_448_##_id
#define API_NS2(_pref,_id) _pref##_decaf_448_##_id
#define scalar_t decaf_448_scalar_t
#define point_t decaf_448_point_t
#define precomputed_s decaf_448_precomputed_s
#define SER_BYTES DECAF_448_SER_BYTES

#if WBITS == 64
typedef __int128_t decaf_sdword_t;
#define LIMB(x) (x##ull)
#define SC_LIMB(x) (x##ull)
#elif WBITS == 32
typedef int64_t decaf_sdword_t;
/* 28 is MAGIC */
#define LIMB(x) (x##ull)&((1ull<<28)-1), (x##ull)>>28
#define SC_LIMB(x) (x##ull)&((1ull<<32)-1), (x##ull)>>32
#else
#error "Only supporting 32- and 64-bit platforms right now"
#endif

//static const int QUADRATIC_NONRESIDUE = -1;

#define sv static void
#define snv static void __attribute__((noinline))
#define siv static inline void __attribute__((always_inline))
static const gf ZERO = {{{0}}}, ONE = {{{1}}}, TWO = {{{2}}};

static const int EDWARDS_D = -39081;

static const scalar_t sc_p = {{{
    SC_LIMB(0x2378c292ab5844f3),
    SC_LIMB(0x216cc2728dc58f55),
    SC_LIMB(0xc44edb49aed63690),
    SC_LIMB(0xffffffff7cca23e9),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0xffffffffffffffff),
    SC_LIMB(0x3fffffffffffffff)
}}};
const scalar_t API_NS(scalar_one) = {{{1}}}, API_NS(scalar_zero) = {{{0}}};

static const scalar_t sc_r2 = {{{
    SC_LIMB(0xe3539257049b9b60),
    SC_LIMB(0x7af32c4bc1b195d9),
    SC_LIMB(0x0d66de2388ea1859),
    SC_LIMB(0xae17cf725ee4d838),
    SC_LIMB(0x1a9cc14ba3c47c44),
    SC_LIMB(0x2052bcb7e4d070af),
    SC_LIMB(0x3402a939f823b729)
}}};

static const scalar_t sc_r1 = {{{
    SC_LIMB(0x721cf5b5529eec34),
    SC_LIMB(0x7a4cf635c8e9c2ab),
    SC_LIMB(0xeec492d944a725bf),
    SC_LIMB(0x000000020cd77058),
    SC_LIMB(0),
    SC_LIMB(0),
    SC_LIMB(0)
}}};

static const decaf_word_t MONTGOMERY_FACTOR = (decaf_word_t)(0x3bd440fae918bc5ull);

/** base = twist of Goldilocks base point (~,19). */

#ifndef FIELD_LITERAL
#  define FIELD_LITERAL(a,b,c,d,e,f,g,h) \
    LIMB(a),LIMB(b),LIMB(c),LIMB(d),LIMB(e),LIMB(f),LIMB(g),LIMB(h)
#endif

const point_t API_NS(point_base) = {{
    {{{ FIELD_LITERAL(
        0xb39a2d57e08c7b,0xb38639c75ff281,
        0x2ec981082b3288,0x99fe8607e5237c,
        0x0e33fbb1fadd1f,0xe714f67055eb4a,
        0xc9ae06d64067dd,0xf7be45054760fa )}}},
    {{{ FIELD_LITERAL(  
        0xbd8715f551617f,0x8c17fbeca8f5fc,
        0xaae0eec209c06f,0xce41ad80cbe6b8,
        0xdf360b5c828c00,0xaf25b6bbb40e3b,
        0x8ed37f0ce4ed31,0x72a1c3214557b9 )}}},
    {{{ 1 }}},          
    {{{ FIELD_LITERAL(  
        0x97ca9c8ed8bde9,0xf0b780da83304c,
        0x0d79c0a7729a69,0xc18d3f24aebc1c,
        0x1fbb5389b3fda5,0xbb24f674635948,
        0x723a55709a3983,0xe1c0107a823dd4 )}}}
}};

/* Projective Niels coordinates */
typedef struct { gf a, b, c; } niels_s, niels_t[1];
typedef struct { niels_t n; gf z; } pniels_s, pniels_t[1];

/* Precomputed base */
struct precomputed_s { niels_t table [DECAF_COMBS_N<<(DECAF_COMBS_T-1)]; };

extern const decaf_word_t API_NS(precomputed_base_as_words)[];
const precomputed_s *API_NS(precomputed_base) =
    (const precomputed_s *) &API_NS(precomputed_base_as_words);

const size_t API_NS2(sizeof,precomputed_s) = sizeof(precomputed_s);
const size_t API_NS2(alignof,precomputed_s) = 32;

#ifdef __clang__
#if 100*__clang_major__ + __clang_minor__ > 305
#define VECTORIZE _Pragma("clang loop unroll(disable) vectorize(enable) vectorize_width(8)")
#endif
#endif

#ifndef VECTORIZE
#define VECTORIZE
#endif

#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<NLIMBS; i++)  { op; }}
#define FOR_LIMB_V(i,op) { unsigned int i=0; VECTORIZE for (i=0; i<NLIMBS; i++)  { op; }}

/** Copy x = y */
siv gf_cpy(gf x, const gf y) { x[0] = y[0]; }

/** Mostly-unoptimized multiply, but at least it's unrolled. */
siv gf_mul (gf c, const gf a, const gf b) {
    field_mul((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Dedicated square */
siv gf_sqr (gf c, const gf a) {
    field_sqr((field_t *)c, (const field_t *)a);
}

/** Inverse square root using addition chain. */
siv gf_isqrt(gf y, const gf x) {
    field_isr((field_t *)y, (const field_t *)x);
}

/** Inverse.  TODO: adapt to 5-mod-8 fields? */
sv gf_invert(gf y, const gf x) {
    gf t1, t2;
    gf_sqr(t1, x); // o^2
    gf_isqrt(t2, t1); // +-1/sqrt(o^2) = +-1/o
    gf_sqr(t1, t2);
    gf_mul(t2, t1, x); // not direct to y in case of alias.
    gf_cpy(y, t2);
}

/** Add mod p.  Conservatively always weak-reduce. */
snv gf_add ( gf_s *__restrict__ c, const gf a, const gf b ) {
    field_add((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Subtract mod p.  Conservatively always weak-reduce. */
snv gf_sub ( gf c, const gf a, const gf b ) {
    field_sub((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Add mod p.  Conservatively always weak-reduce.) */
siv gf_bias ( gf c, int amt) {
    field_bias((field_t *)c, amt);
}

/** Subtract mod p.  Bias by 2 and don't reduce  */
siv gf_sub_nr ( gf_s *__restrict__ c, const gf a, const gf b ) {
//    FOR_LIMB_V(i, c->limb[i] = a->limb[i] - b->limb[i] + 2*P->limb[i] );
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_sub_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
    gf_bias(c, 2);
    if (WBITS==32) field_weak_reduce((field_t*) c); // HACK FIXME
}

/** Subtract mod p. Bias by amt but don't reduce.  */
siv gf_sub_nr_x ( gf c, const gf a, const gf b, int amt ) {
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_sub_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
    gf_bias(c, amt);
    if (WBITS==32) field_weak_reduce((field_t*) c); // HACK FIXME
}

/** Add mod p.  Don't reduce. */
siv gf_add_nr ( gf c, const gf a, const gf b ) {
//    FOR_LIMB_V(i, c->limb[i] = a->limb[i] + b->limb[i]);
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_add_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
}

/** Constant time, x = is_z ? z : y */
siv cond_sel(gf x, const gf y, const gf z, decaf_bool_t is_z) {
    big_register_t br_mask = br_set_to_mask(is_z);
    big_register_t *out = (big_register_t *)x;
    const big_register_t *y_ = (const big_register_t *)y, *z_ = (const big_register_t *)z;
    word_t k;
    for (k=0; k<sizeof(gf)/sizeof(big_register_t); k++) {
        out[k] = (~br_mask & y_[k]) | (br_mask & z_[k]);
    }
    /*
    constant_time_select(x,z,y,sizeof(gf),is_z);
    */
}

/** Constant time, if (neg) x=-x; */
sv cond_neg(gf x, decaf_bool_t neg) {
    gf y;
    gf_sub(y,ZERO,x);
    cond_sel(x,x,y,neg);
}

/** Constant time, if (swap) (x,y) = (y,x); */
siv cond_swap(gf x, gf_s *__restrict__ y, decaf_bool_t swap) {
    FOR_LIMB_V(i, {
        decaf_word_t s = (x->limb[i] ^ y->limb[i]) & swap;
        x->limb[i] ^= s;
        y->limb[i] ^= s;
    });
}

/**
 * Mul by signed int.  Not constant-time WRT the sign of that int.
 * Just uses a full mul (PERF)
 */
siv gf_mlw(gf c, const gf a, int w) {
    if (w>0) {
        field_mulw((field_t *)c, (const field_t *)a, w);
    } else {
        field_mulw((field_t *)c, (const field_t *)a, -w);
        gf_sub(c,ZERO,c);
    }
}

/** Canonicalize */
siv gf_canon ( gf a ) {
    field_strong_reduce((field_t *)a);
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

/** Inverse square root using addition chain. */
static decaf_bool_t gf_isqrt_chk(gf y, const gf x, decaf_bool_t allow_zero) {
    gf tmp0, tmp1;
    field_isr((field_t *)y, (const field_t *)x);
    gf_sqr(tmp0,y);
    gf_mul(tmp1,tmp0,x);
    return gf_eq(tmp1,ONE) | (allow_zero & gf_eq(tmp1,ZERO));
}

/** Return high bit of x = low bit of 2x mod p */
static decaf_word_t hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_canon(y);
    return -(y->limb[0]&1);
}

/** {extra,accum} - sub +? p
 * Must have extra <= 1
 */
snv sc_subx(
    scalar_t out,
    const decaf_word_t accum[SCALAR_LIMBS],
    const scalar_t sub,
    const scalar_t p,
    decaf_word_t extra
) {
    decaf_sdword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + accum[i]) - sub->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_bool_t borrow = chain+extra; /* = 0 or -1 */
    
    chain = 0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
}

snv sc_montmul (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    unsigned int i,j;
    decaf_word_t accum[SCALAR_LIMBS+1] = {0};
    decaf_word_t hi_carry = 0;
    
    for (i=0; i<SCALAR_LIMBS; i++) {
        decaf_word_t mand = a->limb[i];
        const decaf_word_t *mier = b->limb;
        
        decaf_dword_t chain = 0;
        for (j=0; j<SCALAR_LIMBS; j++) {
            chain += ((decaf_dword_t)mand)*mier[j] + accum[j];
            accum[j] = chain;
            chain >>= WBITS;
        }
        accum[j] = chain;
        
        mand = accum[0] * MONTGOMERY_FACTOR;
        chain = 0;
        mier = sc_p->limb;
        for (j=0; j<SCALAR_LIMBS; j++) {
            chain += (decaf_dword_t)mand*mier[j] + accum[j];
            if (j) accum[j-1] = chain;
            chain >>= WBITS;
        }
        chain += accum[j];
        chain += hi_carry;
        accum[j-1] = chain;
        hi_carry = chain >> WBITS;
    }
    
    sc_subx(out, accum, sc_p, sc_p, hi_carry);
}

void API_NS(scalar_mul) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    sc_montmul(out,a,b);
    sc_montmul(out,out,sc_r2);
}

/* PERF: could implement this */
siv sc_montsqr (
    scalar_t out,
    const scalar_t a
) {
    sc_montmul(out,a,a);
}

decaf_bool_t API_NS(scalar_invert) (
    scalar_t out,
    const scalar_t a
) {
    /* FIELD MAGIC */
    scalar_t chain[7], tmp;
    sc_montmul(chain[0],a,sc_r2);
    
    unsigned int i,j;
    /* Addition chain generated by a not-too-clever SAGE script.  First part: compute a^(2^222-1) */
    const struct { uint8_t widx, sidx, sct, midx; } muls [] = {
        {2,0,1,0}, {3,2,1,0}, {4,3,1,0}, {5,4,1,0}, /* 0x3,7,f,1f */
        {1,5,1,0}, {1,1,3,3}, {6,1,9,1}, {1,6,1,0}, {6,1,18,6}, /* a^(2^37-1) */
        {1,6,37,6}, {1,1,37,6}, {1,1,111,1} /* a^(2^222-1) */
    };
    /* Second part: sliding window */
    const struct { uint8_t sct, midx; } muls1 [] = {
        {6, 5}, {4, 2}, {3, 0}, {2, 0}, {4, 0}, {8, 5},
        {2, 0}, {5, 3}, {4, 0}, {4, 0}, {5, 3}, {3, 2},
        {3, 2}, {3, 2}, {2, 0}, {3, 0}, {4, 2}, {2, 0},
        {4, 3}, {3, 2}, {2, 0}, {3, 2}, {5, 2}, {3, 2},
        {2, 0}, {3, 0}, {7, 0}, {5, 0}, {3, 2}, {3, 2},
        {4, 2}, {5, 0}, {5, 3}, {3, 0}, {2, 0}, {5, 2},
        {4, 3}, {4, 0}, {3, 2}, {7, 4}, {2, 0}, {2, 0},
        {2, 0}, {2, 0}, {3, 0}, {5, 2}, {5, 4}, {5, 2},
        {5, 0}, {2, 0}, {3, 0}, {3, 0}, {2, 0}, {2, 0},
        {2, 0}, {3, 2}, {2, 0}, {3, 2}, {5, 0}, {4, 0},
        {6, 4}, {4, 0}
    };
    
    for (i=0; i<sizeof(muls)/sizeof(muls[0]); i++) {
        sc_montsqr(tmp, chain[muls[i].sidx]);
        for (j=1; j<muls[i].sct; j++) {
            sc_montsqr(tmp, tmp);
        }
        sc_montmul(chain[muls[i].widx], tmp, chain[muls[i].midx]);
    }
    
    for (i=0; i<sizeof(muls1)/sizeof(muls1[0]); i++) {
        sc_montsqr(tmp, chain[1]);
        for (j=1; j<muls1[i].sct; j++) {
            sc_montsqr(tmp, tmp);
        }
        sc_montmul(chain[1], tmp, chain[muls1[i].midx]);
    }
    
    sc_montmul(out,chain[1],API_NS(scalar_one));
    for (i=0; i<sizeof(chain)/sizeof(chain[0]); i++) {
        API_NS(scalar_destroy)(chain[i]);
    }
    return ~API_NS(scalar_eq)(out,API_NS(scalar_zero));
}

void API_NS(scalar_sub) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    sc_subx(out, a->limb, b, sc_p, 0);
}

void API_NS(scalar_add) (
    scalar_t out,
    const scalar_t a,
    const scalar_t b
) {
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + b->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    sc_subx(out, out->limb, sc_p, sc_p, chain);
}

snv sc_halve (
    scalar_t out,
    const scalar_t a,
    const scalar_t p
) {
    decaf_word_t mask = -(a->limb[0] & 1);
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + (p->limb[i] & mask);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    for (i=0; i<SCALAR_LIMBS-1; i++) {
        out->limb[i] = out->limb[i]>>1 | out->limb[i+1]<<(WBITS-1);
    }
    out->limb[i] = out->limb[i]>>1 | chain<<(WBITS-1);
}

void API_NS(scalar_set) (
    scalar_t out,
    decaf_word_t w
) {
    memset(out,0,sizeof(scalar_t));
    out->limb[0] = w;
}

decaf_bool_t API_NS(scalar_eq) (
    const scalar_t a,
    const scalar_t b
) {
    decaf_word_t diff = 0;
    unsigned int i;
    for (i=0; i<SCALAR_LIMBS; i++) {
        diff |= a->limb[i] ^ b->limb[i];
    }
    return (((decaf_dword_t)diff)-1)>>WBITS;
}

/* *** API begins here *** */    

/** identity = (0,1) */
const point_t API_NS(point_identity) = {{{{{0}}},{{{1}}},{{{1}}},{{{0}}}}};

static void gf_encode ( unsigned char ser[SER_BYTES], gf a ) {
    field_serialize(ser, (field_t *)a);
}

void API_NS(point_encode)( unsigned char ser[SER_BYTES], const point_t p ) {
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
    gf_encode(ser, a);
}

/**
 * Deserialize a bool, return TRUE if < p.
 */
static decaf_bool_t gf_deser(gf s, const unsigned char ser[SER_BYTES]) {
    return field_deserialize((field_t *)s, ser);
}
    
decaf_bool_t API_NS(point_decode) (
    point_t p,
    const unsigned char ser[SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, a, b, c, d;
    decaf_bool_t succ = gf_deser(s, ser), zero = gf_eq(s, ZERO);
    succ &= allow_identity | ~zero;
    succ &= ~hibit(s);
    gf_sqr ( a, s );
    gf_sub ( p->z, ONE, a );
    gf_sqr ( b, p->z ); 
    gf_mlw ( c, a, 4-4*EDWARDS_D );
    gf_add ( c, c, b );
    gf_mul ( b, c, a );
    succ &= gf_isqrt_chk ( d, b, DECAF_TRUE );
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

void API_NS(point_sub) (
    point_t p,
    const point_t q,
    const point_t r
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
    
void API_NS(point_add) (
    point_t p,
    const point_t q,
    const point_t r
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

snv point_double_internal (
    point_t p,
    const point_t q,
    decaf_bool_t before_double
) {
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
    if (!before_double) gf_mul ( p->t, b, d );
}

void API_NS(point_double)(point_t p, const point_t q) {
    point_double_internal(p,q,0);
}

void API_NS(point_negate) (
   point_t nega,
   const point_t a
) {
    gf_sub(nega->x, ZERO, a->x);
    gf_cpy(nega->y, a->y);
    gf_cpy(nega->z, a->z);
    gf_sub(nega->t, ZERO, a->t);
}

siv scalar_decode_short (
    scalar_t s,
    const unsigned char ser[SER_BYTES],
    unsigned int nbytes
) {
    unsigned int i,j,k=0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t) && k<nbytes; j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
}

decaf_bool_t API_NS(scalar_decode)(
    scalar_t s,
    const unsigned char ser[SER_BYTES]
) {
    unsigned int i;
    scalar_decode_short(s, ser, SER_BYTES);
    decaf_sdword_t accum = 0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - sc_p->limb[i]) >> WBITS;
    }
    
    sc_montmul(s,s,sc_r1); /* ham-handed reduce */
    
    return accum;
}

void decaf_bzero (
    void *s,
    size_t size
) {
#ifdef __STDC_LIB_EXT1__
    memset_s(s, size, 0, size);
#else
    const size_t sw = sizeof(decaf_word_t);
    volatile uint8_t *destroy = (volatile uint8_t *)s;
    for (; size && ((uintptr_t)destroy)%sw; size--, destroy++)
        *destroy = 0;
    for (; size >= sw; size -= sw, destroy += sw)
        *(volatile decaf_word_t *)destroy = 0;
    for (; size; size--, destroy++)
        *destroy = 0;
#endif
}


void API_NS(scalar_destroy) (
    scalar_t scalar
) {
    decaf_bzero(scalar, sizeof(scalar_t));
}

static inline void ignore_result ( decaf_bool_t boo ) {
    (void)boo;
}

void API_NS(scalar_decode_long)(
    scalar_t s,
    const unsigned char *ser,
    size_t ser_len
) {
    if (ser_len == 0) {
        API_NS(scalar_copy)(s, API_NS(scalar_zero));
        return;
    }
    
    size_t i;
    scalar_t t1, t2;

    i = ser_len - (ser_len%SER_BYTES);
    if (i==ser_len) i -= SER_BYTES;
    
    scalar_decode_short(t1, &ser[i], ser_len-i);

    if (ser_len == sizeof(scalar_t)) {
        assert(i==0);
        /* ham-handed reduce */
        sc_montmul(s,t1,sc_r1);
        API_NS(scalar_destroy)(t1);
        return;
    }

    while (i) {
        i -= SER_BYTES;
        sc_montmul(t1,t1,sc_r2);
        ignore_result( API_NS(scalar_decode)(t2, ser+i) );
        API_NS(scalar_add)(t1, t1, t2);
    }

    API_NS(scalar_copy)(s, t1);
    API_NS(scalar_destroy)(t1);
    API_NS(scalar_destroy)(t2);
}

void API_NS(scalar_encode)(
    unsigned char ser[SER_BYTES],
    const scalar_t s
) {
    unsigned int i,j,k=0;
    for (i=0; i<SCALAR_LIMBS; i++) {
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            ser[k] = s->limb[i] >> (8*j);
        }
    }
}

/* Operations on [p]niels */
siv cond_neg_niels (
    niels_t n,
    decaf_bool_t neg
) {
    cond_swap(n->a, n->b, neg);
    cond_neg(n->c, neg);
}

static void pt_to_pniels (
    pniels_t b,
    const point_t a
) {
    gf_sub ( b->n->a, a->y, a->x );
    gf_add ( b->n->b, a->x, a->y );
    gf_mlw ( b->n->c, a->t, 2*EDWARDS_D-2 );
    gf_add ( b->z, a->z, a->z );
}

static void pniels_to_pt (
    point_t e,
    const pniels_t d
) {
    gf eu;
    gf_add ( eu, d->n->b, d->n->a );
    gf_sub ( e->y, d->n->b, d->n->a );
    gf_mul ( e->t, e->y, eu);
    gf_mul ( e->x, d->z, e->y );
    gf_mul ( e->y, d->z, eu );
    gf_sqr ( e->z, d->z );
}

snv niels_to_pt (
    point_t e,
    const niels_t n
) {
    gf_add ( e->y, n->b, n->a );
    gf_sub ( e->x, n->b, n->a );
    gf_mul ( e->t, e->y, e->x );
    gf_cpy ( e->z, ONE );
}

snv add_niels_to_pt (
    point_t d,
    const niels_t e,
    decaf_bool_t before_double
) {
    gf a, b, c;
    gf_sub_nr ( b, d->y, d->x );
    gf_mul ( a, e->a, b );
    gf_add_nr ( b, d->x, d->y );
    gf_mul ( d->y, e->b, b );
    gf_mul ( d->x, e->c, d->t );
    gf_add_nr ( c, a, d->y );
    gf_sub_nr ( b, d->y, a );
    gf_sub_nr ( d->y, d->z, d->x );
    gf_add_nr ( a, d->x, d->z );
    gf_mul ( d->z, a, d->y );
    gf_mul ( d->x, d->y, b );
    gf_mul ( d->y, a, c );
    if (!before_double) gf_mul ( d->t, b, c );
}

snv sub_niels_from_pt (
    point_t d,
    const niels_t e,
    decaf_bool_t before_double
) {
    gf a, b, c;
    gf_sub_nr ( b, d->y, d->x );
    gf_mul ( a, e->b, b );
    gf_add_nr ( b, d->x, d->y );
    gf_mul ( d->y, e->a, b );
    gf_mul ( d->x, e->c, d->t );
    gf_add_nr ( c, a, d->y );
    gf_sub_nr ( b, d->y, a );
    gf_add_nr ( d->y, d->z, d->x );
    gf_sub_nr ( a, d->z, d->x );
    gf_mul ( d->z, a, d->y );
    gf_mul ( d->x, d->y, b );
    gf_mul ( d->y, a, c );
    if (!before_double) gf_mul ( d->t, b, c );
}

sv add_pniels_to_pt (
    point_t p,
    const pniels_t pn,
    decaf_bool_t before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_cpy ( p->z, L0 );
    add_niels_to_pt( p, pn->n, before_double );
}

sv sub_pniels_from_pt (
    point_t p,
    const pniels_t pn,
    decaf_bool_t before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_cpy ( p->z, L0 );
    sub_niels_from_pt( p, pn->n, before_double );
}

extern const scalar_t API_NS(point_scalarmul_adjustment);

/* TODO: get rid of big_register_t dependencies? */
siv constant_time_lookup_xx (
    void *__restrict__ out_,
    const void *table_,
    decaf_word_t elem_bytes,
    decaf_word_t n_table,
    decaf_word_t idx
) {
    big_register_t big_one = br_set_to_mask(1), big_i = br_set_to_mask(idx);
    big_register_t *out = (big_register_t *)out_;
    const unsigned char *table = (const unsigned char *)table_;
    word_t j,k;
    
    big_register_t br_mask = br_is_zero(big_i);
    for (k=0; k<elem_bytes/sizeof(big_register_t); k++)
        out[k] = br_mask & *(const big_register_t*)(&table[k*sizeof(big_register_t)]);
    big_i-=big_one;
    for (j=1; j<n_table; j++, big_i-=big_one) {
        br_mask = br_is_zero(big_i);
        for (k=0; k<elem_bytes/sizeof(big_register_t); k++) {
            out[k] |= br_mask & *(const big_register_t*)(&table[k*sizeof(big_register_t)+j*elem_bytes]);
        }
    }
}

snv prepare_fixed_window(
    pniels_t *multiples,
    const point_t b,
    int ntable
) {
    point_t tmp;
    pniels_t pn;
    int i;
    
    point_double_internal(tmp, b, 0);
    pt_to_pniels(pn, tmp);
    pt_to_pniels(multiples[0], b);
    API_NS(point_copy)(tmp, b);
    for (i=1; i<ntable; i++) {
        add_pniels_to_pt(tmp, pn, 0);
        pt_to_pniels(multiples[i], tmp);
    }
}

void API_NS(point_scalarmul) (
    point_t a,
    const point_t b,
    const scalar_t scalar
) {
    const int WINDOW = DECAF_WINDOW_BITS,
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    scalar_t scalar1x;
    API_NS(scalar_add)(scalar1x, scalar, API_NS(point_scalarmul_adjustment));
    sc_halve(scalar1x,scalar1x,sc_p);
    
    /* Set up a precomputed table with odd multiples of b. */
    pniels_t pn, multiples[NTABLE];
    point_t tmp;
    prepare_fixed_window(multiples, b, NTABLE);

    /* Initialize. */
    int i,j,first=1;
    i = SCALAR_BITS - ((SCALAR_BITS-1) % WINDOW) - 1;

    for (; i>=0; i-=WINDOW) {
        /* Fetch another block of bits */
        decaf_word_t bits = scalar1x->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW && i/WBITS<SCALAR_LIMBS-1) {
            bits ^= scalar1x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits &= WINDOW_MASK;
        decaf_word_t inv = (bits>>(WINDOW-1))-1;
        bits ^= inv;
    
        /* Add in from table.  Compute t only on last iteration. */
        constant_time_lookup_xx(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv);
        if (first) {
            pniels_to_pt(tmp, pn);
            first = 0;
        } else {
           /* Using Hisil et al's lookahead method instead of extensible here
            * for no particular reason.  Double WINDOW times, but only compute t on
            * the last one.
            */
            for (j=0; j<WINDOW-1; j++)
                point_double_internal(tmp, tmp, -1);
            point_double_internal(tmp, tmp, 0);
            add_pniels_to_pt(tmp, pn, i ? -1 : 0);
        }
    }
    
    /* Write out the answer */
    API_NS(point_copy)(a,tmp);
}

void API_NS(point_double_scalarmul) (
    point_t a,
    const point_t b,
    const scalar_t scalarb,
    const point_t c,
    const scalar_t scalarc
) {
    const int WINDOW = DECAF_WINDOW_BITS,
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    scalar_t scalar1x, scalar2x;
    API_NS(scalar_add)(scalar1x, scalarb, API_NS(point_scalarmul_adjustment));
    sc_halve(scalar1x,scalar1x,sc_p);
    API_NS(scalar_add)(scalar2x, scalarc, API_NS(point_scalarmul_adjustment));
    sc_halve(scalar2x,scalar2x,sc_p);
    
    /* Set up a precomputed table with odd multiples of b. */
    pniels_t pn, multiples1[NTABLE], multiples2[NTABLE];
    point_t tmp;
    prepare_fixed_window(multiples1, b, NTABLE);
    prepare_fixed_window(multiples2, c, NTABLE);

    /* Initialize. */
    int i,j,first=1;
    i = SCALAR_BITS - ((SCALAR_BITS-1) % WINDOW) - 1;

    for (; i>=0; i-=WINDOW) {
        /* Fetch another block of bits */
        decaf_word_t bits1 = scalar1x->limb[i/WBITS] >> (i%WBITS),
                     bits2 = scalar2x->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW && i/WBITS<SCALAR_LIMBS-1) {
            bits1 ^= scalar1x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
            bits2 ^= scalar2x->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits1 &= WINDOW_MASK;
        bits2 &= WINDOW_MASK;
        decaf_word_t inv1 = (bits1>>(WINDOW-1))-1;
        decaf_word_t inv2 = (bits2>>(WINDOW-1))-1;
        bits1 ^= inv1;
        bits2 ^= inv2;
    
        /* Add in from table.  Compute t only on last iteration. */
        constant_time_lookup_xx(pn, multiples1, sizeof(pn), NTABLE, bits1 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv1);
        if (first) {
            pniels_to_pt(tmp, pn);
            first = 0;
        } else {
           /* Using Hisil et al's lookahead method instead of extensible here
            * for no particular reason.  Double WINDOW times, but only compute t on
            * the last one.
            */
            for (j=0; j<WINDOW-1; j++)
                point_double_internal(tmp, tmp, -1);
            point_double_internal(tmp, tmp, 0);
            add_pniels_to_pt(tmp, pn, 0);
        }
        constant_time_lookup_xx(pn, multiples2, sizeof(pn), NTABLE, bits2 & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv2);
        add_pniels_to_pt(tmp, pn, i?-1:0);
    }
    
    /* Write out the answer */
    API_NS(point_copy)(a,tmp);
}

decaf_bool_t API_NS(point_eq) ( const point_t p, const point_t q ) {
    /* equality mod 2-torsion compares x/y */
    gf a, b;
    gf_mul ( a, p->y, q->x );
    gf_mul ( b, q->y, p->x );
    return gf_eq(a,b);
}

void API_NS(point_from_hash_nonuniform) (
    point_t p,
    const unsigned char ser[SER_BYTES]
) {
    gf r,urr,a,b,c,dee,e,ur2_d,udr2_1;
    (void)gf_deser(r,ser);
    gf_canon(r);
    gf_sqr(a,r);
    /* gf_mlw(urr,a,QUADRATIC_NONRESIDUE); */
    gf_sub(urr,ZERO,a);
    gf_mlw(dee,ONE,EDWARDS_D);
    gf_add(a,urr,ONE);
    gf_sub(ur2_d,dee,urr);
    gf_mul(c,a,ur2_d);
    gf_mlw(b,urr,-EDWARDS_D);
    gf_add(udr2_1,b,ONE);
    gf_mul(a,c,udr2_1);
    gf_mlw(c,a,EDWARDS_D+1);
    decaf_bool_t square = gf_isqrt_chk(b,c,DECAF_FALSE);
    /* FIELD: if 5 mod 8, multiply result by u. */
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

void API_NS(point_from_hash_uniform) (
    point_t pt,
    const unsigned char hashed_data[2*SER_BYTES]
) {
    point_t pt2;
    API_NS(point_from_hash_nonuniform)(pt,hashed_data);
    API_NS(point_from_hash_nonuniform)(pt2,&hashed_data[SER_BYTES]);
    API_NS(point_add)(pt,pt,pt2);
}

decaf_bool_t API_NS(point_valid) (
    const point_t p
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

static void gf_batch_invert (
    gf *__restrict__ out,
    /* const */ gf *in,
    unsigned int n
) {
    gf t1;
    assert(n>1);
  
    gf_cpy(out[1], in[0]);
    int i;
    for (i=1; i<(int) (n-1); i++) {
        gf_mul(out[i+1], out[i], in[i]);
    }
    gf_mul(out[0], out[n-1], in[n-1]);

    gf_invert(out[0], out[0]);

    for (i=n-1; i>0; i--) {
        gf_mul(t1, out[i], out[0]);
        gf_cpy(out[i], t1);
        gf_mul(t1, out[0], in[i]);
        gf_cpy(out[0], t1);
    }
}

static void batch_normalize_niels (
    niels_t *table,
    gf *zs,
    gf *zis,
    int n
) {
    int i;
    gf product;
    gf_batch_invert(zis, zs, n);

    for (i=0; i<n; i++) {
        gf_mul(product, table[i]->a, zis[i]);
        gf_canon(product);
        gf_cpy(table[i]->a, product);
        
        gf_mul(product, table[i]->b, zis[i]);
        gf_canon(product);
        gf_cpy(table[i]->b, product);
        
        gf_mul(product, table[i]->c, zis[i]);
        gf_canon(product);
        gf_cpy(table[i]->c, product);
    }
}

void API_NS(precompute) (
    precomputed_s *table,
    const point_t base
) { 
    const unsigned int n = DECAF_COMBS_N, t = DECAF_COMBS_T, s = DECAF_COMBS_S;
    assert(n*t*s >= SCALAR_BITS);
  
    point_t working, start, doubles[t-1];
    API_NS(point_copy)(working, base);
    pniels_t pn_tmp;
  
    gf zs[n<<(t-1)], zis[n<<(t-1)];
  
    unsigned int i,j,k;
    
    /* Compute n tables */
    for (i=0; i<n; i++) {

        /* Doubling phase */
        for (j=0; j<t; j++) {
            if (j) API_NS(point_add)(start, start, working);
            else API_NS(point_copy)(start, working);

            if (j==t-1 && i==n-1) break;

            point_double_internal(working, working,0);
            if (j<t-1) API_NS(point_copy)(doubles[j], working);

            for (k=0; k<s-1; k++)
                point_double_internal(working, working, k<s-2);
        }

        /* Gray-code phase */
        for (j=0;; j++) {
            int gray = j ^ (j>>1);
            int idx = (((i+1)<<(t-1))-1) ^ gray;

            pt_to_pniels(pn_tmp, start);
            memcpy(table->table[idx], pn_tmp->n, sizeof(pn_tmp->n));
            gf_cpy(zs[idx], pn_tmp->z);
			
            if (j >= (1u<<(t-1)) - 1) break;
            int delta = (j+1) ^ ((j+1)>>1) ^ gray;

            for (k=0; delta>1; k++)
                delta >>=1;
            
            if (gray & (1<<k)) {
                API_NS(point_add)(start, start, doubles[k]);
            } else {
                API_NS(point_sub)(start, start, doubles[k]);
            }
        }
    }
    
    batch_normalize_niels(table->table,zs,zis,n<<(t-1));
}

extern const scalar_t API_NS(precomputed_scalarmul_adjustment);

siv constant_time_lookup_xx_niels (
    niels_s *__restrict__ ni,
    const niels_t *table,
    int nelts,
    int idx
) {
    constant_time_lookup_xx(ni, table, sizeof(niels_s), nelts, idx);
}

void API_NS(precomputed_scalarmul) (
    point_t out,
    const precomputed_s *table,
    const scalar_t scalar
) {
    int i;
    unsigned j,k;
    const unsigned int n = DECAF_COMBS_N, t = DECAF_COMBS_T, s = DECAF_COMBS_S;
    
    scalar_t scalar1x;
    API_NS(scalar_add)(scalar1x, scalar, API_NS(precomputed_scalarmul_adjustment));
    sc_halve(scalar1x,scalar1x,sc_p);
    
    niels_t ni;
    
    for (i=s-1; i>=0; i--) {
        if (i != (int)s-1) point_double_internal(out,out,0);
        
        for (j=0; j<n; j++) {
            int tab = 0;
         
            for (k=0; k<t; k++) {
                unsigned int bit = i + s*(k + j*t);
                if (bit < SCALAR_BITS) {
                    tab |= (scalar1x->limb[bit/WBITS] >> (bit%WBITS) & 1) << k;
                }
            }
            
            decaf_bool_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;

            constant_time_lookup_xx_niels(ni, &table->table[j<<(t-1)], 1<<(t-1), tab);

            cond_neg_niels(ni, invert);
            if ((i!=s-1)||j) {
                add_niels_to_pt(out, ni, j==n-1 && i);
            } else {
                niels_to_pt(out, ni);
            }
        }
    }
}

#if DECAF_USE_MONTGOMERY_LADDER
/** Return high bit of x/2 = low bit of x mod p */
static inline decaf_word_t lobit(gf x) {
    gf_canon(x);
    return -(x->limb[0]&1);
}

decaf_bool_t API_NS(direct_scalarmul) (
    uint8_t scaled[SER_BYTES],
    const uint8_t base[SER_BYTES],
    const scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) {
    /* The Montgomery ladder does not short-circuit return on invalid points,
     * since it detects them during recompress.
     */
    (void)short_circuit;
    
    gf s0, x0, xa, za, xd, zd, xs, zs, L0, L1;
    decaf_bool_t succ = gf_deser ( s0, base );
    succ &= allow_identity |~ gf_eq( s0, ZERO);

    /* Prepare the Montgomery ladder: Q = 1:0, P+Q = P */
    gf_sqr ( xa, s0 );
    gf_cpy ( x0, xa );
    gf_cpy ( za, ONE );
    gf_cpy ( xd, ONE );
    gf_cpy ( zd, ZERO );
    
    int j;
    decaf_bool_t pflip = 0;
    for (j=SCALAR_BITS+1; j>=0; j--) {
        /* FIXME: -1, but the test cases use too many bits */
        
        /* Augmented Montgomery ladder */
        decaf_bool_t flip = -((scalar->limb[j/WBITS]>>(j%WBITS))&1);
        
        /* Differential add first... */
        gf_add_nr ( xs, xa, za );
        gf_sub_nr ( zs, xa, za );
        gf_add_nr ( xa, xd, zd );
        gf_sub_nr ( za, xd, zd );
        
        cond_sel(L0,xa,xs,flip^pflip);
        cond_sel(L1,za,zs,flip^pflip);
        
        gf_mul ( xd, xa, zs );
        gf_mul ( zd, xs, za );
        gf_add_nr ( xs, xd, zd );
        gf_sub_nr ( zd, xd, zd );
        gf_mul ( zs, zd, s0 );
        gf_sqr ( xa, xs );
        gf_sqr ( za, zs );
        
        /* ... and then double */
        gf_sqr ( zd, L0 );
        gf_sqr ( L0, L1 );
        gf_sub_nr ( L1, zd, L0 );
        gf_mul ( xd, L0, zd );
        gf_mlw ( zd, L1, 1-EDWARDS_D );
        gf_add_nr ( L0, L0, zd );
        gf_mul ( zd, L0, L1 );
        
        pflip = flip;
    }
    cond_swap(xa,xd,pflip);
    cond_swap(za,zd,pflip);
    
    /* OK, time to reserialize! Should be easy (heh, but seriously, TODO: simplify) */
    gf xz_d, xz_a, xz_s, den, L2, L3;
    mask_t zcase, output_zero, sflip, za_zero;
    gf_mul(xz_s, xs, zs);
    gf_mul(xz_d, xd, zd);
    gf_mul(xz_a, xa, za);
    output_zero = gf_eq(xz_d, ZERO);
    xz_d->limb[0] -= output_zero; /* make xz_d always nonzero */
    zcase = output_zero | gf_eq(xz_a, ZERO);
    za_zero = gf_eq(za, ZERO);

    /* Curve test in zcase, compute x0^2 + (2d-4)x0 + 1
     * (we know that x0 = s0^2 is square).
     */
    gf_add(L0,x0,ONE);
    gf_sqr(L1,L0);
    gf_mlw(L0,x0,-4*EDWARDS_D);
    gf_add(L1,L1,L0);
    cond_sel(xz_a,xz_a,L1,zcase);

    /* Compute denominator = x0 xa za xd zd */
    gf_mul(L0, x0, xz_a);
    gf_mul(L1, L0, xz_d);
    gf_isqrt(den, L1);

    /* Check that the square root came out OK. */
    gf_sqr(L2, den);
    gf_mul(L3, L0, L2); /* x0 xa za den^2 = 1/xz_d, for later */
    gf_mul(L0, L1, L2);
    gf_add(L0, L0, ONE);
    succ &= ~hibit(s0) & ~gf_eq(L0, ZERO);

    /* Compute y/x for input and output point. */
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
    sflip = (lobit(L1) ^ lobit(L2)) | za_zero;
    /* OK, done with y-coordinates */
    
    /* If xa==0 or za ==0: return 0
     * Else if za == 0: return s0           * (sflip ? zd : xd)^2 * L3
     * Else if zd == 0: return s0           * (sflip ? zd : xd)^2 * L3
     * Else if pflip:   return      xs * zs * (sflip ? zd : xd)   * L3
     * Else:            return s0 * xs * zs * (sflip ? zd : xd)   * den
     */
    cond_sel(xd, xd, zd, sflip); /* xd = actual xd we care about */
    cond_sel(den,den,L3,pflip|zcase);
    cond_sel(xz_s,xz_s,xd,zcase);
    cond_sel(s0,s0,ONE,pflip&~zcase);
    cond_sel(s0,s0,ZERO,output_zero);
    
    gf_mul(L0,xd,den);
    gf_mul(L1,L0,s0);
    gf_mul(L0,L1,xz_s);
    
    cond_neg(L0,hibit(L0));
    gf_encode(scaled, L0);

    return succ;
}
#else /* DECAF_USE_MONTGOMERY_LADDER */
decaf_bool_t API_NS(direct_scalarmul) (
    uint8_t scaled[SER_BYTES],
    const uint8_t base[SER_BYTES],
    const scalar_t scalar,
    decaf_bool_t allow_identity,
    decaf_bool_t short_circuit
) {
    point_t basep;
    decaf_bool_t succ = API_NS(point_decode)(basep, base, allow_identity);
    if (short_circuit & ~succ) return succ;
    API_NS(point_scalarmul)(basep, basep, scalar);
    API_NS(point_encode)(scaled, basep);
    return succ;
}
#endif /* DECAF_USE_MONTGOMERY_LADDER */

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int recode_wnaf (
    struct smvt_control *control, /* [nbits/(tableBits+1) + 3] */
    const scalar_t scalar,
    unsigned int tableBits
) {
    int current = 0, i, j;
    unsigned int position = 0;

    /* PERF: negate scalar if it's large
     * PERF: this is a pretty simplistic algorithm.  I'm sure there's a faster one...
     * PERF MINOR: not technically WNAF, since last digits can be adjacent.  Could be rtl.
     */
    for (i=SCALAR_BITS-1; i >= 0; i--) {
        int bit = (scalar->limb[i/WORD_BITS] >> (i%WORD_BITS)) & 1;
        current = 2*current + bit;

        /*
         * Sizing: |current| >= 2^(tableBits+1) -> |current| = 2^0
         * So current loses (tableBits+1) bits every time.  It otherwise gains
         * 1 bit per iteration.  The number of iterations is
         * (nbits + 2 + tableBits), and an additional control word is added at
         * the end.  So the total number of control words is at most
         * ceil((nbits+1) / (tableBits+1)) + 2 = floor((nbits)/(tableBits+1)) + 2.
         * There's also the stopper with power -1, for a total of +3.
         */
        if (current >= (2<<tableBits) || current <= -1 - (2<<tableBits)) {
            int delta = (current + 1) >> 1; /* |delta| < 2^tablebits */
            current = -(current & 1);

            for (j=i; (delta & 1) == 0; j++) {
                delta >>= 1;
            }
            control[position].power = j+1;
            control[position].addend = delta;
            position++;
            assert(position <= SCALAR_BITS/(tableBits+1) + 2);
        }
    }
    
    if (current) {
        for (j=0; (current & 1) == 0; j++) {
            current >>= 1;
        }
        control[position].power = j;
        control[position].addend = current;
        position++;
        assert(position <= SCALAR_BITS/(tableBits+1) + 2);
    }
    
  
    control[position].power = -1;
    control[position].addend = 0;
    return position;
}

sv prepare_wnaf_table(
    pniels_t *output,
    const point_t working,
    unsigned int tbits
) {
    point_t tmp;
    int i;
    pt_to_pniels(output[0], working);

    if (tbits == 0) return;

    API_NS(point_double)(tmp,working);
    pniels_t twop;
    pt_to_pniels(twop, tmp);

    add_pniels_to_pt(tmp, output[0],0);
    pt_to_pniels(output[1], tmp);

    for (i=2; i < 1<<tbits; i++) {
        add_pniels_to_pt(tmp, twop,0);
        pt_to_pniels(output[i], tmp);
    }
}

extern const decaf_word_t API_NS(precomputed_wnaf_as_words)[];
static const niels_t *API_NS(wnaf_base) = (const niels_t *)API_NS(precomputed_wnaf_as_words);
const size_t API_NS2(sizeof,precomputed_wnafs) __attribute((visibility("hidden")))
    = sizeof(niels_t)<<DECAF_WNAF_FIXED_TABLE_BITS;

void API_NS(precompute_wnafs) (
    niels_t out[1<<DECAF_WNAF_FIXED_TABLE_BITS],
    const point_t base
) __attribute__ ((visibility ("hidden")));

void API_NS(precompute_wnafs) (
    niels_t out[1<<DECAF_WNAF_FIXED_TABLE_BITS],
    const point_t base
) {
    pniels_t tmp[1<<DECAF_WNAF_FIXED_TABLE_BITS];
    gf zs[1<<DECAF_WNAF_FIXED_TABLE_BITS], zis[1<<DECAF_WNAF_FIXED_TABLE_BITS];
    int i;
    prepare_wnaf_table(tmp,base,DECAF_WNAF_FIXED_TABLE_BITS);
    for (i=0; i<1<<DECAF_WNAF_FIXED_TABLE_BITS; i++) {
        memcpy(out[i], tmp[i]->n, sizeof(niels_t));
        gf_cpy(zs[i], tmp[i]->z);
    }
    batch_normalize_niels(out, zs, zis, 1<<DECAF_WNAF_FIXED_TABLE_BITS);
}

void API_NS(base_double_scalarmul_non_secret) (
    point_t combo,
    const scalar_t scalar1,
    const point_t base2,
    const scalar_t scalar2
) {
    const int table_bits_var = DECAF_WNAF_VAR_TABLE_BITS,
        table_bits_pre = DECAF_WNAF_FIXED_TABLE_BITS;
    struct smvt_control control_var[SCALAR_BITS/(table_bits_var+1)+3];
    struct smvt_control control_pre[SCALAR_BITS/(table_bits_pre+1)+3];
    
    int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
    int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  
    pniels_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, base2, table_bits_var);
  
    int contp=0, contv=0, i = control_var[0].power;

    if (i < 0) {
        API_NS(point_copy)(combo, API_NS(point_identity));
        return;
    } else if (i > control_pre[0].power) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1], i);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        niels_to_pt(combo, API_NS(wnaf_base)[control_pre[0].addend >> 1]);
        contp++;
    }
    
    for (i--; i >= 0; i--) {
        int cv = (i==control_var[contv].power), cp = (i==control_pre[contp].power);
        point_double_internal(combo,combo,i && !(cv||cp));

        if (cv) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                add_pniels_to_pt(combo, precmp_var[control_var[contv].addend >> 1], i&&!cp);
            } else {
                sub_pniels_from_pt(combo, precmp_var[(-control_var[contv].addend) >> 1], i&&!cp);
            }
            contv++;
        }

        if (cp) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                add_niels_to_pt(combo, API_NS(wnaf_base)[control_pre[contp].addend >> 1], i);
            } else {
                sub_niels_from_pt(combo, API_NS(wnaf_base)[(-control_pre[contp].addend) >> 1], i);
            }
            contp++;
        }
    }

    assert(contv == ncb_var); (void)ncb_var;
    assert(contp == ncb_pre); (void)ncb_pre;
}

void API_NS(point_destroy) (
  point_t point
) {
    decaf_bzero(point, sizeof(point_t));
}

void API_NS(precomputed_destroy) (
  precomputed_s *pre
) {
    decaf_bzero(pre, API_NS2(sizeof,precomputed_s));
}
