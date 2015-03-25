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

//static const int QUADRATIC_NONRESIDUE = -1;

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

static const decaf_448_scalar_t decaf_448_scalar_r1 = {{{
    SC_LIMB(0x721cf5b5529eec34),
    SC_LIMB(0x7a4cf635c8e9c2ab),
    SC_LIMB(0xeec492d944a725bf),
    SC_LIMB(0x000000020cd77058),
    SC_LIMB(0),
    SC_LIMB(0),
    SC_LIMB(0)
}}};

static const decaf_word_t DECAF_MONTGOMERY_FACTOR = (decaf_word_t)(0x3bd440fae918bc5ull);

/** base = twist of Goldilocks base point (~,19). */

const decaf_448_point_t decaf_448_point_base = {{
    {{{ LIMB(0xb39a2d57e08c7b),LIMB(0xb38639c75ff281),
        LIMB(0x2ec981082b3288),LIMB(0x99fe8607e5237c),
        LIMB(0x0e33fbb1fadd1f),LIMB(0xe714f67055eb4a),
        LIMB(0xc9ae06d64067dd),LIMB(0xf7be45054760fa) }}},
    {{{ LIMB(0xbd8715f551617f),LIMB(0x8c17fbeca8f5fc),
        LIMB(0xaae0eec209c06f),LIMB(0xce41ad80cbe6b8),
        LIMB(0xdf360b5c828c00),LIMB(0xaf25b6bbb40e3b),
        LIMB(0x8ed37f0ce4ed31),LIMB(0x72a1c3214557b9) }}},
    {{{ 1 }}},
    {{{ LIMB(0x97ca9c8ed8bde9),LIMB(0xf0b780da83304c),
        LIMB(0x0d79c0a7729a69),LIMB(0xc18d3f24aebc1c),
        LIMB(0x1fbb5389b3fda5),LIMB(0xbb24f674635948),
        LIMB(0x723a55709a3983),LIMB(0xe1c0107a823dd4) }}}
}};

/* Projective Niels coordinates */
typedef struct { gf a, b, c; } niels_s, niels_t[1];
typedef struct { niels_t n; gf z; } pniels_s, pniels_t[1];
struct decaf_448_precomputed_s { niels_t table [5<<4]; /* MAGIC */ };

extern const decaf_word_t decaf_448_precomputed_base_as_words[];
const decaf_448_precomputed_s *decaf_448_precomputed_base =
    (const decaf_448_precomputed_s *) &decaf_448_precomputed_base_as_words;

const size_t sizeof_decaf_448_precomputed_s = sizeof(decaf_448_precomputed_s);
const size_t alignof_decaf_448_precomputed_s = 32;


#ifdef __clang__
#if 100*__clang_major__ + __clang_minor__ > 305
#define VECTORIZE _Pragma("clang loop unroll(disable) vectorize(enable) vectorize_width(8)")
#endif
#endif

#ifndef VECTORIZE
#define VECTORIZE
#endif

#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}
#define FOR_LIMB_V(i,op) { unsigned int i=0; VECTORIZE for (i=0; i<DECAF_448_LIMBS; i++)  { op; }}

/** Copy x = y */
siv gf_cpy(gf x, const gf y) { FOR_LIMB_V(i, x->limb[i] = y->limb[i]); }

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
}

/** Subtract mod p. Bias by amt but don't reduce.  */
siv gf_sub_nr_x ( gf c, const gf a, const gf b, int amt ) {
    ANALYZE_THIS_ROUTINE_CAREFULLY; //TODO
    field_sub_nr((field_t *)c, (const field_t *)a, (const field_t *)b);
    gf_bias(c, amt);
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

/** Return high bit of x = low bit of 2x mod p */
static decaf_word_t hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_canon(y);
    return -(y->limb[0]&1);
}

/** Return high bit of x/2 = low bit of x mod p */
static inline decaf_word_t lobit(gf x) {
    gf_canon(x);
    return -(x->limb[0]&1);
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

/* PERF: could implement this */
siv decaf_448_montsqr (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    decaf_448_montmul(out,a,a);
}

decaf_bool_t decaf_448_scalar_invert (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a
) {
    decaf_448_scalar_t chain[7], tmp;
    decaf_448_montmul(chain[0],a,decaf_448_scalar_r2);
    
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
        decaf_448_montsqr(tmp, chain[muls[i].sidx]);
        for (j=1; j<muls[i].sct; j++) {
            decaf_448_montsqr(tmp, tmp);
        }
        decaf_448_montmul(chain[muls[i].widx], tmp, chain[muls[i].midx]);
    }
    
    for (i=0; i<sizeof(muls1)/sizeof(muls1[0]); i++) {
        decaf_448_montsqr(tmp, chain[1]);
        for (j=1; j<muls1[i].sct; j++) {
            decaf_448_montsqr(tmp, tmp);
        }
        decaf_448_montmul(chain[1], tmp, chain[muls1[i].midx]);
    }
    
    decaf_448_montmul(out,chain[1],decaf_448_scalar_one);
    for (i=0; i<sizeof(chain)/sizeof(chain[0]); i++) {
        decaf_448_scalar_destroy(chain[i]);
    }
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

snv decaf_448_halve (
    decaf_448_scalar_t out,
    const decaf_448_scalar_t a,
    const decaf_448_scalar_t p
) {
    decaf_word_t mask = -(a->limb[0] & 1);
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + (p->limb[i] & mask);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    for (i=0; i<DECAF_448_SCALAR_LIMBS-1; i++) {
        out->limb[i] = out->limb[i]>>1 | out->limb[i+1]<<(WBITS-1);
    }
    out->limb[i] = out->limb[i]>>1 | chain<<(WBITS-1);
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
const decaf_448_point_t decaf_448_point_identity = {{{{{0}}},{{{1}}},{{{1}}},{{{0}}}}};

static void gf_encode ( unsigned char ser[DECAF_448_SER_BYTES], gf a ) {
    gf_canon(a);
    int i, k=0, bits=0;
    decaf_dword_t buf=0;
    for (i=0; i<DECAF_448_LIMBS; i++) {
        buf |= (decaf_dword_t)a->limb[i]<<bits;
        for (bits += LBITS; (bits>=8 || i==DECAF_448_LIMBS-1) && k<DECAF_448_SER_BYTES; bits-=8, buf>>=8) {
            ser[k++]=buf;
        }
    }
}

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
    gf_encode(ser, a);
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
    p->y->limb[0] -= zero;
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

snv decaf_448_point_double_internal (
    decaf_448_point_t p,
    const decaf_448_point_t q,
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

void decaf_448_point_double(decaf_448_point_t p, const decaf_448_point_t q) {
    decaf_448_point_double_internal(p,q,0);
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

siv decaf_448_scalar_decode_short (
    decaf_448_scalar_t s,
    const unsigned char ser[DECAF_448_SER_BYTES],
    unsigned int nbytes
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t) && k<nbytes; j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
}

decaf_bool_t decaf_448_scalar_decode(
    decaf_448_scalar_t s,
    const unsigned char ser[DECAF_448_SER_BYTES]
) {
    unsigned int i;
    decaf_448_scalar_decode_short(s, ser, DECAF_448_SER_BYTES);
    decaf_sdword_t accum = 0;
    for (i=0; i<DECAF_448_SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - decaf_448_scalar_p->limb[i]) >> WBITS;
    }
    
    decaf_448_montmul(s,s,decaf_448_scalar_r1); /* ham-handed reduce */
    
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
    decaf_448_scalar_t t1, t2;

    i = ser_len - (ser_len%DECAF_448_SER_BYTES);
    if (i==ser_len) i -= DECAF_448_SER_BYTES;
    
    decaf_448_scalar_decode_short(t1, &ser[i], ser_len-i);

    if (ser_len == sizeof(*ser)) {
        assert(i==0);
        /* ham-handed reduce */
        decaf_448_montmul(s,t1,decaf_448_scalar_r1);
        decaf_448_scalar_destroy(t1);
        return;
    }

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
    const decaf_448_point_t a
) {
    gf_sub ( b->n->a, a->y, a->x );
    gf_add ( b->n->b, a->x, a->y );
    gf_mlw ( b->n->c, a->t, 2*EDWARDS_D-2 );
    gf_add ( b->z, a->z, a->z );
}

static void pniels_to_pt (
    decaf_448_point_t e,
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
    decaf_448_point_t e,
    const niels_t n
) {
    gf_add ( e->y, n->b, n->a );
    gf_sub ( e->x, n->b, n->a );
    gf_mul ( e->t, e->y, e->x );
    gf_cpy ( e->z, ONE );
}

snv add_niels_to_pt (
    decaf_448_point_t d,
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
    decaf_448_point_t d,
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
    decaf_448_point_t p,
    const pniels_t pn,
    decaf_bool_t before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_cpy ( p->z, L0 );
    add_niels_to_pt( p, pn->n, before_double );
}

sv sub_pniels_from_pt (
    decaf_448_point_t p,
    const pniels_t pn,
    decaf_bool_t before_double
) {
    gf L0;
    gf_mul ( L0, p->z, pn->z );
    gf_cpy ( p->z, L0 );
    sub_niels_from_pt( p, pn->n, before_double );
}

extern const decaf_448_scalar_t decaf_448_point_scalarmul_adjustment;

/* TODO: get rid of big_register_t dependencies? */
siv constant_time_lookup_xx (
    void *__restrict__ out_,
    const void *table_,
    word_t elem_bytes,
    word_t n_table,
    word_t idx
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

void decaf_448_point_scalarmul (
    decaf_448_point_t a,
    const decaf_448_point_t b,
    const decaf_448_scalar_t scalar
) {
    const int WINDOW = 5, /* PERF: Make 4 on non hugevector platforms? */
        WINDOW_MASK = (1<<WINDOW)-1,
        WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1);
        
    decaf_448_scalar_t scalar2;
    decaf_448_scalar_add(scalar2, scalar, decaf_448_point_scalarmul_adjustment);
    decaf_448_halve(scalar2,scalar2,decaf_448_scalar_p);
    
    /* Set up a precomputed table with odd multiples of b. */
    pniels_t pn, multiples[NTABLE];
    decaf_448_point_t tmp;
    decaf_448_point_double(tmp, b);
    pt_to_pniels(pn, tmp);
    pt_to_pniels(multiples[0], b);
    decaf_448_point_copy(tmp, b);

    int i,j;
    for (i=1; i<NTABLE; i++) {
        add_pniels_to_pt(tmp, pn, 0);
        pt_to_pniels(multiples[i], tmp);
    }

    /* Initialize. */
    i = DECAF_448_SCALAR_BITS - ((DECAF_448_SCALAR_BITS-1) % WINDOW) - 1;
    int bits = scalar2->limb[i/WBITS] >> (i%WBITS) & WINDOW_MASK,
        inv = (bits>>(WINDOW-1))-1;
    bits ^= inv;
    
    constant_time_lookup_xx(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
    cond_neg_niels(pn->n, inv);
    pniels_to_pt(tmp, pn);

    for (i-=WINDOW; i>=0; i-=WINDOW) {
        /* Using Hisil et al's lookahead method instead of extensible here
         * for no particular reason.  Double WINDOW times, but only compute t on
         * the last one.
         */
        for (j=0; j<WINDOW-1; j++)
            decaf_448_point_double_internal(tmp, tmp, -1);
        decaf_448_point_double(tmp, tmp);

        /* Fetch another block of bits */
        bits = scalar2->limb[i/WBITS] >> (i%WBITS);
        if (i%WBITS >= WBITS-WINDOW) {
            bits ^= scalar2->limb[i/WBITS+1] << (WBITS - (i%WBITS));
        }
        bits &= WINDOW_MASK;
        inv = (bits>>(WINDOW-1))-1;
        bits ^= inv;
    
        /* Add in from table.  Compute t only on last iteration. */
        constant_time_lookup_xx(pn, multiples, sizeof(pn), NTABLE, bits & WINDOW_T_MASK);
        cond_neg_niels(pn->n, inv);
        add_pniels_to_pt(tmp, pn, i ? -1 : 0);
    }
    
    /* Write out the answer */
    decaf_448_point_copy(a,tmp);
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

static void gf_batch_invert (
    gf *__restrict__ out,
    /* const */ gf *in,
    unsigned int n
) {
    // if (n==0) {
    //     return;
    // } else if (n==1) {
    //     field_inverse(out[0],in[0]);
    //     return;
    // }
    assert(n>1);
  
    gf_cpy(out[1], in[0]);
    int i;
    for (i=1; i<(int) (n-1); i++) {
        gf_mul(out[i+1], out[i], in[i]);
    }
    gf_mul(out[0], out[n-1], in[n-1]);

    gf t1, t2;
    gf_isqrt(t1, out[0]);
    gf_sqr(t2, t1);
    gf_sqr(t1, t2);
    gf_mul(t2, t1, out[0]);
    gf_cpy(out[0], t2);

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

void
decaf_448_precompute (
    decaf_448_precomputed_s *table,
    const decaf_448_point_t base
) { 
    const unsigned int n = 5, t = 5, s = 18; // TODO MAGIC
    assert(n*t*s >= DECAF_448_SCALAR_BITS);
  
    decaf_448_point_t working, start, doubles[t-1];
    decaf_448_point_copy(working, base);
    pniels_t pn_tmp;
  
    gf zs[n<<(t-1)], zis[n<<(t-1)];
  
    unsigned int i,j,k;
    
    /* Compute n tables */
    for (i=0; i<n; i++) {

        /* Doubling phase */
        for (j=0; j<t; j++) {
            if (j) decaf_448_point_add(start, start, working);
            else decaf_448_point_copy(start, working);

            if (j==t-1 && i==n-1) break;

            decaf_448_point_double(working, working);
            if (j<t-1) decaf_448_point_copy(doubles[j], working);

            for (k=0; k<s-1; k++)
                decaf_448_point_double_internal(working, working, k<s-2);
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
                decaf_448_point_add(start, start, doubles[k]);
            } else {
                decaf_448_point_sub(start, start, doubles[k]);
            }
        }
    }
    
    batch_normalize_niels(table->table,zs,zis,n<<(t-1));
}

extern const decaf_448_scalar_t decaf_448_precomputed_scalarmul_adjustment;

siv constant_time_lookup_niels (
    niels_s *__restrict__ ni,
    const niels_t *table,
    int nelts,
    int idx
) {
    constant_time_lookup_xx(ni, table, sizeof(niels_s), nelts, idx);
}

void decaf_448_precomputed_scalarmul (
    decaf_448_point_t out,
    const decaf_448_precomputed_s *table,
    const decaf_448_scalar_t scalar
) {
    int i;
    unsigned j,k;
    const unsigned int n = 5, t = 5, s = 18; // TODO MAGIC
    
    decaf_448_scalar_t scalar1x;
    decaf_448_scalar_add(scalar1x, scalar, decaf_448_precomputed_scalarmul_adjustment);
    decaf_448_halve(scalar1x,scalar1x,decaf_448_scalar_p);
    
    niels_t ni;
    
    for (i=s-1; i>=0; i--) {
        if (i != (int)s-1) decaf_448_point_double(out,out);
        
        for (j=0; j<n; j++) {
            int tab = 0;
         
            for (k=0; k<t; k++) {
                unsigned int bit = i + s*(k + j*t);
                if (bit < SCALAR_WORDS * WBITS) {
                    tab |= (scalar1x->limb[bit/WBITS] >> (bit%WBITS) & 1) << k;
                }
            }
            
            decaf_bool_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;

            constant_time_lookup_niels(ni, &table->table[j<<(t-1)], 1<<(t-1), tab);

            cond_neg_niels(ni, invert);
            if ((i!=s-1)||j) {
                add_niels_to_pt(out, ni, j==n-1 && i);
            } else {
                niels_to_pt(out, ni);
            }
        }
    }
}

decaf_bool_t decaf_448_direct_scalarmul (
    uint8_t scaled[DECAF_448_SER_BYTES],
    const uint8_t base[DECAF_448_SER_BYTES],
    const decaf_448_scalar_t scalar,
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
    for (j=DECAF_448_SCALAR_BITS+1; j>=0; j--) {
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

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int recode_wnaf (
    struct smvt_control *control, /* [nbits/(tableBits+1) + 3] */
    const decaf_448_scalar_t scalar,
    unsigned int tableBits
) {
    int current = 0, i, j;
    unsigned int position = 0;

    /* PERF: negate scalar if it's large
     * PERF: this is a pretty simplistic algorithm.  I'm sure there's a faster one...
     */
    for (i=DECAF_448_SCALAR_BITS-1; i >= 0; i--) {
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
            assert(position <= DECAF_448_SCALAR_BITS/(tableBits+1) + 2);
        }
    }
    
    if (current) {
        for (j=0; (current & 1) == 0; j++) {
            current >>= 1;
        }
        control[position].power = j;
        control[position].addend = current;
        position++;
        assert(position <= DECAF_448_SCALAR_BITS/(tableBits+1) + 2);
    }
    
  
    control[position].power = -1;
    control[position].addend = 0;
    return position;
}

sv prepare_wnaf_table(
    pniels_t *output,
    const decaf_448_point_t working,
    unsigned int tbits
) {
    decaf_448_point_t tmp;
    int i;
    pt_to_pniels(output[0], working);

    if (tbits == 0) return;

    decaf_448_point_double(tmp,working);
    pniels_t twop;
    pt_to_pniels(twop, tmp);

    add_pniels_to_pt(tmp, output[0],0);
    pt_to_pniels(output[1], tmp);

    for (i=2; i < 1<<tbits; i++) {
        add_pniels_to_pt(tmp, twop,0);
        pt_to_pniels(output[i], tmp);
    }
}

extern const decaf_word_t decaf_448_precomputed_wnaf_as_words[];
static const niels_t *decaf_448_wnaf_base = (const niels_t *)decaf_448_precomputed_wnaf_as_words;

const size_t sizeof_decaf_448_precomputed_wnafs __attribute((visibility("hidden"))) = sizeof(niels_t)<<5;

void decaf_448_precompute_wnafs (
    niels_t out[1<<5],
    const decaf_448_point_t base
) __attribute__ ((visibility ("hidden")));

void decaf_448_precompute_wnafs (
    niels_t out[1<<5],
    const decaf_448_point_t base
) {
    // TODO MAGIC
    pniels_t tmp[1<<5];
    gf zs[1<<5], zis[1<<5];
    int i;
    prepare_wnaf_table(tmp,base,5);
    for (i=0; i<1<<5; i++) {
        memcpy(out[i], tmp[i]->n, sizeof(niels_t));
        gf_cpy(zs[i], tmp[i]->z);
    }
    batch_normalize_niels(out, zs, zis, 1<<5);
}

void decaf_448_base_double_scalarmul_non_secret (
    decaf_448_point_t combo,
    const decaf_448_scalar_t scalar1,
    const decaf_448_point_t base2,
    const decaf_448_scalar_t scalar2
) {
    const int table_bits_var = 3, table_bits_pre = 5; // TODO MAGIC
    struct smvt_control control_var[DECAF_448_SCALAR_BITS/(table_bits_var+1)+3];
    struct smvt_control control_pre[DECAF_448_SCALAR_BITS/(table_bits_pre+1)+3];
    
    int ncb_pre = recode_wnaf(control_pre, scalar1, table_bits_pre);
    int ncb_var = recode_wnaf(control_var, scalar2, table_bits_var);
  
    pniels_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, base2, table_bits_var);
  
    int contp=0, contv=0, i = control_var[0].power;

    if (i < 0) {
        decaf_448_point_copy(combo, decaf_448_point_identity);
        return;
    } else if (i > control_pre[0].power) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        pniels_to_pt(combo, precmp_var[control_var[0].addend >> 1]);
        add_niels_to_pt(combo, decaf_448_wnaf_base[control_pre[0].addend >> 1], i);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        niels_to_pt(combo, decaf_448_wnaf_base[control_pre[0].addend >> 1]);
        contp++;
    }
    
    for (i--; i >= 0; i--) {
        int cv = (i==control_var[contv].power), cp = (i==control_pre[contp].power);
        decaf_448_point_double_internal(combo,combo,i && !(cv||cp));

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
                add_niels_to_pt(combo, decaf_448_wnaf_base[control_pre[contp].addend >> 1], i);
            } else {
                sub_niels_from_pt(combo, decaf_448_wnaf_base[(-control_pre[contp].addend) >> 1], i);
            }
            contp++;
        }
    }

    assert(contv == ncb_var); (void)ncb_var;
    assert(contp == ncb_pre); (void)ncb_pre;
}
