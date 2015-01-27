/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.c
 * @author Mike Hamburg
 * @brief Decaf high-level functions.
 */ 

#include "decaf.h"

typedef uint64_t word_t, mask_t; // TODO
typedef __uint128_t dword_t;
typedef __int128_t sdword_t;
#define WBITS 64
#define LBITS 56

#define siv static inline void
#define NLIMBS 8

typedef word_t gf[NLIMBS];
static const gf ZERO = {0}, ONE = {1}, TWO = {2};

static const word_t LMASK = (1ull<<LBITS)-1;
static const gf P = { LMASK, LMASK, LMASK, LMASK, LMASK-1, LMASK, LMASK, LMASK };
#define FOR_LIMB(i,op) { unsigned int i=0; \
   op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
}

static const int EDWARDS_D = -39081;

siv gf_cpy(gf x, const gf y) { FOR_LIMB(i, x[i] = y[i]); }

static inline void __attribute__((always_inline)) gf_mul_inline (gf c, const gf a, const gf b) {
    gf aa;
    gf_cpy(aa,a);
    
    dword_t accum[NLIMBS] = {0};
    FOR_LIMB(i, {
        FOR_LIMB(j,{ accum[(i+j)%NLIMBS] += (dword_t)b[i] * aa[j]; });
        aa[(NLIMBS-1-i)^(NLIMBS/2)] += aa[NLIMBS-1-i];
    });
    
    accum[NLIMBS-1] += accum[NLIMBS-2] >> LBITS;
    accum[NLIMBS-2] &= LMASK;
    accum[NLIMBS/2] += accum[NLIMBS-1] >> LBITS;
    FOR_LIMB(j,{
        accum[j] += accum[(j-1)%NLIMBS] >> LBITS;
        accum[(j-1)%NLIMBS] &= LMASK;
    });
    FOR_LIMB(j, c[j] = accum[j] );
}

static void gf_mul( gf a, const gf b, const gf c ) { gf_mul_inline(a,b,c); }
static void gf_sqr( gf a, const gf b ) { gf_mul_inline(a,b,b); }

static void gf_isqrt(gf y, const gf x) {
    gf a, b, c;
    gf_sqr ( c,   x );
#define STEP(s,m,n) {gf_mul(s,m,c); gf_cpy(c,s); int i; for (i=0;i<n;i++) gf_sqr(c,c);}
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

siv gf_reduce(gf x) {
    x[NLIMBS/2] += x[NLIMBS-1] >> LBITS;
    FOR_LIMB(j,{
        x[j] += x[(j-1)%NLIMBS] >> LBITS;
        x[(j-1)%NLIMBS] &= LMASK;
    });
}

siv gf_add ( gf x, const gf y, const gf z ) {
    FOR_LIMB(i, x[i] = y[i] + z[i] );
    gf_reduce(x);
}

siv gf_sub ( gf x, const gf y, const gf z ) {
    FOR_LIMB(i, x[i] = y[i] - z[i] + 2*P[i] );
    gf_reduce(x);
}

siv gf_mlw(gf a, const gf b, word_t w) {
    if (w>0) {
        gf ww = {w};
        gf_mul_inline(a,b,ww);
    } else {
        gf ww = {-w};
        gf_mul_inline(a,b,ww);
        gf_sub(a,ZERO,a);
    }
}

siv cond_neg(gf x, mask_t neg) {
    gf y;
    gf_sub(y,ZERO,x);
    FOR_LIMB(i, x[i] = (x[i] & ~neg) | (y[i] & neg) );
}

siv cond_swap(gf x, gf y, mask_t swap) {
    FOR_LIMB(i, {
        word_t s = (x[i] ^ y[i]) & swap;
        x[i] ^= s;
        y[i] ^= s;
    });
}

static void gf_canon ( gf a ) {
    gf_reduce(a);

    /* subtract p with borrow */
    sdword_t carry = 0;
    FOR_LIMB(i, {
        carry = carry + a[i] - P[i];
        a[i] = carry & LMASK;
        carry >>= LBITS;
    });
    
    mask_t addback = carry;
    carry = 0;

    /* add it back */
    FOR_LIMB(i, {
        carry = carry + a[i] + (P[i] & addback);
        a[i] = carry & LMASK;
        carry >>= LBITS;
    });
}

static inline word_t gf_eq(const gf a, const gf b) {
    gf c;
    gf_sub(c,a,b);
    gf_canon(c);
    word_t ret=0;
    FOR_LIMB(i, ret |= c[i] );
    return ((dword_t)ret - 1) >> WBITS;
}

static inline word_t hibit(const gf x) {
    gf y;
    gf_add(y,x,x);
    gf_canon(y);
    return -(y[0]&1);
}

const decaf_point_t decaf_identity_point = {{{0},{1},{1},{0}}};

siv add_sub_point (
    decaf_point_t p,
    const decaf_point_t q,
    const decaf_point_t r,
    mask_t sub
) {
    gf a, b, c, d;
    gf_sub ( b, q->y, q->x );
    gf_sub ( c, r->y, r->x );
    gf_add ( d, r->y, r->x );
    cond_swap(c,d,sub);
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
    cond_swap(a,p->y,sub);
    gf_mul ( p->z, a, p->y );
    gf_mul ( p->x, p->y, c );
    gf_mul ( p->y, a, b );
    gf_mul ( p->t, b, c );
}
    
void decaf_encode( unsigned char ser[DECAF_SER_BYTES], const decaf_point_t p ) {
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
    
    // FIXME arch
    gf_canon(a);
    int j;
    FOR_LIMB(i,{
        for (j=0; j<7; j++) {
            ser[7*i+j] = a[i];
            a[i] >>= 8;
        }
    });
}
    
decaf_bool_t decaf_decode (
    decaf_point_t p,
    const unsigned char ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, a, b, c, d, e;
    
    // FIXME arch
    int j;
    FOR_LIMB(i, {
        word_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((word_t)ser[7*i+j])<<(8*j);
        }
        s[i] = out;
    });
    
    sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + P[i] - s[i]) >> WBITS );
    
    mask_t succ = ~accum;
    mask_t zero = gf_eq(s, ZERO);
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
    return succ;
}
    
void decaf_add(decaf_point_t a, const decaf_point_t b, const decaf_point_t c) {
    add_sub_point(a,b,c,0);
}
    
void decaf_sub(decaf_point_t a, const decaf_point_t b, const decaf_point_t c) {
    add_sub_point(a,b,c,-1);
}
    
void decaf_add_sub (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_point_t c,
    decaf_bool_t do_sub
) {
    add_sub_point(a,b,c,do_sub);
}

decaf_bool_t decaf_eq ( const decaf_point_t p, const decaf_point_t q ) {
    gf a, b;
    gf_mul ( a, p->y, q->x );
    gf_mul ( b, q->y, p->x );
    return gf_eq(a,b);
}
