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
   op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; }

static const int EDWARDS_D = -39081;

siv gf_cpy(gf x, const gf y) { FOR_LIMB(i, x[i] = y[i]); }

siv gf_mul_x (gf c, const gf a, const word_t *b, int limbs_b) {
    gf aa;
    gf_cpy(aa,a);
    
    dword_t accum[NLIMBS] = {0};
    int i;
    for (i=0; i<limbs_b; i++) {
        FOR_LIMB(j,{ accum[(i+j)%NLIMBS] += (__uint128_t)b[i] * aa[j]; });
        aa[(NLIMBS-1-i)^(NLIMBS/2)] += aa[NLIMBS-1-i];
    }
    
    accum[NLIMBS-1] += accum[NLIMBS-2] >> LBITS;
    accum[NLIMBS-2] &= LMASK;
    accum[NLIMBS/2] += accum[NLIMBS-1] >> LBITS;
    FOR_LIMB(j,{
        accum[j] += accum[(j-1)%NLIMBS] >> LBITS;
        accum[(j-1)%NLIMBS] &= LMASK;
    });
    FOR_LIMB(j, c[j] = accum[j] );
}

static void gf_mul( gf a, const gf b, const gf c ) { gf_mul_x(a,b,c,NLIMBS); }
static void gf_sqr( gf a, const gf b ) { gf_mul_x(a,b,b,NLIMBS); }

siv gf_sqrn ( gf x, const gf y, int n ) {
    gf_cpy(x,y);
    int i;
    for (i=0; i<n; i++) gf_sqr(x,x);
}

static void gf_isqrt(gf y, const gf x) {
    gf a, b, c;
    gf_sqrn( b,    x,   1 );
    gf_mul ( c,    x,   b );
    gf_sqrn( b,   c,    1 );
    gf_mul ( c,   x,   b );
    gf_sqrn( b,   c,    3 );
    gf_mul ( a,   c,   b );
    gf_sqrn( b,   a,    3 );
    gf_mul ( a,   c,   b );
    gf_sqrn( c,   a,    9 );
    gf_mul ( b,   a,   c );
    gf_sqrn( a,   b,    1  );
    gf_mul ( c,     x,  a  );
    gf_sqrn( a,   c,   18  );
    gf_mul ( c,   b,   a  );
    gf_sqrn( a,   c,   37  );
    gf_mul ( b,   c,   a  );
    gf_sqrn( a,   b,   37  );
    gf_mul ( b,   c,   a  );
    gf_sqrn( a,   b,   111 );
    gf_mul ( c,   b,   a   );
    gf_sqrn( a,   c,     1 );
    gf_mul ( b,   x,    a  );
    gf_sqrn( a,   b,   223 );
    gf_mul ( y,   c,   a   );
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
        gf_mul_x(a,b,&w,1);
    } else {
        word_t ww = -w;
        gf_mul_x(a,b,&ww,1);
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

// FIXME: 32-bit cleanliness
siv gf_ser ( uint8_t serial[DECAF_SER_BYTES], const gf x ) {
    int j;
    gf red;
    gf_cpy(red,x);
    gf_canon(red);
    FOR_LIMB(i,{
        for (j=0; j<7; j++) {
            serial[7*i+j] = red[i];
            red[i] >>= 8;
        }
    });
}

// FIXME: 32-bit cleanliness
static mask_t gf_deser ( gf x, const uint8_t serial[DECAF_SER_BYTES] ) {
    int j;
    FOR_LIMB(i, {
        uint64_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((uint64_t)serial[7*i+j])<<(8*j);
        }
        x[i] = out;
    });
    
    sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + P[i] - x[i]) >> WBITS );
    return ~accum;
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
    
void decaf_encode( uint8_t ser[DECAF_SER_BYTES], const decaf_point_t p ) {
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
    gf_ser(ser,a);
}
    
decaf_bool_t decaf_decode (
    decaf_point_t p,
    const uint8_t ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, a, b, c, d, e;
    mask_t succ = gf_deser( s, ser );
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
