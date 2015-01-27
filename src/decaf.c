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

static void ISR(gf a, const gf x) {
    gf L0, L1, L2;
    gf_sqr (L1,    x );
    gf_mul (L2,    x,   L1 );
    gf_sqr (L1,   L2 );
    gf_mul (L2,    x,   L1 );
    gf_sqrn(L1,   L2,    3 );
    gf_mul (L0,   L2,   L1 );
    gf_sqrn(L1,   L0,    3 );
    gf_mul (L0,   L2,   L1 );
    gf_sqrn(L2,   L0,    9 );
    gf_mul (L1,   L0,   L2 );
    gf_sqr (L0,   L1 );
    gf_mul (L2,     x,  L0  );
    gf_sqrn(L0,   L2,   18  );
    gf_mul (L2,   L1,   L0  );
    gf_sqrn(L0,   L2,   37  );
    gf_mul (L1,   L2,   L0  );
    gf_sqrn(L0,   L1,   37  );
    gf_mul (L1,   L2,   L0  );
    gf_sqrn(L0,   L1,   111 );
    gf_mul (L2,   L1,   L0  );
    gf_sqr (L0,   L2 );
    gf_mul (L1,    x,   L0  );
    gf_sqrn(L0,   L1,   223 );
    gf_mul ( a,   L2,   L0  );
}

const decaf_point_t decaf_identity_point = {{{0},{1},{1},{0}}};

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
siv gf_ser ( uint8_t serial[56], const gf x ) {
    int i,j;
    gf red;
    gf_cpy(red,x);
    gf_canon(red);
    for (i=0; i<8; i++) {
        for (j=0; j<7; j++) {
            serial[7*i+j] = red[i];
            red[i] >>= 8;
        }
    }
}

// FIXME: 32-bit cleanliness
static mask_t gf_deser ( gf x, const uint8_t serial[56] ) {
    int i,j;
    for (i=0; i<8; i++) {
        uint64_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((uint64_t)serial[7*i+j])<<(8*j);
        }
        x[i] = out;
    }
    
    sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + P[i] - x[i]) >> WBITS );
    return ~accum;
}

siv
add_sub_point (
    decaf_point_t c,
    const decaf_point_t d,
    const decaf_point_t e,
    mask_t sub
) {
    gf L0, L1, L2, L3;
    gf_sub ( L1, d->y, d->x );
    gf_sub ( L2, e->y, e->x );
    gf_add ( L3, e->y, e->x );
    cond_swap(L2,L3,sub);
    gf_mul ( L0, L2, L1 );
    gf_add ( L1, d->y, d->x );
    gf_mul ( c->y, L3, L1 );
    gf_mul ( L1, e->t, d->t );
    gf_mlw ( c->x, L1, 2-2*EDWARDS_D );
    gf_add ( L1, L0, c->y );
    gf_sub ( L2, c->y, L0 );
    gf_mul ( L0, d->z, e->z );
    gf_add ( L0, L0, L0 );
    gf_add ( c->y, L0, c->x );
    gf_sub ( L0, L0, c->x );
    cond_swap(L0,c->y,sub);
    gf_mul ( c->z, L0, c->y );
    gf_mul ( c->x, c->y, L2 );
    gf_mul ( c->y, L0, L1 );
    gf_mul ( c->t, L1, L2 );
}
    
void decaf_encode( uint8_t ser[DECAF_SER_BYTES], const decaf_point_t a ) {
    gf L0, L1, L2, L3;
    gf_mlw ( L0, a->y, 1-EDWARDS_D ); 
    gf_mul ( L2, L0, a->t ); 
    gf_mul ( L0, a->x, a->z ); 
    gf_sub ( L3, L2, L0 ); 
    gf_add ( L0, a->z, a->y ); 
    gf_sub ( L1, a->z, a->y ); 
    gf_mul ( L2, L1, L0 );
    gf_mlw ( L1, L2, -EDWARDS_D );
    ISR ( L0, L1 );
    gf_mlw ( L1, L0, -EDWARDS_D ); 
    gf_mul ( L2, L1, L0 );
    gf_mul ( L0, L2, L3 );
    gf_add ( L3, L1, L1 );  
    gf_mul ( L2, L3, a->z );   
    cond_neg ( L1, ~hibit(L2) ); 
    gf_mul ( L2, L1, a->y ); 
    gf_add ( L0, L0, L2 );
    cond_neg ( L0, hibit(L0) );
    gf_ser(ser,L0);
}
    
decaf_bool_t decaf_decode (
    decaf_point_t a,
    const uint8_t ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, L0, L1, L2, L3, L4;
    mask_t zero = gf_eq(s, ZERO);
    mask_t succ = gf_deser( s, ser );
    succ &= allow_identity | ~zero;
    succ &= ~hibit(s);
    gf_sqr ( L0, s );
    gf_sub ( a->z, ONE, L0 );
    gf_sqr ( L1, a->z ); 
    gf_mlw ( L2, L0, 4-4*EDWARDS_D );
    gf_add ( L2, L2, L1 );
    gf_mul ( L1, L2, L0 );
    ISR ( L3, L1 );
    gf_sqr ( L4, L3 );
    gf_mul ( L0, L4, L1 );
    gf_add ( L0, L0, ONE );
    succ &= ~gf_eq ( L0, ZERO );
    gf_mul ( L1, L2, L3 );
    cond_neg ( L3, hibit(L1) );
    gf_add ( a->x, s, s );
    gf_mul ( L2, L3, s );
    gf_sub ( L1, TWO, a->z );
    gf_mul ( L0, L1, L2 );
    gf_mul ( a->y,L0,a->z );
    gf_mul ( a->t,a->x,L0 );
    a->y[0] -= zero;
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

decaf_bool_t decaf_eq ( const decaf_point_t a, const decaf_point_t b ) {
    gf L0, L1;
    gf_mul ( L0, b->y, a->x );
    gf_mul ( L1, a->y, b->x );
    return gf_eq(L0,L1);
}
