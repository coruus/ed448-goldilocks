/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf.c
 * @author Mike Hamburg
 * @brief Decaf high-level functions.
 */ 

#include "decaf.h"

typedef __uint128_t decaf_dword_t;
typedef __int128_t decaf_sdword_t;
#define WBITS 64
#define LBITS 56

#define sv static void
#define NLIMBS 8

typedef decaf_word_t gf[NLIMBS];
static const gf ZERO = {0}, ONE = {1}, TWO = {2};

#define LMASK ((1ull<<LBITS)-1)
static const gf P = { LMASK, LMASK, LMASK, LMASK, LMASK-1, LMASK, LMASK, LMASK };

#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)) || defined(DECAF_FORCE_UNROLL)
#define FOR_LIMB(i,op) { unsigned int i=0; \
   op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; op;i++; \
}
#else
#define FOR_LIMB(i,op) { unsigned int i=0; for (i=0; i<NLIMBS; i++)  { op; }}
#endif

static const int EDWARDS_D = -39081;

/** Copy x = y */
sv gf_cpy(gf x, const gf y) { FOR_LIMB(i, x[i] = y[i]); }

/** Mostly-unoptimized multiply (PERF), but at least it's unrolled. */
sv gf_mul (gf c, const gf a, const gf b) {
    gf aa;
    gf_cpy(aa,a);
    
    decaf_dword_t accum[NLIMBS] = {0};
    FOR_LIMB(i, {
        FOR_LIMB(j,{ accum[(i+j)%NLIMBS] += (decaf_dword_t)b[i] * aa[j]; });
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

/** No dedicated square (PERF) */
#define gf_sqr(c,a) gf_mul(c,a,a)

/** Inverse square root using addition chain. */
sv gf_isqrt(gf y, const gf x) {
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
sv gf_reduce(gf x) {
    x[NLIMBS/2] += x[NLIMBS-1] >> LBITS;
    FOR_LIMB(j,{
        x[j] += x[(j-1)%NLIMBS] >> LBITS;
        x[(j-1)%NLIMBS] &= LMASK;
    });
}

/** Add mod p.  Conservatively always weak-reduce. (PERF) */
sv gf_add ( gf x, const gf y, const gf z ) {
    FOR_LIMB(i, x[i] = y[i] + z[i] );
    gf_reduce(x);
}

/** Subtract mod p.  Conservatively always weak-reduce. (PERF) */
sv gf_sub ( gf x, const gf y, const gf z ) {
    FOR_LIMB(i, x[i] = y[i] - z[i] + 2*P[i] );
    gf_reduce(x);
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
sv gf_mlw(gf a, const gf b, int w) {
    if (w>0) {
        gf ww = {w};
        gf_mul(a,b,ww);
    } else {
        gf ww = {-w};
        gf_mul(a,b,ww);
        gf_sub(a,ZERO,a);
    }
}

/** Canonicalize */
sv gf_canon ( gf a ) {
    gf_reduce(a);

    /* subtract p with borrow */
    decaf_sdword_t carry = 0;
    FOR_LIMB(i, {
        carry = carry + a[i] - P[i];
        a[i] = carry & LMASK;
        carry >>= LBITS;
    });
    
    decaf_bool_t addback = carry;
    carry = 0;

    /* add it back */
    FOR_LIMB(i, {
        carry = carry + a[i] + (P[i] & addback);
        a[i] = carry & LMASK;
        carry >>= LBITS;
    });
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
sv decaf_cond_sel (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_point_t c,
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
sv decaf_subx(
    decaf_scalar_t out,
    const decaf_word_t accum[DECAF_SCALAR_LIMBS],
    const decaf_scalar_t sub,
    const decaf_scalar_t p,
    decaf_word_t extra
) {
    decaf_sdword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        chain = (chain + accum[i]) - sub->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_bool_t borrow = chain+extra; /* = 0 or -1 */
    
    chain = 0;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
        out->limb[i] = chain;
        chain >>= WBITS;
    }
}

const decaf_scalar_t decaf_scalar_p = {{{
    0x2378c292ab5844f3ull,
    0x216cc2728dc58f55ull,
    0xc44edb49aed63690ull,
    0xffffffff7cca23e9ull,
    0xffffffffffffffffull,
    0xffffffffffffffffull,
    0x3fffffffffffffffull
        // TODO 32-bit clean
}}}, decaf_scalar_one = {{{1}}}, decaf_scalar_zero = {{{0}}};

static const decaf_scalar_t decaf_scalar_r2 = {{{
    0xe3539257049b9b60ull,
    0x7af32c4bc1b195d9ull,
    0x0d66de2388ea1859ull,
    0xae17cf725ee4d838ull,
    0x1a9cc14ba3c47c44ull,
    0x2052bcb7e4d070afull,
    0x3402a939f823b729ull 
        // TODO 32-bit clean
}}};

static const decaf_word_t DECAF_MONTGOMERY_FACTOR = 0x3bd440fae918bc5ull;

sv decaf_montmul (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b,
    const decaf_scalar_t p,
    decaf_word_t montgomery_factor
) {
    unsigned int i,j;
    decaf_word_t accum[DECAF_SCALAR_LIMBS+1] = {0};
    decaf_word_t hi_carry = 0;
    
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        decaf_word_t mand = a->limb[i];
        const decaf_word_t *mier = b->limb;
        
        decaf_dword_t chain = 0;
        for (j=0; j<DECAF_SCALAR_LIMBS; j++) {
            chain += ((decaf_dword_t)mand)*mier[j] + accum[j];
            accum[j] = chain;
            chain >>= WBITS;
        }
        accum[j] = chain;
        
        mand = accum[0] * montgomery_factor;
        chain = 0;
        mier = p->limb;
        for (j=0; j<DECAF_SCALAR_LIMBS; j++) {
            chain += (decaf_dword_t)mand*mier[j] + accum[j];
            if (j) accum[j-1] = chain;
            chain >>= WBITS;
        }
        chain += accum[j];
        chain += hi_carry;
        accum[j-1] = chain;
        hi_carry = chain >> WBITS;
    }
    
    decaf_subx(out, accum, p, p, hi_carry);
}

void decaf_scalar_mul (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) {
    decaf_montmul(out,a,b,decaf_scalar_p,DECAF_MONTGOMERY_FACTOR);
    decaf_montmul(out,out,decaf_scalar_r2,decaf_scalar_p,DECAF_MONTGOMERY_FACTOR);
}

void decaf_scalar_sub (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) {
    decaf_subx(out, a->limb, b, decaf_scalar_p, 0);
}

void decaf_scalar_add (
    decaf_scalar_t out,
    const decaf_scalar_t a,
    const decaf_scalar_t b
) {
    decaf_dword_t chain = 0;
    unsigned int i;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        chain = (chain + a->limb[i]) + b->limb[i];
        out->limb[i] = chain;
        chain >>= WBITS;
    }
    decaf_subx(out, out->limb, decaf_scalar_p, decaf_scalar_p, chain);
}

void decaf_scalar_copy (
    decaf_scalar_t out,
    const decaf_scalar_t a
) {
    unsigned int i;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        out->limb[i] = a->limb[i];
    }
}

decaf_bool_t decaf_scalar_eq (
    const decaf_scalar_t a,
    const decaf_scalar_t b
) {
    decaf_word_t diff = 0;
    unsigned int i;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        diff |= a->limb[i] ^ b->limb[i];
    }
    return (((decaf_dword_t)diff)-1)>>WBITS;
}

/* *** API begins here *** */    

/** identity = (0,1) */
const decaf_point_t decaf_point_identity = {{{0},{1},{1},{0}}};

/** base = twist of Goldilocks base point (~,19).  FIXME: ARCH */
const decaf_point_t decaf_point_base = {{
    { 0xb39a2d57e08c7bull,0xb38639c75ff281ull,0x2ec981082b3288ull,0x99fe8607e5237cull,
      0x0e33fbb1fadd1full,0xe714f67055eb4aull,0xc9ae06d64067ddull,0xf7be45054760faull },
    { 0xbd8715f551617full,0x8c17fbeca8f5fcull,0xaae0eec209c06full,0xce41ad80cbe6b8ull,
      0xdf360b5c828c00ull,0xaf25b6bbb40e3bull,0x8ed37f0ce4ed31ull,0x72a1c3214557b9ull },
    { 1 },
    { 0x97ca9c8ed8bde9ull,0xf0b780da83304cull,0x0d79c0a7729a69ull,0xc18d3f24aebc1cull,
      0x1fbb5389b3fda5ull,0xbb24f674635948ull,0x723a55709a3983ull,0xe1c0107a823dd4ull }
}};

void decaf_point_encode( unsigned char ser[DECAF_SER_BYTES], const decaf_point_t p ) {
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

/**
 * Deserialize a bool, return TRUE if < p.
 */
static decaf_bool_t gf_deser(gf s, const unsigned char ser[DECAF_SER_BYTES]) {
    // FIXME arch
    int j;
    FOR_LIMB(i, {
        decaf_word_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((decaf_word_t)ser[7*i+j])<<(8*j);
        }
        s[i] = out;
    });
    
    decaf_sdword_t accum = 0;
    FOR_LIMB(i, accum = (accum + s[i] - P[i]) >> WBITS );
    return accum;
}
    
/* Constant-time add or subtract */
sv decaf_point_add_sub (
    decaf_point_t p,
    const decaf_point_t q,
    const decaf_point_t r,
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
    
decaf_bool_t decaf_point_decode (
    decaf_point_t p,
    const unsigned char ser[DECAF_SER_BYTES],
    decaf_bool_t allow_identity
) {
    gf s, a, b, c, d, e;
    decaf_bool_t succ = gf_deser(s, ser);
    decaf_bool_t zero = gf_eq(s, ZERO);
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

void decaf_point_sub(decaf_point_t a, const decaf_point_t b, const decaf_point_t c) {
    decaf_point_add_sub(a,b,c,-1);
}
    
void decaf_point_add(decaf_point_t a, const decaf_point_t b, const decaf_point_t c) {
    decaf_point_add_sub(a,b,c,0);
}

/* No dedicated point double yet (PERF) */
void decaf_point_double(decaf_point_t a, const decaf_point_t b) {
    decaf_point_add(a,b,b);
}

void decaf_point_copy (
    decaf_point_t a,
    const decaf_point_t b
) {
    gf_cpy(a->x, b->x);
    gf_cpy(a->y, b->y);
    gf_cpy(a->z, b->z);
    gf_cpy(a->t, b->t);
}

decaf_bool_t decaf_scalar_decode(
    decaf_scalar_t s,
    const unsigned char ser[DECAF_SER_BYTES]
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        decaf_word_t out = 0;
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            out |= ((decaf_word_t)ser[k])<<(8*j);
        }
        s->limb[i] = out;
    }
    
    decaf_sdword_t accum = 0;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        accum = (accum + s->limb[i] - decaf_scalar_p->limb[i]) >> WBITS;
    }
    
    decaf_scalar_mul(s,s,decaf_scalar_one); /* ham-handed reduce */
    
    return accum;
}

void decaf_scalar_encode(
    unsigned char ser[DECAF_SER_BYTES],
    const decaf_scalar_t s
) {
    unsigned int i,j,k=0;
    for (i=0; i<DECAF_SCALAR_LIMBS; i++) {
        for (j=0; j<sizeof(decaf_word_t); j++,k++) {
            ser[k] = s->limb[i] >> (8*j);
        }
    }
}

void decaf_point_scalarmul (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_scalar_t scalar
) {
    /* w=2 signed window uses about 1.5 adds per bit.
     * I figured a few extra lines was worth the 25% speedup.
     * NB: if adapting this function to scalarmul by a
     * possibly-odd number of unmasked bits, may need to mask.
     */
    decaf_point_t w,b3,tmp;
    decaf_point_double(w,b);
    /* b3 = b*3 */
    decaf_point_add(b3,w,b);
    int i;
    for (i=DECAF_SCALAR_LIMBS*WBITS-2; i>0; i-=2) {
        decaf_word_t bits = scalar->limb[i/WBITS]>>(i%WBITS);
        decaf_cond_sel(tmp,b,b3,((bits^(bits>>1))&1)-1);
        decaf_point_double(w,w);
        decaf_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        decaf_point_double(w,w);
    }
    decaf_point_add_sub(w,w,b,((scalar->limb[0]>>1)&1)-1);
    /* low bit is special because fo signed window */
    decaf_cond_sel(tmp,b,decaf_point_identity,-(scalar->limb[0]&1));
    decaf_point_sub(a,w,tmp);
}

void decaf_point_double_scalarmul (
    decaf_point_t a,
    const decaf_point_t b,
    const decaf_scalar_t scalarb,
    const decaf_point_t c,
    const decaf_scalar_t scalarc
) {
    /* w=2 signed window uses about 1.5 adds per bit.
     * I figured a few extra lines was worth the 25% speedup.
     * NB: if adapting this function to scalarmul by a
     * possibly-odd number of unmasked bits, may need to mask.
     */
    decaf_point_t w,b3,c3,tmp;
    decaf_point_double(w,b);
    decaf_point_double(tmp,c);
    /* b3 = b*3 */
    decaf_point_add(b3,w,b);
    decaf_point_add(c3,tmp,c);
    decaf_point_add(w,w,tmp);
    int i;
    for (i=DECAF_SCALAR_LIMBS*WBITS-2; i>0; i-=2) {
        decaf_point_double(w,w);
        decaf_word_t bits = scalarb->limb[i/WBITS]>>(i%WBITS);
        decaf_cond_sel(tmp,b,b3,((bits^(bits>>1))&1)-1);
        decaf_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        bits = scalarc->limb[i/WBITS]>>(i%WBITS);
        decaf_cond_sel(tmp,c,c3,((bits^(bits>>1))&1)-1);
        decaf_point_add_sub(w,w,tmp,((bits>>1)&1)-1);
        decaf_point_double(w,w);
    }
    decaf_point_add_sub(w,w,b,((scalarb->limb[0]>>1)&1)-1);
    decaf_point_add_sub(w,w,c,((scalarc->limb[0]>>1)&1)-1);
    /* low bit is special because of signed window */
    decaf_cond_sel(tmp,b,decaf_point_identity,-(scalarb->limb[0]&1));
    decaf_point_sub(w,w,tmp);
    decaf_cond_sel(tmp,c,decaf_point_identity,-(scalarc->limb[0]&1));
    decaf_point_sub(a,w,tmp);
}

decaf_bool_t decaf_point_eq ( const decaf_point_t p, const decaf_point_t q ) {
    /* equality mod 2-torsion compares x/y */
    gf a, b;
    gf_mul ( a, p->y, q->x );
    gf_mul ( b, q->y, p->x );
    return gf_eq(a,b);
}

static const int QUADRATIC_NONRESIDUE = -1;

void decaf_point_from_hash_nonuniform (
    decaf_point_t p,
    const unsigned char ser[DECAF_SER_BYTES]
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

void decaf_point_from_hash_uniform (
    decaf_point_t pt,
    const unsigned char hashed_data[2*DECAF_SER_BYTES]
) {
    decaf_point_t pt2;
    decaf_point_from_hash_nonuniform(pt,hashed_data);
    decaf_point_from_hash_nonuniform(pt2,&hashed_data[DECAF_SER_BYTES]);
    decaf_point_add(pt,pt,pt2);
}

decaf_bool_t decaf_point_valid (
    const decaf_point_t p
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
    return out;
}
