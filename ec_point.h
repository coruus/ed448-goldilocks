/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/* This file was generated with the assistance of a tool written in SAGE. */
#ifndef __CC_INCLUDED_P448_EDWARDS_H__
#define __CC_INCLUDED_P448_EDWARDS_H__

#include "p448.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Affine point on an Edwards curve.
 */
struct affine_t {
    struct p448_t x, y;
};

/*
 * Affine point on a twisted Edwards curve.
 */
struct tw_affine_t {
    struct p448_t x, y;
};

/*
 * Montgomery buffer.
 */
struct montgomery_t {
    struct p448_t z0, xd, zd, xa, za;
};

/*
 * Extensible coordinates for Edwards curves, suitable for
 * accumulators.
 * 
 * Represents the point (x/z, y/z).  The extra coordinates
 * t,u satisfy xy = tuz, allowing for conversion to Extended
 * form by multiplying t and u.
 * 
 * The idea is that you don't have to do this multiplication
 * when doubling the accumulator, because the t-coordinate
 * isn't used there.  At the same time, as long as you only
 * have one point in extensible form, additions don't cost
 * extra.
 * 
 * This is essentially a lazier version of Hisil et al's
 * lookahead trick.  It might be worth considering that trick
 * instead.
 */
struct extensible_t {
    struct p448_t x, y, z, t, u;
};

/*
 * Extensible coordinates for twisted Edwards curves,
 * suitable for accumulators.
 */
struct tw_extensible_t {
    struct p448_t x, y, z, t, u;
};

/*
 * Niels coordinates for twisted Edwards curves.  Good for
 * mixed readdition; suitable for fixed tables.
 */
struct tw_niels_t {
    struct p448_t a, b, c;
};

/*
 * Projective niels coordinates for twisted Edwards curves.
 * Good for readdition; suitable for temporary tables.
 */
struct tw_pniels_t {
    struct tw_niels_t n;
    struct p448_t z;
};


/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_affine (
    struct affine_t*       a,
    const struct affine_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_affine (
    struct tw_affine_t*       a,
    const struct tw_affine_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_montgomery (
    struct montgomery_t*       a,
    const struct montgomery_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_extensible (
    struct extensible_t*       a,
    const struct extensible_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_extensible (
    struct tw_extensible_t*       a,
    const struct tw_extensible_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_niels (
    struct tw_niels_t*       a,
    const struct tw_niels_t* ds
) __attribute__((unused,always_inline));

/*
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_pniels (
    struct tw_pniels_t*       a,
    const struct tw_pniels_t* ds
) __attribute__((unused,always_inline));

/*
 * Returns 1/sqrt(+- x).
 * 
 * The Legendre symbol of the result is the same as that of the
 * input.
 * 
 * If x=0, returns 0.
 */
void
p448_isr (
    struct p448_t*       a,
    const struct p448_t* x
);

/*
 * Returns 1/x.
 * 
 * If x=0, returns 0.
 */
void
p448_inverse (
    struct p448_t*       a,
    const struct p448_t* x
);

/*
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in half-Niels form.
 */
void
p448_tw_extensible_add_niels (
    struct tw_extensible_t*  d,
    const struct tw_niels_t* e
);

/*
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in projective Niels form.
 */
void
p448_tw_extensible_add_pniels (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* a
);

/*
 * Double a point on a twisted Edwards curve, in "extensible" coordinates.
 */
void
p448_tw_extensible_double (
    struct tw_extensible_t* a
);

/*
 * Double a point on an Edwards curve, in "extensible" coordinates.
 */
void
p448_extensible_double (
    struct extensible_t* a
);

/*
 * 4-isogeny from untwisted to twisted.
 */
void
p448_isogeny_un_to_tw (
    struct tw_extensible_t*    b,
    const struct extensible_t* a
);

/*
 * Dual 4-isogeny from twisted to untwisted.
 */
void
p448_isogeny_tw_to_un (
    struct extensible_t*          b,
    const struct tw_extensible_t* a
);

void
convert_tw_affine_to_tw_pniels (
    struct tw_pniels_t*       b,
    const struct tw_affine_t* a
);

void
convert_tw_affine_to_tw_extensible (
    struct tw_extensible_t*   b,
    const struct tw_affine_t* a
);

void
convert_affine_to_extensible (
    struct extensible_t*   b,
    const struct affine_t* a
);

void
convert_tw_extensible_to_tw_pniels (
    struct tw_pniels_t*           b,
    const struct tw_extensible_t* a
);

void
convert_tw_pniels_to_tw_extensible (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* d
);

void
convert_tw_niels_to_tw_extensible (
    struct tw_extensible_t*  e,
    const struct tw_niels_t* d
);

void
p448_montgomery_step (
    struct montgomery_t* a
);

void
p448_montgomery_serialize (
    struct p448_t*             sign,
    struct p448_t*             ser,
    const struct montgomery_t* a,
    const struct p448_t*       sbz
);

/*
 * Serialize a point on an Edwards curve
 * The serialized form would be sqrt((z-y)/(z+y)) with sign of xz
 * It would be on 4y^2/(1-d) = x^3 + 2(1+d)/(1-d) * x^2 + x.
 * But 4/(1-d) isn't square, so we need to twist it:
 * -x is on 4y^2/(d-1) = x^3 + 2(d+1)/(d-1) * x^2 + x
 */
void
extensible_serialize (
    struct p448_t*             b,
    const struct extensible_t* a
);

/*
 * 
 */
void
isogeny_and_serialize (
    struct p448_t*                b,
    const struct tw_extensible_t* a
);

/*
 * Deserialize a point to an untwisted affine curve
 */
mask_t
affine_deserialize (
    struct affine_t*     a,
    const struct p448_t* sz
);

void
set_identity_extensible (
    struct extensible_t* a
);

void
set_identity_tw_extensible (
    struct tw_extensible_t* a
);

void
set_identity_affine (
    struct affine_t* a
);

mask_t
eq_affine (
    const struct affine_t* a,
    const struct affine_t* b
);

mask_t
eq_extensible (
    const struct extensible_t* a,
    const struct extensible_t* b
);

mask_t
eq_tw_extensible (
    const struct tw_extensible_t* a,
    const struct tw_extensible_t* b
);

void
elligator_2s_inject (
    struct affine_t*     a,
    const struct p448_t* r
);

mask_t
p448_affine_validate (
    const struct affine_t* a
);

/*
 * Check the invariants for struct tw_extensible_t.
 * PERF: This function was automatically generated
 * with no regard for speed.
 */
mask_t
p448_tw_extensible_validate (
    const struct tw_extensible_t* ext
);


void
copy_affine (
    struct affine_t*       a,
    const struct affine_t* ds
) {
    p448_copy ( &a->x, &ds->x );
    p448_copy ( &a->y, &ds->y );
}

void
copy_tw_affine (
    struct tw_affine_t*       a,
    const struct tw_affine_t* ds
) {
    p448_copy ( &a->x, &ds->x );
    p448_copy ( &a->y, &ds->y );
}

void
copy_montgomery (
    struct montgomery_t*       a,
    const struct montgomery_t* ds
) {
    p448_copy ( &a->z0, &ds->z0 );
    p448_copy ( &a->xd, &ds->xd );
    p448_copy ( &a->zd, &ds->zd );
    p448_copy ( &a->xa, &ds->xa );
    p448_copy ( &a->za, &ds->za );
}

void
copy_extensible (
    struct extensible_t*       a,
    const struct extensible_t* ds
) {
    p448_copy ( &a->x, &ds->x );
    p448_copy ( &a->y, &ds->y );
    p448_copy ( &a->z, &ds->z );
    p448_copy ( &a->t, &ds->t );
    p448_copy ( &a->u, &ds->u );
}

void
copy_tw_extensible (
    struct tw_extensible_t*       a,
    const struct tw_extensible_t* ds
) {
    p448_copy ( &a->x, &ds->x );
    p448_copy ( &a->y, &ds->y );
    p448_copy ( &a->z, &ds->z );
    p448_copy ( &a->t, &ds->t );
    p448_copy ( &a->u, &ds->u );
}

void
copy_tw_niels (
    struct tw_niels_t*       a,
    const struct tw_niels_t* ds
) {
    p448_copy ( &a->a, &ds->a );
    p448_copy ( &a->b, &ds->b );
    p448_copy ( &a->c, &ds->c );
}

void
copy_tw_pniels (
    struct tw_pniels_t*       a,
    const struct tw_pniels_t* ds
) {
    copy_tw_niels( &a->n, &ds->n );
    p448_copy ( &a->z, &ds->z );
}



#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __CC_INCLUDED_P448_EDWARDS_H__ */
