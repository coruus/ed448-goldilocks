/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/* This file was generated with the assistance of a tool written in SAGE. */
#include "ec_point.h"


void
p448_isr (
    struct p448_t*       a,
    const struct p448_t* x
) {
    struct p448_t L0, L1, L2;
    p448_sqr  (   &L1,     x );
    p448_mul  (   &L2,     x,   &L1 );
    p448_sqr  (   &L1,   &L2 );
    p448_mul  (   &L2,     x,   &L1 );
    p448_sqrn (   &L1,   &L2,     3 );
    p448_mul  (   &L0,   &L2,   &L1 );
    p448_sqrn (   &L1,   &L0,     3 );
    p448_mul  (   &L0,   &L2,   &L1 );
    p448_sqrn (   &L2,   &L0,     9 );
    p448_mul  (   &L1,   &L0,   &L2 );
    p448_sqr  (   &L0,   &L1 );
    p448_mul  (   &L2,     x,   &L0 );
    p448_sqrn (   &L0,   &L2,    18 );
    p448_mul  (   &L2,   &L1,   &L0 );
    p448_sqrn (   &L0,   &L2,    37 );
    p448_mul  (   &L1,   &L2,   &L0 );
    p448_sqrn (   &L0,   &L1,    37 );
    p448_mul  (   &L1,   &L2,   &L0 );
    p448_sqrn (   &L0,   &L1,   111 );
    p448_mul  (   &L2,   &L1,   &L0 );
    p448_sqr  (   &L0,   &L2 );
    p448_mul  (   &L1,     x,   &L0 );
    p448_sqrn (   &L0,   &L1,   223 );
    p448_mul  (     a,   &L2,   &L0 );
}

void
p448_inverse (
    struct p448_t*       a,
    const struct p448_t* x
) {
    struct p448_t L0, L1;
    p448_isr  (   &L0,     x );
    p448_sqr  (   &L1,   &L0 );
    p448_sqr  (   &L0,   &L1 );
    p448_mul  (     a,     x,   &L0 );
}

void
p448_tw_extensible_add_niels (
    struct tw_extensible_t*  d,
    const struct tw_niels_t* e
) {
    struct p448_t L0, L1;
    p448_bias ( &d->y,     2 );
    p448_bias ( &d->z,     2 );
    p448_sub  (   &L1, &d->y, &d->x );
    p448_mul  (   &L0, &e->a,   &L1 );
    p448_add  (   &L1, &d->x, &d->y );
    p448_mul  ( &d->y, &e->b,   &L1 );
    p448_bias ( &d->y,     2 );
    p448_mul  (   &L1, &d->u, &d->t );
    p448_mul  ( &d->x, &e->c,   &L1 );
    p448_add  ( &d->u,   &L0, &d->y );
    p448_sub  ( &d->t, &d->y,   &L0 );
    p448_sub  ( &d->y, &d->z, &d->x );
    p448_add  (   &L0, &d->x, &d->z );
    p448_mul  ( &d->z,   &L0, &d->y );
    p448_mul  ( &d->x, &d->y, &d->t );
    p448_mul  ( &d->y,   &L0, &d->u );
}

void
p448_tw_extensible_add_pniels (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* a
) {
    struct p448_t L0;
    p448_mul  (   &L0, &e->z, &a->z );
    p448_copy ( &e->z,   &L0 );
    p448_tw_extensible_add_niels(     e, &a->n );
}

void
p448_tw_extensible_double (
    struct tw_extensible_t* a
) {
    struct p448_t L0, L1, L2;
    p448_sqr  (   &L2, &a->x );
    p448_sqr  (   &L0, &a->y );
    p448_add  ( &a->u,   &L2,   &L0 );
    p448_add  ( &a->t, &a->y, &a->x );
    p448_sqr  (   &L1, &a->t );
    p448_bias (   &L1,     3 );
    p448_sub  ( &a->t,   &L1, &a->u );
    p448_sub  (   &L1,   &L0,   &L2 );
    p448_bias (   &L1,     2 );
    p448_sqr  ( &a->x, &a->z );
    p448_bias ( &a->x,     2 );
    p448_add  ( &a->z, &a->x, &a->x );
    p448_sub  (   &L0, &a->z,   &L1 );
    p448_mul  ( &a->z,   &L1,   &L0 );
    p448_mul  ( &a->x,   &L0, &a->t );
    p448_mul  ( &a->y,   &L1, &a->u );
}

void
p448_extensible_double (
    struct extensible_t* a
) {
    struct p448_t L0, L1, L2;
    p448_sqr  (   &L2, &a->x );
    p448_sqr  (   &L0, &a->y );
    p448_add  (   &L1,   &L2,   &L0 );
    p448_add  ( &a->t, &a->y, &a->x );
    p448_sqr  ( &a->u, &a->t );
    p448_bias ( &a->u,     3 );
    p448_sub  ( &a->t, &a->u,   &L1 );
    p448_sub  ( &a->u,   &L0,   &L2 );
    p448_bias ( &a->u,     2 );
    p448_sqr  ( &a->x, &a->z );
    p448_bias ( &a->x,     2 );
    p448_add  ( &a->z, &a->x, &a->x );
    p448_sub  (   &L0, &a->z,   &L1 );
    p448_mul  ( &a->z,   &L1,   &L0 );
    p448_mul  ( &a->x,   &L0, &a->t );
    p448_mul  ( &a->y,   &L1, &a->u );
}

void
p448_isogeny_un_to_tw (
    struct tw_extensible_t*    b,
    const struct extensible_t* a
) {
    struct p448_t L0;
    p448_sqr  ( &b->x, &a->x );
    p448_sqr  ( &b->z, &a->y );
    p448_add  ( &b->u, &b->x, &b->z );
    p448_add  ( &b->t, &a->y, &a->x );
    p448_sqr  (   &L0, &b->t );
    p448_bias (   &L0,     3 );
    p448_sub  ( &b->t,   &L0, &b->u );
    p448_sub  (   &L0, &b->z, &b->x );
    p448_bias (   &L0,     2 );
    p448_sqr  ( &b->x, &a->z );
    p448_bias ( &b->x,     2 );
    p448_add  ( &b->z, &b->x, &b->x );
    p448_sub  ( &b->y, &b->z, &b->u );
    p448_mul  ( &b->z,   &L0, &b->y );
    p448_mul  ( &b->x, &b->y, &b->t );
    p448_mul  ( &b->y,   &L0, &b->u );
}

void
p448_isogeny_tw_to_un (
    struct extensible_t*          b,
    const struct tw_extensible_t* a
) {
    struct p448_t L0;
    p448_sqr  ( &b->x, &a->x );
    p448_sqr  ( &b->z, &a->y );
    p448_add  (   &L0, &b->x, &b->z );
    p448_add  ( &b->t, &a->y, &a->x );
    p448_sqr  ( &b->u, &b->t );
    p448_bias ( &b->u,     3 );
    p448_sub  ( &b->t, &b->u,   &L0 );
    p448_sub  ( &b->u, &b->z, &b->x );
    p448_bias ( &b->u,     2 );
    p448_sqr  ( &b->x, &a->z );
    p448_bias ( &b->x,     2 );
    p448_add  ( &b->z, &b->x, &b->x );
    p448_sub  ( &b->y, &b->z, &b->u );
    p448_mul  ( &b->z,   &L0, &b->y );
    p448_mul  ( &b->x, &b->y, &b->t );
    p448_mul  ( &b->y,   &L0, &b->u );
}

void
convert_tw_affine_to_tw_pniels (
    struct tw_pniels_t*       b,
    const struct tw_affine_t* a
) {
    p448_sub  ( &b->n.a, &a->y, &a->x );
    p448_bias ( &b->n.a,     2 );
    p448_weak_reduce( &b->n.a );
    p448_add  ( &b->n.b, &a->x, &a->y );
    p448_weak_reduce( &b->n.b );
    p448_mul  ( &b->n.c, &a->y, &a->x );
    p448_mulw ( &b->z, &b->n.c, 78164 );
    p448_neg  ( &b->n.c, &b->z );
    p448_bias ( &b->n.c,     2 );
    p448_weak_reduce( &b->n.c );
    p448_set_ui( &b->z,     2 );
}

void
convert_tw_affine_to_tw_extensible (
    struct tw_extensible_t*   b,
    const struct tw_affine_t* a
) {
    p448_copy ( &b->x, &a->x );
    p448_copy ( &b->y, &a->y );
    p448_set_ui( &b->z,     1 );
    p448_copy ( &b->t, &a->x );
    p448_copy ( &b->u, &a->y );
}

void
convert_affine_to_extensible (
    struct extensible_t*   b,
    const struct affine_t* a
) {
    p448_copy ( &b->x, &a->x );
    p448_copy ( &b->y, &a->y );
    p448_set_ui( &b->z,     1 );
    p448_copy ( &b->t, &a->x );
    p448_copy ( &b->u, &a->y );
}

void
convert_tw_extensible_to_tw_pniels (
    struct tw_pniels_t*           b,
    const struct tw_extensible_t* a
) {
    p448_sub  ( &b->n.a, &a->y, &a->x );
    p448_bias ( &b->n.a,     2 );
    p448_weak_reduce( &b->n.a );
    p448_add  ( &b->n.b, &a->x, &a->y );
    p448_weak_reduce( &b->n.b );
    p448_mul  ( &b->n.c, &a->u, &a->t );
    p448_mulw ( &b->z, &b->n.c, 78164 );
    p448_neg  ( &b->n.c, &b->z );
    p448_bias ( &b->n.c,     2 );
    p448_weak_reduce( &b->n.c );
    p448_add  ( &b->z, &a->z, &a->z );
    p448_weak_reduce( &b->z );
}

void
convert_tw_pniels_to_tw_extensible (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* d
) {
    p448_add  ( &e->u, &d->n.b, &d->n.a );
    p448_sub  ( &e->t, &d->n.b, &d->n.a );
    p448_bias ( &e->t,     2 );
    p448_mul  ( &e->x, &d->z, &e->t );
    p448_mul  ( &e->y, &d->z, &e->u );
    p448_sqr  ( &e->z, &d->z );
}

void
convert_tw_niels_to_tw_extensible (
    struct tw_extensible_t*  e,
    const struct tw_niels_t* d
) {
    p448_add  ( &e->y, &d->b, &d->a );
    p448_weak_reduce( &e->y );
    p448_sub  ( &e->x, &d->b, &d->a );
    p448_bias ( &e->x,     2 );
    p448_weak_reduce( &e->x );
    p448_set_ui( &e->z,     1 );
    p448_copy ( &e->t, &e->x );
    p448_copy ( &e->u, &e->y );
}

void
p448_montgomery_step (
    struct montgomery_t* a
) {
    struct p448_t L0, L1;
    p448_bias ( &a->xd,     2 );
    p448_bias ( &a->xa,     2 );
    p448_add  (   &L0, &a->zd, &a->xd );
    p448_sub  (   &L1, &a->xd, &a->zd );
    p448_sub  ( &a->zd, &a->xa, &a->za );
    p448_mul  ( &a->xd,   &L0, &a->zd );
    p448_bias ( &a->xd,     2 );
    p448_add  ( &a->zd, &a->za, &a->xa );
    p448_mul  ( &a->za,   &L1, &a->zd );
    p448_add  ( &a->xa, &a->za, &a->xd );
    p448_sqr  ( &a->zd, &a->xa );
    p448_mul  ( &a->xa, &a->z0, &a->zd );
    p448_sub  ( &a->zd, &a->xd, &a->za );
    p448_sqr  ( &a->za, &a->zd );
    p448_sqr  ( &a->xd,   &L0 );
    p448_bias ( &a->xd,     2 );
    p448_sqr  (   &L0,   &L1 );
    p448_mulw ( &a->zd, &a->xd, 39082 );
    p448_bias ( &a->zd,     4 );
    p448_sub  (   &L1, &a->xd,   &L0 );
    p448_mul  ( &a->xd,   &L0, &a->zd );
    p448_sub  (   &L0, &a->zd,   &L1 );
    p448_mul  ( &a->zd,   &L0,   &L1 );
}

void
p448_montgomery_serialize (
    struct p448_t*             sign,
    struct p448_t*             ser,
    const struct montgomery_t* a,
    const struct p448_t*       sbz
) {
    struct p448_t L0, L1, L2, L3;
    p448_mul  (   &L2, &a->z0, &a->zd );
    p448_bias (   &L2,     2 );
    p448_sub  (   &L0,   &L2, &a->xd );
    p448_mul  (   &L2, &a->za,   &L0 );
    p448_bias (   &L2,     2 );
    p448_mul  (   &L1, &a->z0, &a->xd );
    p448_bias (   &L1,     2 );
    p448_sub  (   &L0,   &L1, &a->zd );
    p448_mul  (   &L3, &a->xa,   &L0 );
    p448_add  (   &L1,   &L3,   &L2 );
    p448_sub  (   &L0,   &L2,   &L3 );
    p448_mul  (   &L2,   &L0,   &L1 );
    p448_mul  (   &L0,   sbz,   &L2 );
    p448_mul  (   &L2, &a->zd,   &L0 );
    p448_mul  (  sign,   &L2, &a->zd );
    p448_mul  (   ser,   &L2, &a->xd );
    p448_mul  (   &L2,  sign,   ser );
    p448_isr  (   &L1,   &L2 );
    p448_mul  (   ser,  sign,   &L1 );
    p448_sqr  (   &L0,   &L1 );
    p448_mul  (  sign,   &L2,   &L0 );
}

void
extensible_serialize (
    struct p448_t*             b,
    const struct extensible_t* a
) {
    struct p448_t L0, L1, L2;
    p448_sub  (   &L0, &a->y, &a->z );
    p448_bias (   &L0,     2 );
    p448_add  (     b, &a->z, &a->y );
    p448_mul  (   &L1, &a->z, &a->x );
    p448_mul  (   &L2,   &L0,   &L1 );
    p448_mul  (   &L1,   &L2,   &L0 );
    p448_mul  (   &L0,   &L2,     b );
    p448_mul  (   &L2,   &L1,   &L0 );
    p448_isr  (   &L0,   &L2 );
    p448_mul  (     b,   &L1,   &L0 );
    p448_sqr  (   &L1,   &L0 );
    p448_mul  (   &L0,   &L2,   &L1 );
}

void
isogeny_and_serialize (
    struct p448_t*                b,
    const struct tw_extensible_t* a
) {
    struct p448_t L0, L1, L2, L3;
    p448_mul  (   &L3, &a->y, &a->x );
    p448_add  (   &L1, &a->y, &a->x );
    p448_sqr  (     b,   &L1 );
    p448_add  (   &L2,   &L3,   &L3 );
    p448_sub  (   &L1,     b,   &L2 );
    p448_bias (   &L1,     3 );
    p448_sqr  (   &L2, &a->z );
    p448_sqr  (     b,   &L2 );
    p448_add  (   &L2,   &L1,   &L1 );
    p448_mulw (   &L1,   &L2, 39082 );
    p448_neg  (   &L2,   &L1 );
    p448_bias (   &L2,     2 );
    p448_mulw (   &L0,   &L2, 39082 );
    p448_neg  (   &L1,   &L0 );
    p448_bias (   &L1,     2 );
    p448_mul  (   &L0,   &L2,     b );
    p448_mul  (     b,   &L1,   &L0 );
    p448_isr  (   &L0,     b );
    p448_mul  (   &L2,   &L1,   &L0 );
    p448_sqr  (   &L1,   &L0 );
    p448_mul  (   &L0,     b,   &L1 );
    p448_mul  (     b,   &L2,   &L3 );
}

mask_t
affine_deserialize (
    struct affine_t*     a,
    const struct p448_t* sz
) {
    struct p448_t L0, L1, L2, L3;
    p448_sqr  (   &L1,    sz );
    p448_copy (   &L3,   &L1 );
    p448_addw (   &L3,     1 );
    p448_sqr  ( &a->x,   &L3 );
    p448_mulw (   &L3, &a->x, 39082 );
    p448_neg  ( &a->x,   &L3 );
    p448_add  (   &L3,   &L1,   &L1 );
    p448_bias (   &L3,     1 );
    p448_add  ( &a->y,   &L3,   &L3 );
    p448_add  (   &L3, &a->y, &a->x );
    p448_copy ( &a->y,   &L1 );
    p448_subw ( &a->y,     1 );
    p448_neg  ( &a->x, &a->y );
    p448_bias ( &a->x,     2 );
    p448_mul  ( &a->y, &a->x,   &L3 );
    p448_sqr  (   &L2, &a->x );
    p448_mul  (   &L0,   &L2, &a->y );
    p448_mul  ( &a->y, &a->x,   &L0 );
    p448_isr  (   &L3, &a->y );
    p448_mul  ( &a->y,   &L2,   &L3 );
    p448_sqr  (   &L2,   &L3 );
    p448_mul  (   &L3,   &L0,   &L2 );
    p448_mul  (   &L0, &a->x,   &L3 );
    p448_bias (   &L0,     1 );
    p448_add  (   &L2, &a->y, &a->y );
    p448_mul  ( &a->x,    sz,   &L2 );
    p448_addw (   &L1,     1 );
    p448_mul  ( &a->y,   &L1,   &L3 );
    p448_subw (   &L0,     1 );
    return p448_is_zero(   &L0 );
}

void
set_identity_extensible (
    struct extensible_t* a
) {
    p448_set_ui( &a->x,     0 );
    p448_set_ui( &a->y,     1 );
    p448_set_ui( &a->z,     1 );
    p448_set_ui( &a->t,     0 );
    p448_set_ui( &a->u,     0 );
}

void
set_identity_tw_extensible (
    struct tw_extensible_t* a
) {
    p448_set_ui( &a->x,     0 );
    p448_set_ui( &a->y,     1 );
    p448_set_ui( &a->z,     1 );
    p448_set_ui( &a->t,     0 );
    p448_set_ui( &a->u,     0 );
}

void
set_identity_affine (
    struct affine_t* a
) {
    p448_set_ui( &a->x,     0 );
    p448_set_ui( &a->y,     1 );
}

mask_t
eq_affine (
    const struct affine_t* a,
    const struct affine_t* b
) {
    mask_t L0, L1;
    struct p448_t L2;
    p448_sub  (   &L2, &a->x, &b->x );
    p448_bias (   &L2,     2 );
       L1 = p448_is_zero(   &L2 );
    p448_sub  (   &L2, &a->y, &b->y );
    p448_bias (   &L2,     2 );
       L0 = p448_is_zero(   &L2 );
    return    L1 &    L0;
}

mask_t
eq_extensible (
    const struct extensible_t* a,
    const struct extensible_t* b
) {
    mask_t L0, L1;
    struct p448_t L2, L3, L4;
    p448_mul  (   &L4, &b->z, &a->x );
    p448_mul  (   &L3, &a->z, &b->x );
    p448_sub  (   &L2,   &L4,   &L3 );
    p448_bias (   &L2,     2 );
       L1 = p448_is_zero(   &L2 );
    p448_mul  (   &L4, &b->z, &a->y );
    p448_mul  (   &L3, &a->z, &b->y );
    p448_sub  (   &L2,   &L4,   &L3 );
    p448_bias (   &L2,     2 );
       L0 = p448_is_zero(   &L2 );
    return    L1 &    L0;
}

mask_t
eq_tw_extensible (
    const struct tw_extensible_t* a,
    const struct tw_extensible_t* b
) {
    mask_t L0, L1;
    struct p448_t L2, L3, L4;
    p448_mul  (   &L4, &b->z, &a->x );
    p448_mul  (   &L3, &a->z, &b->x );
    p448_sub  (   &L2,   &L4,   &L3 );
    p448_bias (   &L2,     2 );
       L1 = p448_is_zero(   &L2 );
    p448_mul  (   &L4, &b->z, &a->y );
    p448_mul  (   &L3, &a->z, &b->y );
    p448_sub  (   &L2,   &L4,   &L3 );
    p448_bias (   &L2,     2 );
       L0 = p448_is_zero(   &L2 );
    return    L1 &    L0;
}

void
elligator_2s_inject (
    struct affine_t*     a,
    const struct p448_t* r
) {
    mask_t L0, L1;
    struct p448_t L2, L3, L4, L5, L6, L7, L8, L9;
    p448_sqr  ( &a->x,     r );
    p448_sqr  (   &L3, &a->x );
    p448_copy ( &a->y,   &L3 );
    p448_subw ( &a->y,     1 );
    p448_neg  (   &L9, &a->y );
    p448_bias (   &L9,     2 );
    p448_sqr  (   &L2,   &L9 );
    p448_bias (   &L2,     1 );
    p448_mulw (   &L7,   &L2, 1527402724 );
    p448_bias (   &L7,     2 );
    p448_mulw (   &L8,   &L3, 6108985600 );
    p448_add  ( &a->y,   &L8,   &L7 );
    p448_mulw (   &L8,   &L2, 6109454568 );
    p448_sub  (   &L7, &a->y,   &L8 );
    p448_mulw (   &L4, &a->y, 78160 );
    p448_mul  (   &L6,   &L7,   &L9 );
    p448_mul  (   &L8,   &L6,   &L4 );
    p448_mul  (   &L4,   &L7,   &L8 );
    p448_isr  (   &L5,   &L4 );
    p448_mul  (   &L4,   &L6,   &L5 );
    p448_sqr  (   &L6,   &L5 );
    p448_mul  (   &L5,   &L8,   &L6 );
    p448_mul  (   &L8,   &L7,   &L5 );
    p448_mul  (   &L7,   &L8,   &L5 );
    p448_copy (   &L6, &a->x );
    p448_subw (   &L6,     1 );
    p448_addw ( &a->x,     1 );
    p448_mul  (   &L5, &a->x,   &L8 );
    p448_sub  ( &a->x,   &L6,   &L5 );
    p448_bias ( &a->x,     3 );
    p448_mul  (   &L5,   &L4, &a->x );
    p448_mulw (   &L4,   &L5, 78160 );
    p448_neg  ( &a->x,   &L4 );
    p448_bias ( &a->x,     2 );
    p448_weak_reduce( &a->x );
    p448_add  (   &L4,   &L3,   &L3 );
    p448_add  (   &L3,   &L4,   &L2 );
    p448_subw (   &L3,     2 );
    p448_mul  (   &L2,   &L3,   &L8 );
    p448_mulw (   &L3,   &L2, 3054649120 );
    p448_add  (   &L2,   &L3, &a->y );
    p448_mul  ( &a->y,   &L7,   &L2 );
       L1 = p448_is_zero(   &L9 );
       L0 = -   L1;
    p448_addw ( &a->y,    L0 );
    p448_weak_reduce( &a->y );
}

mask_t
p448_affine_validate (
    const struct affine_t* a
) {
    struct p448_t L0, L1, L2, L3;
    p448_sqr  (   &L0, &a->y );
    p448_sqr  (   &L2, &a->x );
    p448_add  (   &L3,   &L2,   &L0 );
    p448_subw (   &L3,     1 );
    p448_mulw (   &L1,   &L2, 39081 );
    p448_neg  (   &L2,   &L1 );
    p448_bias (   &L2,     2 );
    p448_mul  (   &L1,   &L0,   &L2 );
    p448_sub  (   &L0,   &L3,   &L1 );
    p448_bias (   &L0,     3 );
    return p448_is_zero(   &L0 );
}

mask_t
p448_tw_extensible_validate (
    const struct tw_extensible_t* ext
) {
    mask_t L0, L1;
    struct p448_t L2, L3, L4, L5;
    /*
     * Check invariant:
     * 0 = -x*y + z*t*u
     */
    p448_mul  (   &L2, &ext->t, &ext->u );
    p448_mul  (   &L4, &ext->z,   &L2 );
    p448_addw (   &L4,     0 );
    p448_mul  (   &L3, &ext->x, &ext->y );
    p448_neg  (   &L2,   &L3 );
    p448_add  (   &L3,   &L2,   &L4 );
    p448_bias (   &L3,     2 );
       L1 = p448_is_zero(   &L3 );
    /*
     * Check invariant:
     * 0 = d*t^2*u^2 + x^2 - y^2 + z^2 - t^2*u^2
     */
    p448_sqr  (   &L4, &ext->y );
    p448_neg  (   &L2,   &L4 );
    p448_addw (   &L2,     0 );
    p448_sqr  (   &L3, &ext->x );
    p448_bias (   &L3,     4 );
    p448_add  (   &L4,   &L3,   &L2 );
    p448_sqr  (   &L5, &ext->u );
    p448_sqr  (   &L3, &ext->t );
    p448_mul  (   &L2,   &L3,   &L5 );
    p448_mulw (   &L3,   &L2, 39081 );
    p448_neg  (   &L5,   &L3 );
    p448_add  (   &L3,   &L5,   &L4 );
    p448_neg  (   &L5,   &L2 );
    p448_add  (   &L4,   &L5,   &L3 );
    p448_sqr  (   &L3, &ext->z );
    p448_add  (   &L2,   &L3,   &L4 );
       L0 = p448_is_zero(   &L2 );
    return    L1 &    L0;
}


