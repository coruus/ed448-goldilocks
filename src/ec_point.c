/**
 * @cond internal
 * @file ec_point.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @warning This file was automatically generated.
 *     Then it was edited by hand.  Good luck, have fun.
 */

#include "ec_point.h"
#include "magic.h"

#define is32 (GOLDI_BITS == 32)

/* I wanted to just use if (is32)
 * But clang's -Wunreachable-code flags it.
 * I wanted to keep that warning on.
 */
#if (is32)
#define IF32(s) (s)
#else
#define IF32(s)
#endif

/* Multiply by signed curve constant */
static __inline__ void
field_mulw_scc (
    struct field_t* __restrict__ out,
    const struct field_t *a,
    int64_t scc
) {
    if (scc >= 0) {
        field_mulw(out, a, scc);
    } else {
        field_mulw(out, a, -scc);
        field_neg(out,out);
        field_bias(out,2);
    }
}

/* Multiply by signed curve constant and weak reduce if biased */
static __inline__ void
field_mulw_scc_wr (
    struct field_t* __restrict__ out,
    const struct field_t *a,
    int64_t scc
) {
    field_mulw_scc(out, a, scc);
    if (scc < 0)
        field_weak_reduce(out);
}

void
field_isr (
    struct field_t*       a,
    const struct field_t* x
) {
    struct field_t L0, L1, L2;
    field_sqr  (   &L1,     x );
    field_mul  (   &L2,     x,   &L1 );
    field_sqr  (   &L1,   &L2 );
    field_mul  (   &L2,     x,   &L1 );
    field_sqrn (   &L1,   &L2,     3 );
    field_mul  (   &L0,   &L2,   &L1 );
    field_sqrn (   &L1,   &L0,     3 );
    field_mul  (   &L0,   &L2,   &L1 );
    field_sqrn (   &L2,   &L0,     9 );
    field_mul  (   &L1,   &L0,   &L2 );
    field_sqr  (   &L0,   &L1 );
    field_mul  (   &L2,     x,   &L0 );
    field_sqrn (   &L0,   &L2,    18 );
    field_mul  (   &L2,   &L1,   &L0 );
    field_sqrn (   &L0,   &L2,    37 );
    field_mul  (   &L1,   &L2,   &L0 );
    field_sqrn (   &L0,   &L1,    37 );
    field_mul  (   &L1,   &L2,   &L0 );
    field_sqrn (   &L0,   &L1,   111 );
    field_mul  (   &L2,   &L1,   &L0 );
    field_sqr  (   &L0,   &L2 );
    field_mul  (   &L1,     x,   &L0 );
    field_sqrn (   &L0,   &L1,   223 );
    field_mul  (     a,   &L2,   &L0 );
}

void
add_tw_niels_to_tw_extensible (
    struct tw_extensible_t*  d,
    const struct tw_niels_t* e
) {
    struct field_t L0, L1;
    field_sub  (   &L1, &d->y, &d->x );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  (   &L0, &e->a,   &L1 );
    field_add  (   &L1, &d->x, &d->y );
    field_mul  ( &d->y, &e->b,   &L1 );
    field_mul  (   &L1, &d->u, &d->t );
    field_mul  ( &d->x, &e->c,   &L1 );
    field_add  ( &d->u,   &L0, &d->y );
    field_sub  ( &d->t, &d->y,   &L0 );
    field_bias ( &d->t,     2 );
    IF32( field_weak_reduce( &d->t ) );
    field_sub  ( &d->y, &d->z, &d->x );
    field_bias ( &d->y,     2 );
    IF32( field_weak_reduce( &d->y ) );
    field_add  (   &L0, &d->x, &d->z );
    field_mul  ( &d->z,   &L0, &d->y );
    field_mul  ( &d->x, &d->y, &d->t );
    field_mul  ( &d->y,   &L0, &d->u );
}

void
sub_tw_niels_from_tw_extensible (
    struct tw_extensible_t*  d,
    const struct tw_niels_t* e
) {
    struct field_t L0, L1;
    field_sub  (   &L1, &d->y, &d->x );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  (   &L0, &e->b,   &L1 );
    field_add  (   &L1, &d->x, &d->y );
    field_mul  ( &d->y, &e->a,   &L1 );
    field_mul  (   &L1, &d->u, &d->t );
    field_mul  ( &d->x, &e->c,   &L1 );
    field_add  ( &d->u,   &L0, &d->y );
    field_sub  ( &d->t, &d->y,   &L0 );
    field_bias ( &d->t,     2 );
    IF32( field_weak_reduce( &d->t ) );
    field_add  ( &d->y, &d->x, &d->z );
    field_sub  (   &L0, &d->z, &d->x );
    field_bias (   &L0,     2 );
    IF32( field_weak_reduce(   &L0 ) );
    field_mul  ( &d->z,   &L0, &d->y );
    field_mul  ( &d->x, &d->y, &d->t );
    field_mul  ( &d->y,   &L0, &d->u );
}

void
add_tw_pniels_to_tw_extensible (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* a
) {
    struct field_t L0;
    field_mul  (   &L0, &e->z, &a->z );
    field_copy ( &e->z,   &L0 );
    add_tw_niels_to_tw_extensible(     e, &a->n );
}

void
sub_tw_pniels_from_tw_extensible (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* a
) {
    struct field_t L0;
    field_mul  (   &L0, &e->z, &a->z );
    field_copy ( &e->z,   &L0 );
    sub_tw_niels_from_tw_extensible(     e, &a->n );
}

void
double_tw_extensible (
    struct tw_extensible_t* a
) {
    struct field_t L0, L1, L2;
    field_sqr  (   &L2, &a->x );
    field_sqr  (   &L0, &a->y );
    field_add  ( &a->u,   &L2,   &L0 );
    field_add  ( &a->t, &a->y, &a->x );
    field_sqr  (   &L1, &a->t );
    field_sub  ( &a->t,   &L1, &a->u );
    field_bias ( &a->t,     3 );
    IF32( field_weak_reduce( &a->t ) );
    field_sub  (   &L1,   &L0,   &L2 );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_sqr  ( &a->x, &a->z );
    field_bias ( &a->x,     2-is32 /*is32 ? 1 : 2*/ );
    field_add  ( &a->z, &a->x, &a->x );
    field_sub  (   &L0, &a->z,   &L1 );
    IF32( field_weak_reduce(   &L0 ) );
    field_mul  ( &a->z,   &L1,   &L0 );
    field_mul  ( &a->x,   &L0, &a->t );
    field_mul  ( &a->y,   &L1, &a->u );
}

void
double_extensible (
    struct extensible_t* a
) {
    struct field_t L0, L1, L2;
    field_sqr  (   &L2, &a->x );
    field_sqr  (   &L0, &a->y );
    field_add  (   &L1,   &L2,   &L0 );
    field_add  ( &a->t, &a->y, &a->x );
    field_sqr  ( &a->u, &a->t );
    field_sub  ( &a->t, &a->u,   &L1 );
    field_bias ( &a->t,     3 );
    IF32( field_weak_reduce( &a->t ) );
    field_sub  ( &a->u,   &L0,   &L2 );
    field_bias ( &a->u,     2 );
    IF32( field_weak_reduce( &a->u ) );
    field_sqr  ( &a->x, &a->z );
    field_bias ( &a->x,     2 );
    field_add  ( &a->z, &a->x, &a->x );
    field_sub  (   &L0, &a->z,   &L1 );
    IF32( field_weak_reduce(   &L0 ) );
    field_mul  ( &a->z,   &L1,   &L0 );
    field_mul  ( &a->x,   &L0, &a->t );
    field_mul  ( &a->y,   &L1, &a->u );
}

void
twist_and_double (
    struct tw_extensible_t*    b,
    const struct extensible_t* a
) {
    struct field_t L0;
    field_sqr  ( &b->x, &a->x );
    field_sqr  ( &b->z, &a->y );
    field_add  ( &b->u, &b->x, &b->z );
    field_add  ( &b->t, &a->y, &a->x );
    field_sqr  (   &L0, &b->t );
    field_sub  ( &b->t,   &L0, &b->u );
    field_bias ( &b->t,     3 );
    IF32( field_weak_reduce( &b->t ) );
    field_sub  (   &L0, &b->z, &b->x );
    field_bias (   &L0,     2 );
    IF32( field_weak_reduce(   &L0 ) );
    field_sqr  ( &b->x, &a->z );
    field_bias ( &b->x,     2 );
    field_add  ( &b->z, &b->x, &b->x );
    field_sub  ( &b->y, &b->z, &b->u );
    IF32( field_weak_reduce( &b->y ) );
    field_mul  ( &b->z,   &L0, &b->y );
    field_mul  ( &b->x, &b->y, &b->t );
    field_mul  ( &b->y,   &L0, &b->u );
}

void
untwist_and_double (
    struct extensible_t*          b,
    const struct tw_extensible_t* a
) {
    struct field_t L0;
    field_sqr  ( &b->x, &a->x );
    field_sqr  ( &b->z, &a->y );
    field_add  (   &L0, &b->x, &b->z );
    field_add  ( &b->t, &a->y, &a->x );
    field_sqr  ( &b->u, &b->t );
    field_sub  ( &b->t, &b->u,   &L0 );
    field_bias ( &b->t,     3 );
    IF32( field_weak_reduce( &b->t ) );
    field_sub  ( &b->u, &b->z, &b->x );
    field_bias ( &b->u,     2 );
    IF32( field_weak_reduce( &b->u ) );
    field_sqr  ( &b->x, &a->z );
    field_bias ( &b->x,     2-is32 /*is32 ? 1 : 2*/ );
    field_add  ( &b->z, &b->x, &b->x );
    field_sub  ( &b->y, &b->z, &b->u );
    IF32( field_weak_reduce( &b->y ) );
    field_mul  ( &b->z,   &L0, &b->y );
    field_mul  ( &b->x, &b->y, &b->t );
    field_mul  ( &b->y,   &L0, &b->u );
}

void
convert_tw_affine_to_tw_pniels (
    struct tw_pniels_t*       b,
    const struct tw_affine_t* a
) {
    field_sub  ( &b->n.a, &a->y, &a->x );
    field_bias ( &b->n.a,     2 );
    field_weak_reduce( &b->n.a );
    field_add  ( &b->n.b, &a->x, &a->y );
    field_weak_reduce( &b->n.b );
    field_mul  ( &b->z, &a->y, &a->x );
    field_mulw_scc_wr ( &b->n.c, &b->z, 2*EDWARDS_D-2 );
    field_set_ui( &b->z,     2 );
}

void
convert_tw_affine_to_tw_extensible (
    struct tw_extensible_t*   b,
    const struct tw_affine_t* a
) {
    field_copy ( &b->x, &a->x );
    field_copy ( &b->y, &a->y );
    field_set_ui( &b->z,     1 );
    field_copy ( &b->t, &a->x );
    field_copy ( &b->u, &a->y );
}

void
convert_affine_to_extensible (
    struct extensible_t*   b,
    const struct affine_t* a
) {
    field_copy ( &b->x, &a->x );
    field_copy ( &b->y, &a->y );
    field_set_ui( &b->z,     1 );
    field_copy ( &b->t, &a->x );
    field_copy ( &b->u, &a->y );
}

void
convert_tw_extensible_to_tw_pniels (
    struct tw_pniels_t*           b,
    const struct tw_extensible_t* a
) {
    field_sub  ( &b->n.a, &a->y, &a->x );
    field_bias ( &b->n.a,     2 );
    field_weak_reduce( &b->n.a );
    field_add  ( &b->n.b, &a->x, &a->y );
    field_weak_reduce( &b->n.b );
    field_mul  ( &b->z, &a->u, &a->t );
    field_mulw_scc_wr ( &b->n.c, &b->z, 2*EDWARDS_D-2 );
    field_add  ( &b->z, &a->z, &a->z );
    field_weak_reduce( &b->z );
}

void
convert_tw_pniels_to_tw_extensible (
    struct tw_extensible_t*   e,
    const struct tw_pniels_t* d
) {
    field_add  ( &e->u, &d->n.b, &d->n.a );
    field_sub  ( &e->t, &d->n.b, &d->n.a );
    field_bias ( &e->t,     2 );
    IF32( field_weak_reduce( &e->t ) );
    field_mul  ( &e->x, &d->z, &e->t );
    field_mul  ( &e->y, &d->z, &e->u );
    field_sqr  ( &e->z, &d->z );
}

void
convert_tw_niels_to_tw_extensible (
    struct tw_extensible_t*  e,
    const struct tw_niels_t* d
) {
    field_add  ( &e->y, &d->b, &d->a );
    field_weak_reduce( &e->y );
    field_sub  ( &e->x, &d->b, &d->a );
    field_bias ( &e->x,     2 );
    field_weak_reduce( &e->x );
    field_set_ui( &e->z,     1 );
    field_copy ( &e->t, &e->x );
    field_copy ( &e->u, &e->y );
}

void
montgomery_step (
    struct montgomery_t* a
) {
    struct field_t L0, L1;
    field_add  (   &L0, &a->zd, &a->xd );
    field_sub  (   &L1, &a->xd, &a->zd );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_sub  ( &a->zd, &a->xa, &a->za );
    field_bias ( &a->zd,     2 );
    IF32( field_weak_reduce( &a->zd ) );
    field_mul  ( &a->xd,   &L0, &a->zd );
    field_add  ( &a->zd, &a->za, &a->xa );
    field_mul  ( &a->za,   &L1, &a->zd );
    field_add  ( &a->xa, &a->za, &a->xd );
    field_sqr  ( &a->zd, &a->xa );
    field_mul  ( &a->xa, &a->z0, &a->zd );
    field_sub  ( &a->zd, &a->xd, &a->za );
    field_bias ( &a->zd,     2 );
    IF32( field_weak_reduce( &a->zd ) );
    field_sqr  ( &a->za, &a->zd );
    field_sqr  ( &a->xd,   &L0 );
    field_sqr  (   &L0,   &L1 );
    field_mulw ( &a->zd, &a->xd, 1-EDWARDS_D );
    field_sub  (   &L1, &a->xd,   &L0 );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  ( &a->xd,   &L0, &a->zd );
    field_sub  (   &L0, &a->zd,   &L1 );
    field_bias (   &L0,     4 - 2*is32 /*is32 ? 2 : 4*/ );
    IF32( field_weak_reduce(   &L0 ) );
    field_mul  ( &a->zd,   &L0,   &L1 );
}

void
deserialize_montgomery (
    struct montgomery_t* a,
    const struct field_t* sbz
) {
    field_sqr  ( &a->z0,   sbz );
    field_set_ui( &a->xd,     1 );
    field_set_ui( &a->zd,     0 );
    field_set_ui( &a->xa,     1 );
    field_copy ( &a->za, &a->z0 );
}

mask_t
serialize_montgomery (
    struct field_t*             b,
    const struct montgomery_t* a,
    const struct field_t*       sbz
) {
    mask_t L4, L5, L6;
    struct field_t L0, L1, L2, L3;
    field_mul  (   &L3, &a->z0, &a->zd );
    field_sub  (   &L1,   &L3, &a->xd );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  (   &L3, &a->za,   &L1 );
    field_mul  (   &L2, &a->z0, &a->xd );
    field_sub  (   &L1,   &L2, &a->zd );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  (   &L0, &a->xa,   &L1 );
    field_add  (   &L2,   &L0,   &L3 );
    field_sub  (   &L1,   &L3,   &L0 );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  (   &L3,   &L1,   &L2 );
    field_copy (   &L2, &a->z0 );
    field_addw (   &L2,     1 );
    field_sqr  (   &L1,   &L2 );
    field_mulw (   &L2,   &L1, 1-EDWARDS_D );
    field_neg  (   &L1,   &L2 );
    field_add  (   &L2, &a->z0, &a->z0 );
    field_bias (   &L2,     1 );
    field_add  (   &L0,   &L2,   &L2 );
    field_add  (   &L2,   &L0,   &L1 );
    IF32( field_weak_reduce(   &L2 ) );
    field_mul  (   &L0, &a->xd,   &L2 );
       L5 = field_is_zero( &a->zd );
       L6 = -   L5;
    field_mask (   &L1,   &L0,    L5 );
    field_add  (   &L2,   &L1, &a->zd );
       L4 = ~   L5;
    field_mul  (   &L1,   sbz,   &L3 );
    field_addw (   &L1,    L6 );
    field_mul  (   &L3,   &L2,   &L1 );
    field_mul  (   &L1,   &L3,   &L2 );
    field_mul  (   &L2,   &L3, &a->xd );
    field_mul  (   &L3,   &L1,   &L2 );
    field_isr  (   &L0,   &L3 );
    field_mul  (   &L2,   &L1,   &L0 );
    field_sqr  (   &L1,   &L0 );
    field_mul  (   &L0,   &L3,   &L1 );
    field_mask (     b,   &L2,    L4 );
    field_subw (   &L0,     1 );
    field_bias (   &L0,     1 );
       L5 = field_is_zero(   &L0 );
       L4 = field_is_zero(   sbz );
    return    L5 |    L4;
}

void
serialize_extensible (
    struct field_t*             b,
    const struct extensible_t* a
) {
    struct field_t L0, L1, L2;
    field_sub  (   &L0, &a->y, &a->z );
    field_bias (   &L0,     2 );
    IF32( field_weak_reduce(   &L0 ) );
    field_add  (     b, &a->z, &a->y );
    field_mul  (   &L1, &a->z, &a->x );
    field_mul  (   &L2,   &L0,   &L1 );
    field_mul  (   &L1,   &L2,   &L0 );
    field_mul  (   &L0,   &L2,     b );
    field_mul  (   &L2,   &L1,   &L0 );
    field_isr  (   &L0,   &L2 );
    field_mul  (     b,   &L1,   &L0 );
    field_sqr  (   &L1,   &L0 );
    field_mul  (   &L0,   &L2,   &L1 );
}

void
untwist_and_double_and_serialize (
    struct field_t*                b,
    const struct tw_extensible_t* a
) {
    struct field_t L0, L1, L2, L3;
    field_mul  (   &L3, &a->y, &a->x );
    field_add  (     b, &a->y, &a->x );
    field_sqr  (   &L1,     b );
    field_add  (   &L2,   &L3,   &L3 );
    field_sub  (     b,   &L1,   &L2 );
    field_bias (     b,     3 );
    IF32( field_weak_reduce(     b ) );
    field_sqr  (   &L2, &a->z );
    field_sqr  (   &L1,   &L2 );
    field_add  (   &L2,     b,     b );
    field_mulw (     b,   &L2, 1-EDWARDS_D );
    field_neg  (   &L2,     b );
    field_bias (   &L2,     2 );
    field_mulw (   &L0,   &L2, 1-EDWARDS_D );
    field_neg  (     b,   &L0 );
    field_bias (     b,     2 );
    field_mul  (   &L0,   &L2,   &L1 );
    field_mul  (   &L2,     b,   &L0 );
    field_isr  (   &L0,   &L2 );
    field_mul  (   &L1,     b,   &L0 );
    field_sqr  (     b,   &L0 );
    field_mul  (   &L0,   &L2,     b );
    field_mul  (     b,   &L1,   &L3 );
}

void
twist_even (
    struct tw_extensible_t*    b,
    const struct extensible_t* a
) {
    mask_t L0, L1;
    field_sqr  ( &b->y, &a->z );
    field_sqr  ( &b->z, &a->x );
    field_sub  ( &b->u, &b->y, &b->z );
    field_bias ( &b->u,     2 );
    IF32( field_weak_reduce( &b->u ) );
    field_sub  ( &b->z, &a->z, &a->x );
    field_bias ( &b->z,     2 );
    IF32( field_weak_reduce( &b->z ) );
    field_mul  ( &b->y, &b->z, &a->y );
    field_sub  ( &b->z, &a->z, &a->y );
    field_bias ( &b->z,     2 );
    IF32( field_weak_reduce( &b->z ) );
    field_mul  ( &b->x, &b->z, &b->y );
    field_mul  ( &b->t, &b->x, &b->u );
    field_mul  ( &b->y, &b->x, &b->t );
    field_isr  ( &b->t, &b->y );
    field_mul  ( &b->u, &b->x, &b->t );
    field_sqr  ( &b->x, &b->t );
    field_mul  ( &b->t, &b->y, &b->x );
    field_mul  ( &b->x, &a->x, &b->u );
    field_mul  ( &b->y, &a->y, &b->u );
       L1 = field_is_zero( &b->z );
       L0 = -   L1;
    field_addw ( &b->y,    L0 );
    field_weak_reduce( &b->y );
    field_set_ui( &b->z,     1 );
    field_copy ( &b->t, &b->x );
    field_copy ( &b->u, &b->y );
}

void
test_only_twist (
    struct tw_extensible_t*    b,
    const struct extensible_t* a
) {
    mask_t L2, L3;
    struct field_t L0, L1;
    field_sqr  ( &b->u, &a->z );
    field_sqr  ( &b->y, &a->x );
    field_sub  ( &b->z, &b->u, &b->y );
    field_bias ( &b->z,     2 );
    field_add  ( &b->y, &b->z, &b->z );
    field_add  ( &b->u, &b->y, &b->y );
    IF32( field_weak_reduce( &b->u ) );
    field_sub  ( &b->y, &a->z, &a->x );
    field_bias ( &b->y,     2 );
    IF32( field_weak_reduce( &b->y ) );
    field_mul  ( &b->x, &b->y, &a->y );
    field_sub  ( &b->z, &a->z, &a->y );
    field_bias ( &b->z,     2 );
    IF32( field_weak_reduce( &b->z ) );
    field_mul  ( &b->t, &b->z, &b->x );
    field_mul  (   &L1, &b->t, &b->u );
    field_mul  ( &b->x, &b->t,   &L1 );
    field_isr  (   &L0, &b->x );
    field_mul  ( &b->u, &b->t,   &L0 );
    field_sqr  (   &L1,   &L0 );
    field_mul  ( &b->t, &b->x,   &L1 );
    field_add  (   &L1, &a->y, &a->x );
    IF32( field_weak_reduce(   &L1 ) );
    field_sub  (   &L0, &a->x, &a->y );
    field_bias (   &L0,     2 );
    IF32( field_weak_reduce(   &L0 ) );
    field_mul  ( &b->x, &b->t,   &L0 );
    field_add  (   &L0, &b->x,   &L1 );
    field_sub  ( &b->t,   &L1, &b->x );
    field_bias ( &b->t,     2 );
    IF32( field_weak_reduce( &b->t ) );
    field_mul  ( &b->x,   &L0, &b->u );
       L2 = field_is_zero( &b->y );
       L3 = -   L2;
    field_addw ( &b->x,    L3 );
    field_weak_reduce( &b->x );
    field_mul  ( &b->y, &b->t, &b->u );
       L2 = field_is_zero( &b->z );
       L3 = -   L2;
    field_addw ( &b->y,    L3 );
    field_weak_reduce( &b->y );
       L3 = field_is_zero( &a->y );
       L2 =    L3 +     1;
    field_set_ui( &b->z,    L2 );
    field_copy ( &b->t, &b->x );
    field_copy ( &b->u, &b->y );
}

mask_t
is_even_pt (
    const struct extensible_t* a
) {
    struct field_t L0, L1, L2;
    field_sqr  (   &L2, &a->z );
    field_sqr  (   &L1, &a->x );
    field_sub  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
    field_weak_reduce(   &L0 );
    return field_is_square (   &L0 );
}

mask_t
is_even_tw (
    const struct tw_extensible_t* a
) {
    struct field_t L0, L1, L2;
    field_sqr  (   &L2, &a->z );
    field_sqr  (   &L1, &a->x );
    field_add  (   &L0,   &L1,   &L2 );
    field_weak_reduce(   &L0 );
    return field_is_square (   &L0 );
}

mask_t
deserialize_affine (
    struct affine_t*     a,
    const struct field_t* sz
) {
    struct field_t L0, L1, L2, L3;
    field_sqr  (   &L1,    sz );
    field_copy (   &L3,   &L1 );
    field_addw (   &L3,     1 );
    field_sqr  (   &L2,   &L3 );
    field_mulw (   &L3,   &L2, 1-EDWARDS_D );
    field_neg  ( &a->x,   &L3 );
    field_add  (   &L3,   &L1,   &L1 );
    field_bias (   &L3,     1 );
    field_add  ( &a->y,   &L3,   &L3 );
    field_add  (   &L3, &a->y, &a->x );
    IF32( field_weak_reduce(   &L3 ) );
    field_copy ( &a->y,   &L1 );
    field_subw ( &a->y,     1 );
    field_neg  ( &a->x, &a->y );
    field_bias ( &a->x,     2 );
    IF32( field_weak_reduce( &a->x ) );
    field_mul  ( &a->y, &a->x,   &L3 );
    field_sqr  (   &L2, &a->x );
    field_mul  (   &L0,   &L2, &a->y );
    field_mul  ( &a->y, &a->x,   &L0 );
    field_isr  (   &L3, &a->y );
    field_mul  ( &a->y,   &L2,   &L3 );
    field_sqr  (   &L2,   &L3 );
    field_mul  (   &L3,   &L0,   &L2 );
    field_mul  (   &L0, &a->x,   &L3 );
    field_add  (   &L2, &a->y, &a->y );
    field_mul  ( &a->x,    sz,   &L2 );
    field_addw (   &L1,     1 );
    field_mul  ( &a->y,   &L1,   &L3 );
    field_subw (   &L0,     1 );
    field_bias (   &L0,     1 );
    return field_is_zero(   &L0 );
}

mask_t
deserialize_and_twist_approx (
    struct tw_extensible_t* a,
    const struct field_t*    sdm1,
    const struct field_t*    sz
) {
    struct field_t L0, L1;
    field_sqr  ( &a->z,    sz );
    field_copy ( &a->y, &a->z );
    field_addw ( &a->y,     1 );
    field_sqr  ( &a->x, &a->y );
    field_mulw ( &a->y, &a->x, 1-EDWARDS_D );
    field_neg  ( &a->x, &a->y );
    field_add  ( &a->y, &a->z, &a->z );
    field_bias ( &a->y,     1 );
    field_add  ( &a->u, &a->y, &a->y );
    field_add  ( &a->y, &a->u, &a->x );
    IF32( field_weak_reduce( &a->y ) );
    field_sqr  ( &a->x, &a->z );
    field_subw ( &a->x,     1 );
    field_neg  ( &a->u, &a->x );
    field_bias ( &a->u,     2 );
    IF32( field_weak_reduce( &a->u ) );
    field_mul  ( &a->x,  sdm1, &a->u );
    field_mul  (   &L0, &a->x, &a->y );
    field_mul  ( &a->t,   &L0, &a->y );
    field_mul  ( &a->u, &a->x, &a->t );
    field_mul  ( &a->t, &a->u,   &L0 );
    field_mul  ( &a->y, &a->x, &a->t );
    field_isr  (   &L0, &a->y );
    field_mul  ( &a->y, &a->u,   &L0 );
    field_sqr  (   &L1,   &L0 );
    field_mul  ( &a->u, &a->t,   &L1 );
    field_mul  ( &a->t, &a->x, &a->u );
    field_add  ( &a->x,    sz,    sz );
    field_mul  (   &L0, &a->u, &a->x );
    field_copy ( &a->x, &a->z );
    field_subw ( &a->x,     1 );
    field_neg  (   &L1, &a->x );
    field_bias (   &L1,     2 );
    IF32( field_weak_reduce(   &L1 ) );
    field_mul  ( &a->x,   &L1,   &L0 );
    field_mul  (   &L0, &a->u, &a->y );
    field_addw ( &a->z,     1 );
    field_mul  ( &a->y, &a->z,   &L0 );
    field_subw ( &a->t,     1 );
    field_bias ( &a->t,     1 );
    mask_t ret = field_is_zero( &a->t );
    field_set_ui( &a->z,     1 );
    field_copy ( &a->t, &a->x );
    field_copy ( &a->u, &a->y );
    return ret;
}

void
set_identity_extensible (
    struct extensible_t* a
) {
    field_set_ui( &a->x,     0 );
    field_set_ui( &a->y,     1 );
    field_set_ui( &a->z,     1 );
    field_set_ui( &a->t,     0 );
    field_set_ui( &a->u,     0 );
}

void
set_identity_tw_extensible (
    struct tw_extensible_t* a
) {
    field_set_ui( &a->x,     0 );
    field_set_ui( &a->y,     1 );
    field_set_ui( &a->z,     1 );
    field_set_ui( &a->t,     0 );
    field_set_ui( &a->u,     0 );
}

void
set_identity_affine (
    struct affine_t* a
) {
    field_set_ui( &a->x,     0 );
    field_set_ui( &a->y,     1 );
}

mask_t
eq_affine (
    const struct affine_t* a,
    const struct affine_t* b
) {
    mask_t L1, L2;
    struct field_t L0;
    field_sub  (   &L0, &a->x, &b->x );
    field_bias (   &L0,     2 );
       L2 = field_is_zero(   &L0 );
    field_sub  (   &L0, &a->y, &b->y );
    field_bias (   &L0,     2 );
       L1 = field_is_zero(   &L0 );
    return    L2 &    L1;
}

mask_t
eq_extensible (
    const struct extensible_t* a,
    const struct extensible_t* b
) {
    mask_t L3, L4;
    struct field_t L0, L1, L2;
    field_mul  (   &L2, &b->z, &a->x );
    field_mul  (   &L1, &a->z, &b->x );
    field_sub  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
       L4 = field_is_zero(   &L0 );
    field_mul  (   &L2, &b->z, &a->y );
    field_mul  (   &L1, &a->z, &b->y );
    field_sub  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
       L3 = field_is_zero(   &L0 );
    return    L4 &    L3;
}

mask_t
eq_tw_extensible (
    const struct tw_extensible_t* a,
    const struct tw_extensible_t* b
) {
    mask_t L3, L4;
    struct field_t L0, L1, L2;
    field_mul  (   &L2, &b->z, &a->x );
    field_mul  (   &L1, &a->z, &b->x );
    field_sub  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
       L4 = field_is_zero(   &L0 );
    field_mul  (   &L2, &b->z, &a->y );
    field_mul  (   &L1, &a->z, &b->y );
    field_sub  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
       L3 = field_is_zero(   &L0 );
    return    L4 &    L3;
}

void
elligator_2s_inject (
    struct affine_t*     a,
    const struct field_t* r
) {
    mask_t L0, L1;
    struct field_t L2, L3, L4, L5, L6, L7, L8;
    field_sqr  ( &a->x,     r );
    field_sqr  (   &L3, &a->x );
    field_copy ( &a->y,   &L3 );
    field_subw ( &a->y,     1 );
    field_neg  (   &L4, &a->y );
    field_bias (   &L4,     2 );
    IF32( field_weak_reduce(   &L4 ) );
    field_sqr  (   &L2,   &L4 );
    field_mulw (   &L7,   &L2, (EDWARDS_D-1)*(EDWARDS_D-1) );
    field_mulw (   &L8,   &L3, 4*(EDWARDS_D+1)*(EDWARDS_D+1) );
    field_add  ( &a->y,   &L8,   &L7 );
    IF32( field_weak_reduce( &a->y ) );
    field_mulw (   &L8,   &L2, 4*(EDWARDS_D)*(EDWARDS_D-1) );
    field_sub  (   &L7, &a->y,   &L8 );
    field_bias (   &L7,     2 );
    IF32( field_weak_reduce(   &L7 ) );
    field_mulw_scc (   &L6, &a->y, -2-2*EDWARDS_D );
    field_mul  (   &L5,   &L7,   &L6 );
    field_mul  (   &L8,   &L5,   &L4 );
    field_mul  (   &L4,   &L5,   &L6 );
    field_mul  (   &L5,   &L7,   &L8 );
    field_mul  (   &L8,   &L5,   &L4 );
    field_mul  (   &L4,   &L7,   &L8 );
    field_isr  (   &L6,   &L4 );
    field_mul  (   &L4,   &L5,   &L6 );
    field_sqr  (   &L5,   &L6 );
    field_mul  (   &L6,   &L8,   &L5 );
    field_mul  (   &L8,   &L7,   &L6 );
    field_mul  (   &L7,   &L8,   &L6 );
    field_copy (   &L6, &a->x );
    field_subw (   &L6,     1 );
    field_addw ( &a->x,     1 );
    field_mul  (   &L5, &a->x,   &L8 );
    field_sub  ( &a->x,   &L6,   &L5 );
    field_bias ( &a->x,     3 );
    IF32( field_weak_reduce( &a->x ) );
    field_mul  (   &L5,   &L4, &a->x );
    field_mulw_scc_wr (   &a->x,   &L5, -2-2*EDWARDS_D );
    field_add  (   &L4,   &L3,   &L3 );
    field_add  (   &L3,   &L4,   &L2 );
    field_subw (   &L3,     2 );
    field_bias (   &L3,     1 );
    IF32( field_weak_reduce(   &L3 ) );
    field_mul  (   &L2,   &L3,   &L8 );
    field_mulw (   &L3,   &L2, 2*(EDWARDS_D+1)*(EDWARDS_D-1) );
    field_add  (   &L2,   &L3, &a->y );
    field_mul  ( &a->y,   &L7,   &L2 );
       L1 = field_is_zero(   &L8 );
       L0 = -   L1;
    field_addw ( &a->y,    L0 );
    field_weak_reduce( &a->y );
}

mask_t
validate_affine (
    const struct affine_t* a
) {
    struct field_t L0, L1, L2, L3;
    field_sqr  (   &L0, &a->y );
    field_sqr  (   &L1, &a->x );
    field_add  (   &L3,   &L1,   &L0 );
    field_subw (   &L3,     1 );
    field_mulw_scc (   &L2,   &L1, EDWARDS_D );
    field_mul  (   &L1,   &L0,   &L2 );
    field_sub  (   &L0,   &L3,   &L1 );
    field_bias (   &L0,     3 );
    return field_is_zero(   &L0 );
}

mask_t
validate_tw_extensible (
    const struct tw_extensible_t* ext
) {
    mask_t L4, L5;
    struct field_t L0, L1, L2, L3;
    /*
     * Check invariant:
     * 0 = -x*y + z*t*u
     */
    field_mul  (   &L1, &ext->t, &ext->u );
    field_mul  (   &L2, &ext->z,   &L1 );
    field_mul  (   &L0, &ext->x, &ext->y );
    field_neg  (   &L1,   &L0 );
    field_add  (   &L0,   &L1,   &L2 );
    field_bias (   &L0,     2 );
       L5 = field_is_zero(   &L0 );
    /*
     * Check invariant:
     * 0 = d*t^2*u^2 + x^2 - y^2 + z^2 - t^2*u^2
     */
    field_sqr  (   &L2, &ext->y );
    field_neg  (   &L1,   &L2 );
    field_sqr  (   &L0, &ext->x );
    field_add  (   &L2,   &L0,   &L1 );
    field_sqr  (   &L3, &ext->u );
    field_sqr  (   &L0, &ext->t );
    field_mul  (   &L1,   &L0,   &L3 );
    field_mulw_scc (   &L3,   &L1, EDWARDS_D );
    field_add  (   &L0,   &L3,   &L2 );
    field_neg  (   &L3,   &L1 );
    field_add  (   &L2,   &L3,   &L0 );
    field_sqr  (   &L1, &ext->z );
    field_add  (   &L0,   &L1,   &L2 );
    field_bias (   &L0,     2 );
       L4 = field_is_zero(   &L0 );
    return    L5 & L4 &~ field_is_zero(&ext->z);
}

mask_t
validate_extensible (
    const struct extensible_t* ext
) {
    mask_t L4, L5;
    struct field_t L0, L1, L2, L3;
    /*
     * Check invariant:
     * 0 = d*t^2*u^2 - x^2 - y^2 + z^2
     */
    field_sqr  (   &L2, &ext->y );
    field_neg  (   &L1,   &L2 );
    field_sqr  (   &L0, &ext->z );
    field_add  (   &L2,   &L0,   &L1 );
    field_sqr  (   &L3, &ext->u );
    field_sqr  (   &L0, &ext->t );
    field_mul  (   &L1,   &L0,   &L3 );
    field_mulw_scc (   &L0,   &L1, EDWARDS_D );
    field_add  (   &L1,   &L0,   &L2 );
    field_sqr  (   &L0, &ext->x );
    field_neg  (   &L2,   &L0 );
    field_add  (   &L0,   &L2,   &L1 );
    field_bias (   &L0,     2 );
       L5 = field_is_zero(   &L0 );
    /*
     * Check invariant:
     * 0 = -x*y + z*t*u
     */
    field_mul  (   &L1, &ext->t, &ext->u );
    field_mul  (   &L2, &ext->z,   &L1 );
    field_mul  (   &L0, &ext->x, &ext->y );
    field_neg  (   &L1,   &L0 );
    field_add  (   &L0,   &L1,   &L2 );
    field_bias (   &L0,     2 );
       L4 = field_is_zero(   &L0 );
    return L5 & L4 &~ field_is_zero(&ext->z);
}
