/**
 * @file field.h
 * @brief Generic field header.
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 */

#ifndef __FIELD_H__
#define __FIELD_H__

#include "constant_time.h"
#include "f_field.h"
#include <string.h>

typedef struct field_t field_a_t[1];
#define field_a_restrict_t struct field_t *__restrict__

#define is32 (GOLDI_BITS == 32 || FIELD_BITS != 448)
#if (is32)
#define IF32(s) (s)
#else
#define IF32(s)
#endif

/**
 * Returns 1/sqrt(+- x).
 * 
 * The Legendre symbol of the result is the same as that of the
 * input.
 * 
 * If x=0, returns 0.
 */
void
field_isr (
    field_a_t       a,
    const field_a_t x
);

/**
 * Returns 1/x.
 * 
 * If x=0, returns 0.
 *
 * TODO: this is currently unused in Decaf, but I've left a decl
 * for it because field_inverse is different (and simpler) than
 * field_isqrt for 5-mod-8 fields.
 */
void
field_inverse (
    field_a_t       a,
    const field_a_t x
);
    
/**
 * Square x, n times.
 */
static __inline__ void
__attribute__((unused,always_inline))
field_sqrn (
    field_a_restrict_t y,
    const field_a_t x,
    int n
) {
    field_a_t tmp;
    assert(n>0);
    if (n&1) {
        field_sqr(y,x);
        n--;
    } else {
        field_sqr(tmp,x);
        field_sqr(y,tmp);
        n-=2;
    }
    for (; n; n-=2) {
        field_sqr(tmp,y);
        field_sqr(y,tmp);
    }
}

static __inline__ void
field_subx_RAW (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_sub_RAW ( d, a, b );
    field_bias( d, 2 );
    IF32( field_weak_reduce ( d ) );
}

static __inline__ void
field_sub (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_sub_RAW ( d, a, b );
    field_bias( d, 2 );
    field_weak_reduce ( d );
}

static __inline__ void
field_add (
    field_a_t d,
    const field_a_t a,
    const field_a_t b
) {
    field_add_RAW ( d, a, b );
    field_weak_reduce ( d );
}

/** Require the warning annotation on raw routines */
#define ANALYZE_THIS_ROUTINE_CAREFULLY const int ANNOTATE___ANALYZE_THIS_ROUTINE_CAREFULLY = 0;
#define MUST_BE_CAREFUL (void) ANNOTATE___ANALYZE_THIS_ROUTINE_CAREFULLY
#define field_add_nr(a,b,c) { MUST_BE_CAREFUL; field_add_RAW(a,b,c); }
#define field_sub_nr(a,b,c) { MUST_BE_CAREFUL; field_sub_RAW(a,b,c); }
#define field_subx_nr(a,b,c) { MUST_BE_CAREFUL; field_subx_RAW(a,b,c); }

#endif // __FIELD_H__
