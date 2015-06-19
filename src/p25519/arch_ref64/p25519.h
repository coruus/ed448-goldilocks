/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#ifndef __P255_H__
#define __P255_H__ 1

#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "word.h"

typedef struct p255_t {
  uint64_t limb[5];
} p255_t;

#define LBITS 51
#define FIELD_LITERAL(a,b,c,d,e) {{a,b,c,d,e}}

#ifdef __cplusplus
extern "C" {
#endif

static __inline__ void
p255_add_RAW (
    p255_t *out,
    const p255_t *a,
    const p255_t *b
) __attribute__((unused));
             
static __inline__ void
p255_sub_RAW (
    p255_t *out,
    const p255_t *a,
    const p255_t *b
) __attribute__((unused));
             
static __inline__ void
p255_copy (
    p255_t *out,
    const p255_t *a
) __attribute__((unused));
             
static __inline__ void
p255_weak_reduce (
    p255_t *inout
) __attribute__((unused));
             
void
p255_strong_reduce (
    p255_t *inout
);

static __inline__ void
p255_bias (
    p255_t *inout,
    int amount
) __attribute__((unused));
         
void
p255_mul (
    p255_t *__restrict__ out,
    const p255_t *a,
    const p255_t *b
);

void
p255_mulw (
    p255_t *__restrict__ out,
    const p255_t *a,
    uint64_t b
);

void
p255_sqr (
    p255_t *__restrict__ out,
    const p255_t *a
);

void
p255_serialize (
    uint8_t serial[32],
    const struct p255_t *x
);

mask_t
p255_deserialize (
    p255_t *x,
    const uint8_t serial[32]
);

/* -------------- Inline functions begin here -------------- */

void
p255_add_RAW (
    p255_t *out,
    const p255_t *a,
    const p255_t *b
) {
    unsigned int i;
    for (i=0; i<5; i++) {
        out->limb[i] = a->limb[i] + b->limb[i];
    }
    p255_weak_reduce(out);
}

void
p255_sub_RAW (
    p255_t *out,
    const p255_t *a,
    const p255_t *b
) {
    unsigned int i;
    uint64_t co1 = ((1ull<<51)-1)*2, co2 = co1-36;
    for (i=0; i<5; i++) {
        out->limb[i] = a->limb[i] - b->limb[i] + ((i==0) ? co2 : co1);
    }
    p255_weak_reduce(out);
}

void
p255_copy (
    p255_t *out,
    const p255_t *a
) {
    memcpy(out,a,sizeof(*a));
}

void
p255_bias (
    p255_t *a,
    int amt
) {
    (void) a;
    (void) amt;
}

void
p255_weak_reduce (
    p255_t *a
) {
    uint64_t mask = (1ull<<51) - 1;
    uint64_t tmp = a->limb[5] >> 51;
    int i;
    for (i=7; i>0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i-1]>>51);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp*19;
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __P255_H__ */
