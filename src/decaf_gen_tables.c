/* Copyright (c) 2015 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/**
 * @file decaf_precompute.c
 * @author Mike Hamburg
 * @brief Decaf global constant table precomputation.
 */

#define _XOPEN_SOURCE 600 /* for posix_memalign */
#include <stdio.h>
#include <stdlib.h>
#include "decaf.h"
#include "decaf_448_config.h" /* MAGIC */
#include "field.h"

#define API_NS(_id) decaf_448_##_id
#define API_NS2(_pref,_id) _pref##_decaf_448_##_id

 /* To satisfy linker. */
const field_t API_NS(precomputed_base_as_fe)[1];
const API_NS(scalar_t) API_NS(precomputed_scalarmul_adjustment);
const API_NS(scalar_t) API_NS(point_scalarmul_adjustment);
const API_NS(scalar_t) sc_r2 = {{{0}}};
const decaf_word_t MONTGOMERY_FACTOR = 0;
const unsigned char base_point_ser_for_pregen[DECAF_448_SER_BYTES];

const API_NS(point_t) API_NS(point_base);

struct niels_s;
const field_t *API_NS(precomputed_wnaf_as_fe);
extern const size_t API_NS2(sizeof,precomputed_wnafs);

void API_NS(precompute_wnafs) (
    struct niels_s *out,
    const API_NS(point_t) base
);

/* TODO: use SC_LIMB? */
static void scalar_print(const char *name, const API_NS(scalar_t) sc) {
    printf("const API_NS(scalar_t) %s = {{{\n", name);
    unsigned i;
    for (i=0; i<sizeof(API_NS(scalar_t))/sizeof(decaf_word_t); i++) {
        if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)sc->limb[i] );
    }
    printf("}}};\n\n");
}

static void field_print(const field_t *f) {
    const int FIELD_SER_BYTES = (FIELD_BITS + 7) / 8;
    unsigned char ser[FIELD_SER_BYTES];
    field_serialize(ser,f);
    int b=0, i, comma=0;
    unsigned long long limb = 0;
    printf("FIELD_LITERAL(");
    for (i=0; i<FIELD_SER_BYTES; i++) {
        limb |= ((uint64_t)ser[i])<<b;
        b += 8;
        if (b >= FIELD_LIT_LIMB_BITS) {
            limb &= (1ull<<FIELD_LIT_LIMB_BITS) -1;
            b -= FIELD_LIT_LIMB_BITS;
            if (comma) printf(",");
            comma = 1;
            printf("0x%016llx", limb);
            limb = ((uint64_t)ser[i])>>(8-b);
        }
    }
    printf(")");
    assert(b<8);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    API_NS(point_t) real_point_base;
    int ret = API_NS(point_decode)(real_point_base,base_point_ser_for_pregen,0);
    if (!ret) return 1;
    
    API_NS(precomputed_s) *pre;
    ret = posix_memalign((void**)&pre, API_NS2(alignof,precomputed_s), API_NS2(sizeof,precomputed_s));
    if (ret || !pre) return 1;
    API_NS(precompute)(pre, real_point_base);
    
    struct niels_s *preWnaf;
    ret = posix_memalign((void**)&preWnaf, API_NS2(alignof,precomputed_s), API_NS2(sizeof,precomputed_wnafs));
    if (ret || !preWnaf) return 1;
    API_NS(precompute_wnafs)(preWnaf, real_point_base);

    const field_t *output;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"field.h\"\n\n");
    printf("#include \"decaf.h\"\n\n");
    printf("#define API_NS(_id) decaf_448_##_id\n");
    printf("#define API_NS2(_pref,_id) _pref##_decaf_448_##_id\n");
    
    output = (const field_t *)real_point_base;
    printf("const API_NS(point_t) API_NS(point_base) = {{\n");
    for (i=0; i < sizeof(API_NS(point_t)); i+=sizeof(field_t)) {
        if (i) printf(",\n  ");
        printf("{");
        field_print(output++);
        printf("}");
    }
    printf("\n}};\n");
    
    output = (const field_t *)pre;
    printf("const field_t API_NS(precomputed_base_as_fe)[%d]\n", 
        (int)(API_NS2(sizeof,precomputed_s) / sizeof(field_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS2(alignof,precomputed_s));
    
    for (i=0; i < API_NS2(sizeof,precomputed_s); i+=sizeof(field_t)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    output = (const field_t *)preWnaf;
    printf("const field_t API_NS(precomputed_wnaf_as_fe)[%d]\n", 
        (int)(API_NS2(sizeof,precomputed_wnafs) / sizeof(field_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS2(alignof,precomputed_s));
    for (i=0; i < API_NS2(sizeof,precomputed_wnafs); i+=sizeof(field_t)) {
        if (i) printf(",\n  ");
        field_print(output++);
    }
    printf("\n};\n");
    
    API_NS(scalar_t) smadj;
    API_NS(scalar_copy)(smadj,API_NS(scalar_one));

    for (i=0; i<DECAF_COMBS_N*DECAF_COMBS_T*DECAF_COMBS_S; i++) {
        API_NS(scalar_add)(smadj,smadj,smadj);
    }
    API_NS(scalar_sub)(smadj, smadj, API_NS(scalar_one));
    scalar_print("API_NS(precomputed_scalarmul_adjustment)", smadj);
    
    API_NS(scalar_copy)(smadj,API_NS(scalar_one));
    for (i=0; i<DECAF_448_SCALAR_BITS-1 + DECAF_WINDOW_BITS
            - ((DECAF_448_SCALAR_BITS-1)%DECAF_WINDOW_BITS); i++) {
        API_NS(scalar_add)(smadj,smadj,smadj);
    }
    API_NS(scalar_sub)(smadj, smadj, API_NS(scalar_one));
    scalar_print("API_NS(point_scalarmul_adjustment)", smadj);
    
    API_NS(scalar_copy)(smadj,API_NS(scalar_one));
    for (i=0; i<sizeof(API_NS(scalar_t))*8*2; i++) {
        API_NS(scalar_add)(smadj,smadj,smadj);
    }
    scalar_print("sc_r2", smadj);
    
    API_NS(scalar_sub)(smadj,API_NS(scalar_zero),API_NS(scalar_one)); /* HACK */
    
    unsigned long long w = 1, plo = smadj->limb[0]+1;
#if DECAF_WORD_BITS == 32
    plo |= ((unsigned long long)smadj->limb[1]) << 32;
#endif
    for (i=0; i<6; i++) {
        w *= w*plo + 2;
    }
    printf("const decaf_word_t MONTGOMERY_FACTOR = (decaf_word_t)0x%016llxull;\n\n", w);
    
    return 0;
}
