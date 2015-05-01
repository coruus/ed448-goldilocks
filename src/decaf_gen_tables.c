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

#define API_NS(_id) decaf_448_##_id
#define API_NS2(_pref,_id) _pref##_decaf_448_##_id

 /* To satisfy linker. */
const decaf_word_t API_NS(precomputed_base_as_words)[1];
const API_NS(scalar_t) API_NS(precomputed_scalarmul_adjustment);
const API_NS(scalar_t) API_NS(point_scalarmul_adjustment);

struct niels_s;
const decaf_word_t *API_NS(precomputed_wnaf_as_words);
extern const size_t API_NS2(sizeof,precomputed_wnafs);

void API_NS(precompute_wnafs) (
    struct niels_s *out,
    const API_NS(point_t) base
);

static void scalar_print(const char *name, const API_NS(scalar_t) sc) {
    printf("const API_NS(scalar_t) %s = {{{\n", name);
    unsigned i;
    for (i=0; i<sizeof(API_NS(scalar_t))/sizeof(decaf_word_t); i++) {
        if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)sc->limb[i] );
    }
    printf("}}};\n\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    API_NS(precomputed_s) *pre;
    int ret = posix_memalign((void**)&pre, API_NS2(alignof,precomputed_s), API_NS2(sizeof,precomputed_s));
    if (ret || !pre) return 1;
    API_NS(precompute)(pre, API_NS(point_base));
    
    struct niels_s *preWnaf;
    ret = posix_memalign((void**)&preWnaf, API_NS2(alignof,precomputed_s), API_NS2(sizeof,precomputed_wnafs));
    if (ret || !preWnaf) return 1;
    API_NS(precompute_wnafs)(preWnaf, API_NS(point_base));

    const decaf_word_t *output = (const decaf_word_t *)pre;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"decaf.h\"\n\n");
    printf("#define API_NS(_id) decaf_448_##_id\n");
    printf("#define API_NS2(_pref,_id) _pref##_decaf_448_##_id\n");
    printf("const decaf_word_t API_NS(precomputed_base_as_words)[%d]\n", 
        (int)(API_NS2(sizeof,precomputed_s) / sizeof(decaf_word_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS2(alignof,precomputed_s));
    
    for (i=0; i < API_NS2(sizeof,precomputed_s); i+=sizeof(decaf_word_t)) {
        if (i && (i%8==0)) printf(",\n  ");
        else if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)*output );
        output++;
    }
    printf("\n};\n");
    
    output = (const decaf_word_t *)preWnaf;
    printf("const decaf_word_t API_NS(precomputed_wnaf_as_words)[%d]\n", 
        (int)(API_NS2(sizeof,precomputed_wnafs) / sizeof(decaf_word_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)API_NS2(alignof,precomputed_s));
    for (i=0; i < API_NS2(sizeof,precomputed_wnafs); i+=sizeof(decaf_word_t)) {
        if (i && (i%8==0)) printf(",\n  ");
        else if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)*output );
        output++;
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
    
    return 0;
}
