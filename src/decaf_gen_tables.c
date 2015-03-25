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
#include "decaf_448_config.h"

 /* To satisfy linker. */
const decaf_word_t decaf_448_precomputed_base_as_words[1];
const decaf_448_scalar_t decaf_448_precomputed_scalarmul_adjustment;
const decaf_448_scalar_t decaf_448_point_scalarmul_adjustment;

struct niels_s;
const decaf_word_t *decaf_448_precomputed_wnaf_as_words;
extern const size_t sizeof_decaf_448_precomputed_wnafs;

void decaf_448_precompute_wnafs (
    struct niels_s *out,
    const decaf_448_point_t base
);

static void scalar_print(const char *name, const decaf_448_scalar_t sc) {
    printf("const decaf_448_scalar_t %s = {{{\n", name);
    unsigned i;
    for (i=0; i<sizeof(decaf_448_scalar_t)/sizeof(decaf_word_t); i++) {
        if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)sc->limb[i] );
    }
    printf("}}};\n\n");
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    decaf_448_precomputed_s *pre;
    int ret = posix_memalign((void**)&pre, alignof_decaf_448_precomputed_s, sizeof_decaf_448_precomputed_s);
    if (ret || !pre) return 1;
    decaf_448_precompute(pre, decaf_448_point_base);
    
    struct niels_s *preWnaf;
    ret = posix_memalign((void**)&preWnaf, alignof_decaf_448_precomputed_s, sizeof_decaf_448_precomputed_wnafs);
    if (ret || !preWnaf) return 1;
    decaf_448_precompute_wnafs(preWnaf, decaf_448_point_base);

    const decaf_word_t *output = (const decaf_word_t *)pre;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"decaf.h\"\n\n");
    printf("const decaf_word_t decaf_448_precomputed_base_as_words[%d]\n", 
        (int)(sizeof_decaf_448_precomputed_s / sizeof(decaf_word_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)alignof_decaf_448_precomputed_s);
    
    for (i=0; i < sizeof_decaf_448_precomputed_s; i+=sizeof(decaf_word_t)) {
        if (i && (i%8==0)) printf(",\n  ");
        else if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)*output );
        output++;
    }
    printf("\n};\n");
    
    output = (const decaf_word_t *)preWnaf;
    printf("const decaf_word_t decaf_448_precomputed_wnaf_as_words[%d]\n", 
        (int)(sizeof_decaf_448_precomputed_wnafs / sizeof(decaf_word_t)));
    printf("__attribute__((aligned(%d),visibility(\"hidden\"))) = {\n  ", (int)alignof_decaf_448_precomputed_s);
    for (i=0; i < sizeof_decaf_448_precomputed_wnafs; i+=sizeof(decaf_word_t)) {
        if (i && (i%8==0)) printf(",\n  ");
        else if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)*output );
        output++;
    }
    printf("\n};\n");
    
    decaf_448_scalar_t smadj;
    decaf_448_scalar_copy(smadj,decaf_448_scalar_one);

    for (i=0; i<DECAF_COMBS_N*DECAF_COMBS_T*DECAF_COMBS_S; i++) {
        decaf_448_scalar_add(smadj,smadj,smadj);
    }
    decaf_448_scalar_sub(smadj, smadj, decaf_448_scalar_one);
    scalar_print("decaf_448_precomputed_scalarmul_adjustment", smadj);
    
    decaf_448_scalar_copy(smadj,decaf_448_scalar_one);
    for (i=0; i<DECAF_448_SCALAR_BITS-1 + DECAF_WINDOW_BITS
            - ((DECAF_448_SCALAR_BITS-1)%DECAF_WINDOW_BITS); i++) {
        decaf_448_scalar_add(smadj,smadj,smadj);
    }
    decaf_448_scalar_sub(smadj, smadj, decaf_448_scalar_one);
    scalar_print("decaf_448_point_scalarmul_adjustment", smadj);
    
    return 0;
}
