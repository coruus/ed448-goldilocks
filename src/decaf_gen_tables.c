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

 /* To satisfy linker. */
const decaf_word_t decaf_448_precomputed_base_as_words[1];
const decaf_448_scalar_t decaf_448_precomputed_scalarmul_adjustment;
const decaf_448_scalar_t decaf_448_point_scalarmul_adjustment;

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
    
    const decaf_word_t *output = (const decaf_word_t *)pre;
    unsigned i;
    
    printf("/** @warning: this file was automatically generated. */\n");
    printf("#include \"decaf.h\"\n\n");
    printf("const decaf_word_t decaf_448_precomputed_base_as_words[%d]\n", 
        (int)(sizeof_decaf_448_precomputed_s / sizeof(decaf_word_t)));
    printf("__attribute__((aligned(%d))) = {\n  ", (int)alignof_decaf_448_precomputed_s);
    
    for (i=0; i < sizeof_decaf_448_precomputed_s; i+=sizeof(decaf_word_t)) {
        if (i && (i%8==0)) printf(",\n  ");
        else if (i) printf(", ");
        printf("0x%0*llxull", (int)sizeof(decaf_word_t)*2, (unsigned long long)*output );
        output++;
    }
    printf("\n};\n");
    
    decaf_448_scalar_t smadj;
    decaf_448_scalar_copy(smadj,decaf_448_scalar_one);

    const unsigned int n = 5, t = 5, s = 18; // TODO MAGIC
    for (i=0; i<n*t*s; i++) {
        decaf_448_scalar_add(smadj,smadj,smadj);
    }
    decaf_448_scalar_sub(smadj, smadj, decaf_448_scalar_one);
    scalar_print("decaf_448_precomputed_scalarmul_adjustment", smadj);
    
    const unsigned int WINDOW=5; // TODO magic
    decaf_448_scalar_copy(smadj,decaf_448_scalar_one);
    for (i=0; i<DECAF_448_SCALAR_BITS-1 + WINDOW - ((DECAF_448_SCALAR_BITS-1)%WINDOW); i++) {
        decaf_448_scalar_add(smadj,smadj,smadj);
    }
    decaf_448_scalar_sub(smadj, smadj, decaf_448_scalar_one);
    scalar_print("decaf_448_point_scalarmul_adjustment", smadj);
    
    return 0;
}
