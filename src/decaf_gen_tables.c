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

const decaf_word_t decaf_448_precomputed_base_as_words[1]; /* To satisfy linker. */

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    decaf_448_precomputed_s *pre;
    posix_memalign((void**)&pre, alignof_decaf_448_precomputed_s, sizeof_decaf_448_precomputed_s);
    if (!pre) return 1;
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
    
    return 0;
}
