/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "p448.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "crandom.h"
#include "goldilocks.h"

word_t q448_lo[4] = {
    0xdc873d6d54a7bb0dull,
    0xde933d8d723a70aaull,
    0x3bb124b65129c96full,
    0x000000008335dc16ull
};

double now() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  return tv.tv_sec + tv.tv_usec/1000000.0;
}

void p448_randomize( struct crandom_state_t *crand, struct p448_t *a ) {
    crandom_generate(crand, (unsigned char *)a, sizeof(*a));
    p448_strong_reduce(a);
}

void q448_randomize( struct crandom_state_t *crand, uint64_t sk[7] ) {
    crandom_generate(crand, (unsigned char *)sk, sizeof(uint64_t)*7);
}

void p448_print( const char *descr, const struct p448_t *a ) {
    p448_t b;
    p448_copy(&b, a);
    p448_strong_reduce(&b);
    int j;
    printf("%s = 0x", descr);
    for (j=7; j>=0; j--) {
        printf("%014llx", (unsigned long long)b.limb[j]);
    }
    printf("\n");
}

void p448_print_full( const char *descr, const struct p448_t *a ) {
    int j;
    printf("%s = 0x", descr);
    for (j=7; j>=0; j--) {
        printf("%02llx_%014llx ", a->limb[j]>>56, (unsigned long long)a->limb[j]&(1ull<<56)-1);
    }
    printf("\n");
}

void q448_print( const char *descr, const uint64_t secret[7] ) {
    int j;
    printf("%s = 0x", descr);
    for (j=6; j>=0; j--) {
        printf("%016llx", (unsigned long long)secret[j]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    struct tw_extensible_t ext;
    struct extensible_t exta;
    struct tw_niels_t niels;
    struct tw_pniels_t pniels;
    struct affine_t affine;
    struct montgomery_t mb;
    struct p448_t a,b,c,d;
    
    
    double when;
    int i,j;
    
    /* Bad randomness so we can debug. */
    char initial_seed[32];
    for (i=0; i<32; i++) initial_seed[i] = i;
    struct crandom_state_t crand;
    crandom_init_from_buffer(&crand, initial_seed);
    
    uint64_t sk[7],tk[7];
    q448_randomize(&crand, sk);
    
    when = now();
    for (i=0; i<10000000; i++) {
        p448_mul(&c, &b, &a);
    }
    when = now() - when;
    printf("mul:         %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<10000000; i++) {
        p448_sqr(&c, &a);
    }
    when = now() - when;
    printf("sqr:         %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<5000000; i++) {
        p448_mul(&c, &b, &a);
        p448_mul(&a, &b, &c);
    }
    when = now() - when;
    printf("mul dep:     %5.1fns\n", when * 1e9 / i / 2);
    
    when = now();
    for (i=0; i<10000000; i++) {
        p448_mulw(&c, &b, 1234562);
    }
    when = now() - when;
    printf("mulw:        %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<100000; i++) {
        p448_randomize(&crand, &a);
    }
    when = now() - when;
    printf("rand448:     %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<10000; i++) {
        p448_isr(&c, &a);
    }
    when = now() - when;
    printf("isr auto:    %5.1fµs\n", when * 1e6 / i);
    
    for (i=0; i<100; i++) {
        p448_randomize(&crand, &a);
        p448_isr(&d,&a);
        p448_sqr(&b,&d);
        p448_mul(&c,&b,&a);
        p448_sqr(&b,&c);
        p448_subw(&b,1);
        p448_bias(&b,1);
        if (!p448_is_zero(&b)) {
            printf("ISR validation failure!\n");
            p448_print("a", &a);
            p448_print("s", &d);
        }
    }
    
    when = now();
    for (i=0; i<10000; i++) {
        elligator_2s_inject(&affine, &a);
    }
    when = now() - when;
    printf("elligator:   %5.1fµs\n", when * 1e6 / i);
    
    for (i=0; i<100; i++) {
        p448_randomize(&crand, &a);
        elligator_2s_inject(&affine, &a);
        if (!p448_affine_validate(&affine)) {
            printf("Elligator validation failure!\n");
            p448_print("a", &a);
            p448_print("x", &affine.x);
            p448_print("y", &affine.y);
        }
    }
    
    when = now();
    for (i=0; i<10000; i++) {
        affine_deserialize(&affine, &a);
    }
    when = now() - when;
    printf("decompress:  %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<10000; i++) {
        extensible_serialize(&a, &exta);
    }
    when = now() - when;
    printf("compress:    %5.1fµs\n", when * 1e6 / i);
    
    int goods = 0;
    for (i=0; i<100; i++) {
        p448_randomize(&crand, &a);
        mask_t good = affine_deserialize(&affine, &a);
        if (good & !p448_affine_validate(&affine)) {
            printf("Deserialize validation failure!\n");
            p448_print("a", &a);
            p448_print("x", &affine.x);
            p448_print("y", &affine.y);
        } else if (good) {
            goods++;
            convert_affine_to_extensible(&exta,&affine);
            extensible_serialize(&b, &exta);
            p448_sub(&c,&b,&a);
            p448_bias(&c,2);
            if (!p448_is_zero(&c)) {
                printf("Reserialize validation failure!\n");
                p448_print("a", &a);
                p448_print("x", &affine.x);
                p448_print("y", &affine.y);
                affine_deserialize(&affine, &b);
                p448_print("b", &b);
                p448_print("x", &affine.x);
                p448_print("y", &affine.y);
                printf("\n");
            }
        }
    }
    if (goods<i/3) {
        printf("Deserialization validation failure! Deserialized %d/%d points\n", goods, i);
    }
    
    uint64_t lsk[12];
    for (i=0;i<10; i++) {
        for (j=11; j>=0; j--) {
            lsk[j] = random();
            lsk[j] = lsk[j]<<22 ^ random();
            lsk[j] = lsk[j]<<22 ^ random();
        }
    }
    
    when = now();
    for (i=0; i<1000000; i++) {
        barrett_reduce(lsk,12,0,q448_lo,7,4,62);
    }
    when = now() - when;
    printf("barrett red: %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<100000; i++) {
        barrett_mac(lsk,7,lsk,7,lsk,7,q448_lo,7,4,62);
    }
    when = now() - when;
    printf("barrett mac: %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_tw_extensible_add_niels(&ext, &niels);
    }
    when = now() - when;
    printf("exti+niels:  %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_tw_extensible_add_pniels(&ext, &pniels);
    }
    when = now() - when;
    printf("exti+pniels: %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_tw_extensible_double(&ext);
    }
    when = now() - when;
    printf("exti dbl:    %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_isogeny_tw_to_un(&exta, &ext);
    }
    when = now() - when;
    printf("i->a isog:   %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_isogeny_un_to_tw(&ext, &exta);
    }
    when = now() - when;
    printf("a->i isog:   %5.1fns\n", when * 1e9 / i);
    
    when = now();
    for (i=0; i<1000000; i++) {
        p448_montgomery_step(&mb);
    }
    when = now() - when;
    printf("monty step:  %5.1fns\n", when * 1e9 / i);
	
    when = now();
    for (i=0; i<1000; i++) {
        p448_montgomery_ladder(&a,&b,sk,448,0);
    }
    when = now() - when;
    printf("full ladder: %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<1000; i++) {
        edwards_scalar_multiply(&ext,sk);
    }
    when = now() - when;
    printf("edwards smz: %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    int sum = 0;
    for (i=0; i<1000; i++) {
        q448_randomize(&crand, sk);
        sum += edwards_scalar_multiply_vt(&ext,sk);
    }
    when = now() - when;
    printf("edwards vtm: %5.1fµs (%0.2f avg bits = 1.5 + 448/%0.2f)\n",
        when * 1e6 / i, 1.0*sum/i, 448.0*i/(sum-1.5*i));
    
    struct tw_niels_t wnaft[1<<6];
    when = now();
    for (i=0; i<1000; i++) {
        precompute_for_wnaf(wnaft,&ext,6);
    }
    when = now() - when;
    printf("wnaf6 pre:   %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<1000; i++) {
        q448_randomize(&crand, sk);
        edwards_scalar_multiply_vt_pre(&ext,sk,wnaft,6);
    }
    when = now() - when;
    printf("edwards vt6: %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<1000; i++) {
        precompute_for_wnaf(wnaft,&ext,4);
    }
    when = now() - when;
    printf("wnaf4 pre:   %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<1000; i++) {
        q448_randomize(&crand, sk);
        edwards_scalar_multiply_vt_pre(&ext,sk,wnaft,4);
    }
    when = now() - when;
    printf("edwards vt4: %5.1fµs\n", when * 1e6 / i);

    when = now();
    for (i=0; i<1000; i++) {
        precompute_for_wnaf(wnaft,&ext,5);
    }
    when = now() - when;
    printf("wnaf5 pre:   %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<1000; i++) {
        q448_randomize(&crand, sk);
        edwards_scalar_multiply_vt_pre(&ext,sk,wnaft,5);
    }
    when = now() - when;
    printf("edwards vt5: %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    sum = 0;
    for (i=0; i<1000; i++) {
        q448_randomize(&crand, sk);
        q448_randomize(&crand, tk);
        sum += edwards_combo_var_fixed_vt(&ext,sk,tk,wnaft,5);
    }
    when = now() - when;
    printf("vt vf combo: %5.1fµs (avg = %0.3f)\n", when * 1e6 / i, 1.0*sum/i);
    
    when = now();
    for (i=0; i<1000; i++) {
        affine_deserialize(&affine, &a);
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        edwards_scalar_multiply(&ext,sk);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
    }
    when = now() - when;
    printf("edwards sm:  %5.1fµs\n", when * 1e6 / i);
    
    struct tw_niels_t table[80] __attribute__((aligned(32)));

    while (1) {
        p448_randomize(&crand, &a);
        if (affine_deserialize(&affine, &a)) break;
    }
    convert_affine_to_extensible(&exta,&affine);
    p448_isogeny_un_to_tw(&ext,&exta);
    when = now();
    for (i=0; i<1000; i++) {
        precompute_for_combs(table, &ext, 5, 5, 18);
    }
    when = now() - when;
    printf("pre(5,5,18): %5.1fµs\n", when * 1e6 / i);
	
    when = now();
    for (i=0; i<10000; i++) {
        edwards_comb(&ext, sk, table, 5, 5, 18);
    }
    when = now() - when;
    printf("com(5,5,18): %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<10000; i++) {
        edwards_comb(&ext, sk, table, 3, 5, 30);
    }
    when = now() - when;
    printf("com(3,5,30): %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<10000; i++) {
        edwards_comb(&ext, sk, table, 2, 5, 45);
    }
    when = now() - when;
    printf("com(2,5,45): %5.1fµs\n", when * 1e6 / i);

    when = now();
    for (i=0; i<10000; i++) {
        edwards_comb(&ext, sk, table, 8, 4, 14);
    }
    when = now() - when;
    printf("com(4,4,28): %5.1fµs\n", when * 1e6 / i);
    
    when = now();
    for (i=0; i<10000; i++) {
        q448_randomize(&crand, sk);
        edwards_comb(&ext, sk, table, 5, 5, 18);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
    }
    when = now() - when;
    printf("keygen:      %5.1fµs\n", when * 1e6 / i);
    
    printf("\nGoldilocks:\n");
    
    int res = goldilocks_init();
    assert(!res);
    
    uint8_t gpk[56],gsk[56],hsk[56],hpk[56];
    
    when = now();
    for (i=0; i<10000; i++) {
        if (i&1) {
            res = goldilocks_keygen(gsk,gpk);
        } else {
            res = goldilocks_keygen(hsk,hpk);
        }
        assert(!res);
    }
    when = now() - when;
    printf("keygen:      %5.1fµs\n", when * 1e6 / i);
    
    uint8_t ss1[64],ss2[64];
    int gres1,gres2;
    when = now();
    for (i=0; i<10000; i++) {
        if (i&1) {
            gres1 = goldilocks_shared_secret(ss1,gsk,hpk);
        } else {
            gres2 = goldilocks_shared_secret(ss2,hsk,gpk);
        }
    }
    when = now() - when;
    printf("ecdh:        %5.1fµs\n", when * 1e6 / i);
    if (gres1 || gres2 || memcmp(ss1,ss2,56)) {
        printf("[FAIL] %d %d\n",gres1,gres2);
        
        printf("ss1 = ");
        for (i=0; i<56; i++) {
            printf("%02x", ss1[i]);
        }
        printf("\nss2 = ");
        for (i=0; i<56; i++) {
            printf("%02x", ss2[i]);
        }
        printf("\n");
    }
    
    printf("\nTesting...\n");
    
    int failures=0, successes = 0;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
		uint64_t two = 2;
        mask_t good = p448_montgomery_ladder(&b,&a,&two,2,0);
		if (!good) continue;
		
		uint64_t x = rand(), y=rand(), z=x*y;
		p448_montgomery_ladder(&b,&a,&x,64,0);
        p448_montgomery_ladder(&c,&b,&y,64,0);
        p448_montgomery_ladder(&b,&a,&z,64,0);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
		if (!p448_is_zero(&d)) {
            printf("Odd ladder validation failure %d!\n", ++failures);
            p448_print("a", &a);
            printf("x=%llx, y=%llx, z=%llx\n", x,y,z);
            p448_print("c", &c);
            p448_print("b", &b);
			printf("\n");
		}
	}
    
    failures = 0;
    for (i=0; i<1000; i++) {
        mask_t good;
        do {
            p448_randomize(&crand, &a);
            good = affine_deserialize(&affine, &a);
        } while (!good);
        
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
        isogeny_and_serialize(&c, &ext);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (good && !p448_is_zero(&d)){
            printf("Iso+serial validation failure %d!\n", ++failures);
            p448_print("a", &a);
            p448_print("b", &b);
            p448_print("c", &c);
            printf("\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i/3) {
        printf("Iso+serial variation: only %d/%d successful.\n", successes, i);
    }
        
    failures = 0;
    uint64_t four = 4;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
        q448_randomize(&crand, sk);
        
        mask_t good = p448_montgomery_ladder(&b,&a,&four,3,0);
        good &= p448_montgomery_ladder(&c,&b,sk,448,0);
        
        mask_t goodb = affine_deserialize(&affine, &a);
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        edwards_scalar_multiply(&ext,sk);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (good != goodb) {
            printf("Compatibility validation failure %d: good: %d != %d\n", ++failures, (int)(-good), (int)(-goodb));
        } else if (good && !p448_is_zero(&d)){
            printf("Compatibility validation failure %d!\n", ++failures);
            p448_print("a", &a);
            q448_print("s", sk);
            p448_print("c", &c);
            p448_print("b", &b);
            printf("\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i/3) {
        printf("Compatibility variation: only %d/%d successful.\n", successes, i);
    }
        
    successes = failures = 0;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
        q448_randomize(&crand, sk);
		if (!i) bzero(&sk, sizeof(sk));
        
        mask_t good = p448_montgomery_ladder(&b,&a,&four,3,0);
        good &= p448_montgomery_ladder(&c,&b,sk,448,0);
        if (!good) continue;
        
        affine_deserialize(&affine, &a);
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        
        precompute_for_combs(table, &ext, 5, 5, 18);
        edwards_comb(&ext, sk, table, 5, 5, 18);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (!p448_is_zero(&d)){
            printf("Comb validation failure %d!\n", ++failures);
            p448_print("a", &a);
            q448_print("s", sk);
            p448_print("c", &c);
            p448_print("b", &b);
            printf("\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i/3) {
        printf("Comb variation: only %d/%d successful.\n", successes, i);
    }
        
    successes = failures = 0;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
        q448_randomize(&crand, sk);
		if (!i) bzero(&sk, sizeof(sk));
        
        mask_t good = affine_deserialize(&affine, &a);
        if (!good) continue;
        
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        struct tw_extensible_t exu;
        copy_tw_extensible(&exu, &ext);
        
        edwards_scalar_multiply(&ext,sk);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);
        
        edwards_scalar_multiply_vt(&exu,sk);
        p448_isogeny_tw_to_un(&exta,&exu);
        extensible_serialize(&c, &exta);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (!p448_is_zero(&d)){
            printf("WNAF validation failure %d!\n", ++failures);
            p448_print("a", &a);
            q448_print("s", sk);
            p448_print("c", &c);
            p448_print("b", &b);
            printf("\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i/3) {
        printf("WNAF variation: only %d/%d successful.\n", successes, i);
    }
        
    successes = failures = 0;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
        q448_randomize(&crand, sk);
		if (!i) bzero(&sk, sizeof(sk));
        
        mask_t good = affine_deserialize(&affine, &a);
        if (!good) continue;
        
        convert_affine_to_extensible(&exta,&affine);
        p448_isogeny_un_to_tw(&ext,&exta);
        struct tw_extensible_t exu;
        copy_tw_extensible(&exu, &ext);
        
        edwards_scalar_multiply(&ext,sk);
        p448_isogeny_tw_to_un(&exta,&ext);
        extensible_serialize(&b, &exta);

        precompute_for_wnaf(wnaft,&exu,5);
        edwards_scalar_multiply_vt_pre(&exu,sk,wnaft,5);
        p448_isogeny_tw_to_un(&exta,&exu);
        extensible_serialize(&c, &exta);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (!p448_is_zero(&d)){
            printf("PreWNAF validation failure %d!\n", ++failures);
            p448_print("a", &a);
            q448_print("s", sk);
            p448_print("c", &c);
            p448_print("b", &b);
            for (j=0; j<1<<5; j++) {
                printf("WNAFT %d\n", j);
                p448_print("  a",&wnaft[j].a);
                p448_print("  b",&wnaft[j].b);
                p448_print("  c",&wnaft[j].c);
            }
            printf("\n\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i/3) {
        printf("PreWNAF variation: only %d/%d successful.\n", successes, i);
    }
    
    successes = failures = 0;
    for (i=0; i<1000; i++) {
        struct p448_t aa;
        struct tw_extensible_t exu,exv,exw;
        
        mask_t good;
        do {
            p448_randomize(&crand, &a);
            good = affine_deserialize(&affine, &a);
            convert_affine_to_extensible(&exta,&affine);
            p448_isogeny_un_to_tw(&ext,&exta);
        } while (!good);
        do {
            p448_randomize(&crand, &aa);
            good = affine_deserialize(&affine, &aa);
            convert_affine_to_extensible(&exta,&affine);
            p448_isogeny_un_to_tw(&exu,&exta);
        } while (!good);
        p448_randomize(&crand, &aa);
        
        q448_randomize(&crand, sk);
		if (i==0 || i==2) bzero(&sk, sizeof(sk));
        q448_randomize(&crand, tk);
		if (i==0 || i==1) bzero(&tk, sizeof(tk));
        
        copy_tw_extensible(&exv, &ext);
        copy_tw_extensible(&exw, &exu);
        edwards_scalar_multiply(&exv,sk);
        edwards_scalar_multiply(&exw,tk);
        convert_tw_extensible_to_tw_pniels(&pniels, &exw);
        p448_tw_extensible_add_pniels(&exv,&pniels);
        p448_isogeny_tw_to_un(&exta,&exv);
        extensible_serialize(&b, &exta);

        precompute_for_wnaf(wnaft,&exu,5);
        edwards_combo_var_fixed_vt(&ext,sk,tk,wnaft,5);
        p448_isogeny_tw_to_un(&exta,&exv);
        extensible_serialize(&c, &exta);
        
        p448_sub(&d,&b,&c);
        p448_bias(&d,2);
        
        if (!p448_is_zero(&d)){
            printf("PreWNAF combo validation failure %d!\n", ++failures);
            p448_print("a", &a);
            p448_print("A", &aa);
            q448_print("s", sk);
            q448_print("t", tk);
            p448_print("c", &c);
            p448_print("b", &b);
            printf("\n\n");
        } else if (good) {
            successes ++;
        }
    }
    if (successes < i) {
        printf("PreWNAF combo variation: only %d/%d successful.\n", successes, i);
    }
    
    successes = failures = 0;
    for (i=0; i<1000; i++) {
        p448_randomize(&crand, &a);
        
        q448_randomize(&crand, sk);
        q448_randomize(&crand, tk);
        
		uint64_t two = 2;
        mask_t good = p448_montgomery_ladder(&b,&a,&two,2,0);
		p448_montgomery_ladder(&b,&a,sk,448,0);
        p448_montgomery_ladder(&d,&b,tk,448,0);
        p448_montgomery_ladder(&b,&a,tk,448,0);
        p448_montgomery_ladder(&c,&b,sk,448,0);
        
        p448_sub(&b,&c,&d);
        p448_bias(&b,2);
        
        mask_t success = p448_is_zero(&b) | ~good;
        
        if (!success) {
            printf("Ladder validation failure %d!\n", ++failures);
            p448_print("a", &a);
            q448_print("s", sk);
            q448_print("t", tk);
            p448_print("c", &c);
            p448_print("d", &d);
            printf("\n");
        }
    }
    
    return 0;
}
