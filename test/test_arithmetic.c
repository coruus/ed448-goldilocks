#include "p448.h"
#include "test.h"
#include <gmp.h>
#include <string.h>
#include <stdio.h>

mpz_t mp_p448;

static mask_t mpz_to_p448 (
    struct p448_t *out,
    const mpz_t in
) {
    uint8_t ser[56];
    mpz_t modded;
    memset(ser,0,sizeof(ser));
    mpz_init(modded);
    mpz_mod(modded, in, mp_p448);
    mpz_export(ser, NULL, -1, 1, -1, 0, modded);
    mask_t succ = p448_deserialize(out, ser);
    return succ;
}

static mask_t p448_assert_eq_gmp(
    const char *descr,
    const struct p448_t *x,
    const mpz_t y,
    float lowBound,
    float highBound
) {
    uint8_t xser[56], yser[56];
    mpz_t modded;
    
    memset(yser,0,sizeof(yser));
    
    p448_serialize(xser, x);
    
    mpz_init(modded);
    mpz_mod(modded, y, mp_p448);
    mpz_export(yser, NULL, -1, 1, -1, 0, modded);
    
    unsigned int i;
    for (i=0; i<sizeof(*x)/sizeof(x->limb[0]); i++) {
        int bits = sizeof(x->limb[0]) * 448 / sizeof(*x);
        word_t yardstick = (i==sizeof(*x)/sizeof(x->limb[0])/2) ?
            (1ull<<bits) - 2 : (1ull<<bits) - 1;
        if (x->limb[i] < yardstick * lowBound || x->limb[i] > yardstick * highBound) {
            youfail();
            printf("    P448 limb %d -> " PRIxWORDfull " is out of bounds (%0.2f, %0.2f) for test %s (yardstick = " PRIxWORDfull ")\n",
                 i, x->limb[i], lowBound, highBound, descr, yardstick);
            break;
        }
    }
    
    if (memcmp(xser,yser,56)) {
        youfail();
        printf("    Failed arithmetic test %s\n", descr);
        p448_print("    p448", x);
        printf("    gmp  = 0x");
        int j;
        for (j=55; j>=0; j--) {
            printf("%02x", yser[j]);
        }
        printf("\n");
        return MASK_FAILURE;
    }
    
    mpz_clear(modded);
    return MASK_SUCCESS;
}

static mask_t test_add_sub (
    const mpz_t x,
    const mpz_t y,
    word_t word
) {
    struct p448_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_p448(&xx,x);
    succ &= mpz_to_p448(&yy,y);
    mpz_init(t);
    
    p448_add(&tt,&xx,&yy);
    mpz_add(t,x,y);
    succ &= p448_assert_eq_gmp("add",&tt,t,0,2.1);
    
    p448_sub(&tt,&xx,&yy);
    p448_bias(&tt,2);
    mpz_sub(t,x,y);
    succ &= p448_assert_eq_gmp("sub",&tt,t,0,3.1);
    
    p448_copy(&tt,&xx);
    p448_addw(&tt,word);
    mpz_add_ui(t,x,word);
    succ &= p448_assert_eq_gmp("addw",&tt,t,0,2.1);
    
    p448_copy(&tt,&xx);
    p448_subw(&tt,word);
    p448_bias(&tt,1);
    mpz_sub_ui(t,x,word);
    succ &= p448_assert_eq_gmp("subw",&tt,t,0,2.1);
    
    if (!succ) {
        p448_print("    x", &xx);
        p448_print("    y", &yy);
    }
    
    mpz_clear(t);
    
    return succ;
}

static mask_t test_mul_sqr (
    const mpz_t x,
    const mpz_t y,
    word_t word
) {
    struct p448_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_p448(&xx,x);
    succ &= mpz_to_p448(&yy,y);
    mpz_init(t);
    
    p448_mul(&tt,&xx,&yy);
    mpz_mul(t,x,y);
    succ &= p448_assert_eq_gmp("mul",&tt,t,0,1.1);
    
    p448_mulw(&tt,&xx,word);
    mpz_mul_ui(t,x,word);
    succ &= p448_assert_eq_gmp("mulw",&tt,t,0,1.1);
    
    p448_sqr(&tt,&xx);
    mpz_mul(t,x,x);
    succ &= p448_assert_eq_gmp("sqrx",&tt,t,0,1.1);
    
    p448_sqr(&tt,&yy);
    mpz_mul(t,y,y);
    succ &= p448_assert_eq_gmp("sqy",&tt,t,0,1.1);
    
    if (!succ) {
        p448_print("    x", &xx);
        p448_print("    y", &yy);
    }
    
    mpz_clear(t);
    
    return succ;
}

int test_arithmetic () {
    int j, ntests = 100000;
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    
    uint8_t pser[56];
    for (j=0; j<56; j++) {
        pser[j] = (j==28) ? 0xFE : 0xFF;
    }
    mpz_init(mp_p448);
    mpz_import(mp_p448, 56, -1, 1, -1, 0, pser);
    
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    
    mask_t succ = MASK_SUCCESS;
    
    int bits = sizeof(word_t) * 448 / sizeof(p448_t);
    
    for (j=0; j<ntests; j++) {
        if (j&1) {
            mpz_rrandomb(x, state, 448);
            mpz_rrandomb(y, state, 448);
        } else {
            mpz_urandomb(x, state, 448);
            mpz_urandomb(y, state, 448);
        }
        
        word_t word = gmp_urandomm_ui (state, 1ull<<bits);
        
        succ &= test_add_sub(x,y,word);
        succ &= test_mul_sqr(x,y,word);
        
        // TODO: test neg, cond_neg, set_ui, wrd, srd, inv, ...?
    }
    
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(mp_p448);
    gmp_randclear(state);
    
    return succ ? 0 : 1;
}

