#include "field.h"
#include "test.h"
#include <gmp.h>
#include <string.h>
#include <stdio.h>

mpz_t mp_field;

static mask_t mpz_to_field (
    struct field_t *out,
    const mpz_t in
) {
    uint8_t ser[FIELD_BYTES];
    mpz_t modded;
    memset(ser,0,sizeof(ser));
    mpz_init(modded);
    mpz_mod(modded, in, mp_field);
    mpz_export(ser, NULL, -1, 1, -1, 0, modded);
    mask_t succ = field_deserialize(out, ser);
    return succ;
}

static mask_t field_assert_eq_gmp(
    const char *descr,
    const struct field_t *x,
    const mpz_t y,
    float lowBound,
    float highBound
) {
    uint8_t xser[FIELD_BYTES], yser[FIELD_BYTES];
    mpz_t modded;
    
    memset(yser,0,sizeof(yser));
    
    field_serialize(xser, x);
    
    mpz_init(modded);
    mpz_mod(modded, y, mp_field);
    mpz_export(yser, NULL, -1, 1, -1, 0, modded);
    
    unsigned int i;
    for (i=0; i<sizeof(*x)/sizeof(x->limb[0]); i++) {
        int radix_bits = sizeof(x->limb[0]) * 448 / sizeof(*x);
        word_t yardstick = (i==sizeof(*x)/sizeof(x->limb[0])/2) ?
            (1ull<<radix_bits) - 2 : (1ull<<radix_bits) - 1; // FIELD_MAGIC
        if (x->limb[i] < yardstick * lowBound || x->limb[i] > yardstick * highBound) {
            youfail();
            printf("    Limb %d -> " PRIxWORDfull " is out of bounds (%0.2f, %0.2f) for test %s (yardstick = " PRIxWORDfull ")\n",
                 i, x->limb[i], lowBound, highBound, descr, yardstick);
            break;
        }
    }
    
    if (memcmp(xser,yser,FIELD_BYTES)) {
        youfail();
        printf("    Failed arithmetic test %s\n", descr);
        field_print("    goldi", x);
        printf("    gmp   = 0x");
        int j;
        for (j=FIELD_BYTES-1; j>=0; j--) {
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
    struct field_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_field(&xx,x);
    succ &= mpz_to_field(&yy,y);
    mpz_init(t);
    
    field_add(&tt,&xx,&yy);
    mpz_add(t,x,y);
    succ &= field_assert_eq_gmp("add",&tt,t,0,2.1);
    
    field_sub(&tt,&xx,&yy);
    field_bias(&tt,2);
    mpz_sub(t,x,y);
    succ &= field_assert_eq_gmp("sub",&tt,t,0,3.1);
    
    field_copy(&tt,&xx);
    field_addw(&tt,word);
    mpz_add_ui(t,x,word);
    succ &= field_assert_eq_gmp("addw",&tt,t,0,2.1);
    
    field_copy(&tt,&xx);
    field_subw(&tt,word);
    field_bias(&tt,1);
    mpz_sub_ui(t,x,word);
    succ &= field_assert_eq_gmp("subw",&tt,t,0,2.1);
    
    if (!succ) {
        field_print("    x", &xx);
        field_print("    y", &yy);
    }
    
    mpz_clear(t);
    
    return succ;
}

static mask_t test_mul_sqr (
    const mpz_t x,
    const mpz_t y,
    word_t word
) {
    struct field_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_field(&xx,x);
    succ &= mpz_to_field(&yy,y);
    mpz_init(t);
    
    field_mul(&tt,&xx,&yy);
    mpz_mul(t,x,y);
    succ &= field_assert_eq_gmp("mul",&tt,t,0,1.1);
    
    field_mulw(&tt,&xx,word);
    mpz_mul_ui(t,x,word);
    succ &= field_assert_eq_gmp("mulw",&tt,t,0,1.1);
    
    field_sqr(&tt,&xx);
    mpz_mul(t,x,x);
    succ &= field_assert_eq_gmp("sqrx",&tt,t,0,1.1);
    
    field_sqr(&tt,&yy);
    mpz_mul(t,y,y);
    succ &= field_assert_eq_gmp("sqy",&tt,t,0,1.1);
    
    if (!succ) {
        field_print("    x", &xx);
        field_print("    y", &yy);
    }
    
    mpz_clear(t);
    
    return succ;
}

int test_arithmetic (void) {
    int j, ntests = 100000;
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    mpz_init(mp_field);
    mpz_import(mp_field, FIELD_BYTES, -1, 1, -1, 0, FIELD_MODULUS);
    
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    
    mask_t succ = MASK_SUCCESS;
    
    int radix_bits = sizeof(word_t) * FIELD_BITS / sizeof(field_t);
    
    for (j=0; j<ntests; j++) {
        if (j<256) {
            mpz_set_ui(x,0);
            mpz_set_ui(y,0);
            mpz_setbit(x,(j%16)*28); // FIELD_MAGIC
            mpz_setbit(y,(j/16)*28); // FIELD_MAGIC
        } else if (j&1) {
            mpz_rrandomb(x, state, FIELD_BITS);
            mpz_rrandomb(y, state, FIELD_BITS);
        } else {
            mpz_urandomb(x, state, FIELD_BITS);
            mpz_urandomb(y, state, FIELD_BITS);
        }
        
        word_t word = gmp_urandomm_ui (state, 1ull<<radix_bits);
        
        succ &= test_add_sub(x,y,word);
        succ &= test_mul_sqr(x,y,word);
        
        // TODO: test neg, cond_neg, set_ui, wrd, srd, inv, ...?
    }
    
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(mp_field);
    gmp_randclear(state);
    
    return succ ? 0 : 1;
}

