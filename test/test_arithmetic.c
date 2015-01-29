#include "field.h"
#include "test.h"
#include "decaf.h"
#include <gmp.h>
#include <string.h>
#include <stdio.h>

mpz_t mp_field;
mpz_t mp_scalar_field;

void decaf_scalar_print (
    const char *descr,
    const decaf_scalar_t scalar
) {
    int j;
    printf("%s = 0x", descr);
    for (j=DECAF_SCALAR_LIMBS-1; j>=0; j--) {
        printf(PRIxWORDfull, scalar->limb[j]);
    }
    printf("\n");
}

static mask_t mpz_to_field (
    field_a_t out,
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

static mask_t mpz_to_scalar (
    decaf_scalar_t out,
    const mpz_t in
) {
    uint8_t ser[DECAF_SCALAR_BYTES];
    mpz_t modded;
    memset(ser,0,sizeof(ser));
    mpz_init(modded);
    mpz_mod(modded, in, mp_scalar_field);
    mpz_export(ser, NULL, -1, 1, -1, 0, modded);
    mask_t succ = decaf_decode_scalar(out, ser);
    return succ;
}

static mask_t scalar_assert_eq_gmp(
    const char *descr,
    const decaf_scalar_t a,
    const decaf_scalar_t b,
    const decaf_scalar_t x,
    const mpz_t ma,
    const mpz_t mb,
    const mpz_t y
) {
    uint8_t xser[FIELD_BYTES], yser[FIELD_BYTES];
    mpz_t modded;
    
    memset(yser,0,sizeof(yser));
    
    decaf_encode_scalar(xser, x);
    
    mpz_init(modded);
    mpz_mod(modded, y, mp_scalar_field);
    mpz_export(yser, NULL, -1, 1, -1, 0, modded);
    
    if (memcmp(xser,yser,FIELD_BYTES)) {
        youfail();
        printf("    Failed arithmetic test %s\n", descr);
        decaf_scalar_print("        a", a);
        decaf_scalar_print("        b", b);
        decaf_scalar_print("    decaf", x);
        // printf("     gmpa = 0x");
        
        int j;
        // mpz_export(yser, NULL, -1, 1, -1, 0, ma);
        // for (j=FIELD_BYTES-1; j>=0; j--) {
        //     printf("%02x", yser[j]);
        // }
        // printf("\n");
        // printf("     gmpb = 0x");
        //
        //
        // mpz_export(yser, NULL, -1, 1, -1, 0, mb);
        // for (j=FIELD_BYTES-1; j>=0; j--) {
        //     printf("%02x", yser[j]);
        // }
        // printf("\n");
        (void)ma; (void)mb;
        
        printf("     gmpy = 0x");

        mpz_export(yser, NULL, -1, 1, -1, 0, modded);
        for (j=FIELD_BYTES-1; j>=0; j--) {
            printf("%02x", yser[j]);
        }
        printf("\n");
        return MASK_FAILURE;
    }
    
    mpz_clear(modded);
    return MASK_SUCCESS;
}

static inline int BRANCH_ON_CONSTANT(int x) {
    __asm__ ("" : "+r"(x));
    return x;
}

static mask_t field_assert_eq_gmp(
    const char *descr,
    const field_a_t a,
    const field_a_t b,
    const field_a_t x,
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
        int radix_bits = 1 + (sizeof(x->limb[0]) * FIELD_BITS - 1) / sizeof(*x);
        word_t yardstick;

        if (BRANCH_ON_CONSTANT(FIELD_BITS == 521) && BRANCH_ON_CONSTANT(sizeof(*x)==12*8)) {
            radix_bits = 58;
        }
        
        yardstick = (1ull<<radix_bits) - 1;

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
        field_print("    a", a);
        field_print("    b", b);
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

static mask_t test_add_sub_RAW (
    const mpz_t x,
    const mpz_t y,
    word_t word
) {
    field_a_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_field(xx,x);
    succ &= mpz_to_field(yy,y);
    mpz_init(t);
    
    field_add_RAW(tt,xx,yy);
    mpz_add(t,x,y);
    succ &= field_assert_eq_gmp("add",xx,yy,tt,t,0,2.1);
    
    field_sub_RAW(tt,xx,yy);
    field_bias(tt,2);
    mpz_sub(t,x,y);
    succ &= field_assert_eq_gmp("sub",xx,yy,tt,t,0,3.1);
    
    field_copy(tt,xx);
    field_addw(tt,word);
    mpz_add_ui(t,x,word);
    succ &= field_assert_eq_gmp("addw",xx,yy,tt,t,0,2.1);
    
    field_copy(tt,xx);
    field_subw(tt,word);
    field_bias(tt,1);
    mpz_sub_ui(t,x,word);
    succ &= field_assert_eq_gmp("subw",xx,yy,tt,t,0,2.1);

    /*
    if (!succ) {
        field_print("    x", &xx);
        field_print("    y", &yy);
    }
    */
    
    mpz_clear(t);
    
    return succ;
}

static mask_t test_scalar (
    const mpz_t x,
    const mpz_t y
) {
    decaf_scalar_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_scalar(xx,x);
    succ &= mpz_to_scalar(yy,y);
    mpz_init(t);
    
    decaf_add_scalars(tt,xx,yy);
    mpz_add(t,x,y);
    succ &= scalar_assert_eq_gmp("scalar add",xx,yy,tt,x,y,t);
    
    decaf_sub_scalars(tt,xx,yy);
    mpz_sub(t,x,y);
    succ &= scalar_assert_eq_gmp("scalar sub",xx,yy,tt,x,y,t);
    
    decaf_mul_scalars(tt,xx,yy);
    mpz_mul(t,x,y);
    succ &= scalar_assert_eq_gmp("scalar mul",xx,yy,tt,x,y,t);
    
    mpz_clear(t);
    
    return succ;
}

static mask_t test_mul_sqr (
    const mpz_t x,
    const mpz_t y,
    word_t word
) {
    field_a_t xx,yy,tt;
    mpz_t t;
    mask_t succ = MASK_SUCCESS;
    succ  = mpz_to_field(xx,x);
    succ &= mpz_to_field(yy,y);
    mpz_init(t);
    
    field_mul(tt,xx,yy);
    mpz_mul(t,x,y);
    succ &= field_assert_eq_gmp("mul",xx,yy,tt,t,0,1.1);
    
    field_mulw(tt,xx,word);
    mpz_mul_ui(t,x,word);
    succ &= field_assert_eq_gmp("mulw",xx,yy,tt,t,0,1.1);
    
    field_sqr(tt,xx);
    mpz_mul(t,x,x);
    succ &= field_assert_eq_gmp("sqrx",xx,yy,tt,t,0,1.1);
    
    field_sqr(tt,yy);
    mpz_mul(t,y,y);
    succ &= field_assert_eq_gmp("sqy",xx,yy,tt,t,0,1.1);
    
    if (!succ) {
        field_print("    x", xx);
        field_print("    y", yy);
    }
    
    mpz_clear(t);
    
    return succ;
}

static mask_t test_isr (
    const mpz_t x
) {
    field_a_t xx,yy,ss,tt;
    mask_t succ = 0;
    succ  = mpz_to_field(xx,x);
    
    field_isr(ss,xx);
    field_sqr(tt,ss);
    field_mul(yy,xx,tt);
    
    field_addw(tt,1);
    succ |= field_is_zero(tt);
    
    field_subw(tt,2);
    field_bias(tt,1);
    succ |= field_is_zero(tt);
    
    field_addw(tt,1);
    if (~succ) {
        youfail();
        printf("ISR failure.\n");
        field_print("    x", xx);
        field_print("    s", ss);
        field_print("    t", tt);
    }
    
    return succ;
}

void dbg_gmp_printf(const mpz_t x);
void dbg_gmp_printf(const mpz_t x) {
    gmp_printf("DEBUG: 0x%Zx\n", x);
}

int test_arithmetic (void) {
    int j, ntests = 100000;
    
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    mpz_init(mp_field);
    mpz_import(mp_field, FIELD_BYTES, -1, 1, -1, 0, FIELD_MODULUS);
    
    mpz_import(mp_scalar_field, DECAF_SCALAR_LIMBS, -1, sizeof(decaf_word_t), -1, 0, decaf_scalar_p);
    
    mpz_t x,y;
    mpz_init(x);
    mpz_init(y);
    
    mask_t succ = MASK_SUCCESS;
    
    int radix_bits = sizeof(word_t) * FIELD_BITS / sizeof(field_a_t);
    
    for (j=0; j<ntests; j++) {
        if (j<256) {
            mpz_set_ui(x,0);
            mpz_set_ui(y,0);
            mpz_setbit(x,(j%16)*28);
            mpz_setbit(y,(j/16)*28);
        } else if (j&1) {
            mpz_rrandomb(x, state, FIELD_BITS);
            mpz_rrandomb(y, state, FIELD_BITS);
        } else {
            mpz_urandomb(x, state, FIELD_BITS);
            mpz_urandomb(y, state, FIELD_BITS);
        }
        
        word_t word = gmp_urandomm_ui (state, 1ull<<radix_bits);
        
        succ &= test_add_sub_RAW(x,y,word);
        succ &= test_mul_sqr(x,y,word);
        succ &= test_scalar(x,y);
        
        if (j < 1000)
            succ &= test_isr(x);
        
        // TODO: test neg, cond_neg_RAW, set_ui, wrd, srd, inv, ...?
    }
    
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(mp_field);
    gmp_randclear(state);
    
    return succ ? 0 : 1;
}

