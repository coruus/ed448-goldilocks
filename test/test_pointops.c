#include "test.h"

#include <stdio.h>

#include "ec_point.h"
#include "scalarmul.h"
#include "magic.h"
#include "field.h"
#include "crandom.h"


static void
failprint_ext (
    const struct extensible_t *a
) {
    field_a_t zi, scaled;
    field_print("    x", a->x);
    field_print("    y", a->y);
    field_print("    z", a->z);
    field_inverse(zi, a->z);
    field_mul(scaled, zi, a->x);
    field_print("    X", scaled);
    field_mul(scaled, zi, a->y);
    field_print("    Y", scaled);
    printf("\n");
}

static void
failprint_tw_ext (
    const struct tw_extensible_t *a
) {
    failprint_ext((const struct extensible_t *)a);
}

static mask_t
fail_if_different (
    const struct extensible_t *a,
    const struct extensible_t *b,
    const char *faildescr,
    const char *adescr,
    const char *bdescr
) {
    mask_t succ = eq_extensible(a, b);
    
    if (!succ) {
        youfail();
        printf("    %s\n", faildescr);
        
        printf("\n    %s:\n", adescr);
        failprint_ext(a);
        
        printf("\n    %s:\n", bdescr);
        failprint_ext(b);
    }
    
    return succ;
}

static mask_t
validate_ext(
    const struct extensible_t *ext,
    int evenness,
    const char *description
) {
    mask_t succ = validate_extensible(ext), succ2;
    const char *error = "Point isn't on the curve.";
    if (evenness > 0) {
        succ2 = is_even_pt(ext);
        if (succ &~ succ2) error = "Point isn't even.";
        succ &= succ2;
    } else if (evenness < 0) {
        succ2 = is_even_pt(ext);
        if (succ &~ succ2) error = "Point is even but shouldn't be.";
        succ &= succ2;
    } /* FUTURE: quadness */
    
    if (~succ) {
        youfail();
        printf("    %s\n", error);
        printf("    %s\n", description);
        failprint_ext(ext);
    }
    
    return succ;
}

static mask_t
validate_tw_ext(
    const struct tw_extensible_t *ext,
    int evenness,
    const char *description
) {
    mask_t succ = validate_tw_extensible(ext), succ2;
    const char *error = "Point isn't on the twisted curve.";
    if (evenness > 0) {
        succ2 = is_even_tw(ext);
        if (succ &~ succ2) error = "Point isn't even.";
        succ &= succ2;
    } else if (evenness < 0) {
        succ2 = is_even_tw(ext);
        if (succ &~ succ2) error = "Point is even but shouldn't be.";
        succ &= succ2;
    } /* FUTURE: quadness */
    
    if (~succ) {
        youfail();
        printf("    %s\n", error);
        printf("    %s\n", description);
        failprint_tw_ext(ext);
    }
    
    return succ;
}

static mask_t
fail_if_different_tw (
    const struct tw_extensible_t *a,
    const struct tw_extensible_t *b,
    const char *faildescr,
    const char *adescr,
    const char *bdescr
) {
    return fail_if_different(
        (const struct extensible_t *)a, (const struct extensible_t *)b,
        faildescr,adescr,bdescr
    );
}

static int
add_double_test (
    const struct affine_t *base1,
    const struct affine_t *base2 
) {
    mask_t succ = MASK_SUCCESS;
    struct extensible_t exb;
    struct tw_extensible_t text1, text2, texta, textb;
    struct tw_pniels_t pn;
    
    /* Convert to ext */
    convert_affine_to_extensible(&exb, base1);
    succ &= validate_ext(&exb,0,"base1");
    twist_and_double(&text1, &exb);
    succ &= validate_tw_ext(&text1,2,"iso1");
    convert_affine_to_extensible(&exb, base2);
    succ &= validate_ext(&exb,0,"base2");
    twist_and_double(&text2, &exb);
    succ &= validate_tw_ext(&text2,2,"iso2");
    
    /* a + b == b + a? */
    convert_tw_extensible_to_tw_pniels(&pn, &text1);
    copy_tw_extensible(&texta, &text2);
    add_tw_pniels_to_tw_extensible(&texta, &pn);
    
    convert_tw_extensible_to_tw_pniels(&pn, &text2);
    copy_tw_extensible(&textb, &text1);
    add_tw_pniels_to_tw_extensible(&textb, &pn);
    
    succ &= fail_if_different_tw(&texta,&textb,"Addition commutativity","a+b","b+a");
    
    copy_tw_extensible(&textb, &text2);
    add_tw_pniels_to_tw_extensible(&textb, &pn);
    copy_tw_extensible(&texta, &text2);
    double_tw_extensible(&texta);
    
    succ &= fail_if_different_tw(&texta,&textb,"Doubling test","2b","b+b");
    
    if (~succ) {
        printf("    Bases were:\n");
        field_print("    x1", base1->x);
        field_print("    y1", base1->y);
        field_print("    x2", base2->x);
        field_print("    y2", base2->y);
    }
    
    return succ ? 0 : -1;
}

static int
single_twisting_test (
    const struct affine_t *base
) {
    struct extensible_t exb, ext, tmpext;
    struct tw_extensible_t text, text2;
    mask_t succ = MASK_SUCCESS;
    
    convert_affine_to_extensible(&exb, base);
    succ &= validate_ext(&exb,0,"base");
    
    /* check: dual . iso = 4 */
    twist_and_double(&text, &exb);
    succ &= validate_tw_ext(&text,2,"iso");
    untwist_and_double(&ext, &text);
    succ &= validate_ext(&ext,2,"dual.iso");
    
    copy_extensible(&tmpext,&exb);
    double_extensible(&tmpext);
    succ &= validate_ext(&tmpext,1,"2*base");
    
    double_extensible(&tmpext);
    succ &= validate_ext(&tmpext,2,"4*base");
    
    succ &= fail_if_different(&ext,&tmpext,"Isogeny and dual","Dual . iso","4*base");
    
    /* check: twist and serialize */
    test_only_twist(&text, &exb);
    succ &= validate_tw_ext(&text,0,"tot");
    mask_t evt = is_even_tw(&text), evb = is_even_pt(&exb);
    if (evt != evb) {
        youfail();
        printf("    Different evenness from twist base: %d, twist: %d\n", (int)-evt, (int)-evb);
        
        succ = 0;
    } /* FUTURE: quadness */
    
    field_a_t sera,serb;
    untwist_and_double_and_serialize(sera,&text);
    copy_extensible(&tmpext,&exb);
    double_extensible(&tmpext);
    serialize_extensible(serb,&tmpext);
    
    /* check that their (doubled; FUTURE?) serializations are equal */
    if (~field_eq(sera,serb)) {
        youfail();
        printf("    Different serialization from twist + double ()\n");
        field_print("    t", sera);
        field_print("    b", serb);
        succ = 0;
    }
    
    untwist_and_double(&ext, &text);
    succ &= validate_ext(&tmpext,1,"dual.tot");
    
    twist_and_double(&text2, &ext);
    succ &= validate_tw_ext(&text2,2,"iso.dual.tot");

    double_tw_extensible(&text);
    succ &= validate_tw_ext(&text,1,"2*tot");

    double_tw_extensible(&text);
    succ &= validate_tw_ext(&text,2,"4*tot");
    
    succ &= fail_if_different_tw(&text,&text2,"Dual and isogeny","4*tot","iso.dual.tot");
    
    if (~succ) {
        printf("    Base was:\n");
        field_print("    x", base->x);
        field_print("    y", base->y);
    }
    
    
    return succ ? 0 : -1;
}

int test_decaf_evil (void) {
    
#if FIELD_BITS != 448 || WORD_BITS != 64
    
    printf(" [ UNIMP ] ");
    return 0;
#else
    
    word_t evil_scalars[5][7] = {
        {0},
        {0x2378c292ab5844f3,0x216cc2728dc58f55,0xc44edb49aed63690,0xffffffff7cca23e9,
         0xffffffffffffffff,0xffffffffffffffff,0x3fffffffffffffff}, /* q */
        {0xdc873d6d54a7bb0d,0xde933d8d723a70aa,0x3bb124b65129c96f,
         0x335dc16,0x0,0x0,0x4000000000000000}, /* qtwist */
        {0x46f1852556b089e6,0x42d984e51b8b1eaa,0x889db6935dac6d20,0xfffffffef99447d3,
         0xffffffffffffffff,0xffffffffffffffff,0x7fffffffffffffff}, /* 2q */
        {0xb90e7adaa94f761a,0xbd267b1ae474e155,0x7762496ca25392df,0x66bb82c,
             0x0,0x0,0x8000000000000000} /* 2*qtwist */
    };
    word_t random_scalar[7];
    
    unsigned char evil_inputs[3][56];
    memset(evil_inputs[0],0,56);
    memset(evil_inputs[1],0,56);
    memset(evil_inputs[2],0xff,56);
    evil_inputs[1][0] = 1;
    evil_inputs[2][0] = evil_inputs[2][28] = 0xFE;
    
    unsigned char random_input[56];
    
    
    crandom_state_a_t crand;
    crandom_init_from_buffer(crand, "my evil_decaf random initializer");

    int i,j,fails=0;
    int ret = 0;
    for (i=0; i<100; i++) {
        
        crandom_generate(crand, (unsigned char *)random_scalar, sizeof(random_scalar));
        if (i<15) {
            memcpy(random_scalar, evil_scalars[i%5], sizeof(random_scalar));
            if (i%3 == 1) random_scalar[0] ++;
            if (i%3 == 2) random_scalar[0] --;
        }
        
        for (j=0; j<100; j++) {
            crandom_generate(crand, random_input, sizeof(random_input));
            mask_t should = 0, care_should = 0;
            if (j<3) {
                memcpy(random_input, evil_inputs[j], sizeof(random_input));
                care_should = -1;
                should = (j==0) ? -1 : 0;
            } else {
                random_input[55] &= 0x7F;
            }
            
            field_a_t base, out_m, out_e;
            mask_t s_base = field_deserialize(base,random_input);
            
            affine_a_t pt_e;
            tw_affine_a_t pt_te;
            // TODO: test don't allow identity
            mask_t s_e  = decaf_deserialize_affine(pt_e,base,-1);
            mask_t s_te = decaf_deserialize_tw_affine(pt_te,base,-1);
            mask_t s_m  = decaf_montgomery_ladder(out_m, base, random_scalar, 448);
            
            tw_extensible_a_t work;
            convert_tw_affine_to_tw_extensible(work,pt_te);
            scalarmul(work, random_scalar);
            decaf_serialize_tw_extensible(out_e, work);
            
            if ((care_should && should != s_m)
                || ~s_base || s_e != s_te || s_m != s_te || (s_te && ~field_eq(out_e,out_m))
            ) {
                youfail();
                field_print("    base", base);
                scalar_print("    scal", random_scalar, (448+WORD_BITS-1)/WORD_BITS);
                field_print("    oute", out_e);
                field_print("    outm", out_m);
                printf("    succ: m=%d, e=%d, t=%d, b=%d, should=%d[%d]\n",
                    -(int)s_m,-(int)s_e,-(int)s_te,-(int)s_base,-(int)should,-(int)care_should
                );
                ret = -1;
                fails++;
            }
        }
    }
    if (fails) {
        printf("    Failed %d trials\n", fails);
    }
    return ret;
#endif
}

int test_decaf (void) {
    struct affine_t base;
    struct tw_affine_t tw_base;
    field_a_t serf;
    
    struct crandom_state_t crand;
    crandom_init_from_buffer(&crand, "my test_decaf random initializer");
    
    int i, hits = 0, fails = 0;
    for (i=0; i<1000; i++) {
        uint8_t ser[FIELD_BYTES];
        
        int j;
        
        mask_t succ = 0;
        for (j=0; j<128 && !succ; j++) {
            crandom_generate(&crand, ser, sizeof(ser));
            ser[FIELD_BYTES-1] &= (1<<((FIELD_BITS-1)%8)) - 1;

            succ = field_deserialize(serf, ser);
            if (!succ) {
                youfail();
                printf("   Unlikely: fail at field_deserialize\n");
                return -1;
            }
        
            succ &= decaf_deserialize_affine(&base, serf, 0);
        }
        if (!succ) {
            youfail();
            printf("Unlikely: fail 128 desers\n");
            return -1;
        }
        
        hits++;
        field_a_t serf2;
        struct extensible_t ext;
        convert_affine_to_extensible(&ext, &base);
        decaf_serialize_extensible(serf2, &ext);
        
        if (~validate_affine(&base)) {
            youfail();
            printf("Invalid decaf deser:\n");
            field_print("    s", serf);
            field_print("    x", base.x);
            field_print("    y", base.y);
            fails ++;
        } else if (~field_eq(serf, serf2)) {
            youfail();
            printf("Fail round-trip through decaf ser:\n");
            field_print("    s", serf);
            field_print("    x", base.x);
            field_print("    y", base.y);
            printf("    deser is %s\n", validate_affine(&base) ? "valid" : "invalid");
            field_print("    S", serf2);
            fails ++;
        } else if (~is_even_pt(&ext)) {
            youfail();
            printf("Decaf deser isn't even:\n");
            field_print("    s", serf);
            field_print("    x", base.x);
            field_print("    y", base.y);
            fails ++;
        }
        
        succ = decaf_deserialize_tw_affine(&tw_base, serf, 0);
        struct tw_extensible_t tw_ext, tw_ext2;
        convert_tw_affine_to_tw_extensible(&tw_ext, &tw_base);
        decaf_serialize_tw_extensible(serf2, &tw_ext);
        
        twist_even(&tw_ext2, &ext);

        if (~succ | ~validate_tw_extensible(&tw_ext)) {
            youfail();
            printf("Invalid decaf tw deser:\n");
            field_print("    s", serf);
            field_print("    x", tw_base.x);
            field_print("    y", tw_base.y);
            fails ++;
        } else if (~field_eq(serf, serf2)) {
            youfail();
            printf("Fail round-trip through decaf ser:\n");
            field_print("    s", serf);
            field_print("    x", tw_base.x);
            field_print("    y", tw_base.y);
            printf("    tw deser is %s\n", validate_tw_extensible(&tw_ext) ? "valid" : "invalid");
            field_print("    S", serf2);
            fails ++;
        } else if (~is_even_tw(&tw_ext)) {
            youfail();
            printf("Decaf tw deser isn't even:\n");
            field_print("    s", serf);
            field_print("    x", tw_base.x);
            field_print("    y", tw_base.y);
            fails ++;
        } else if (~decaf_eq_tw_extensible(&tw_ext,&tw_ext2)) {
            youfail();
            printf("Decaf tw doesn't equal ext:\n");
            field_print("    s",  serf);
            field_print("    x1", base.x);
            field_print("    y1", base.y);
            field_print("    x2", tw_base.x);
            field_print("    y2", tw_base.y);
            field_print("    X2", tw_ext2.x);
            field_print("    Y2", tw_ext2.y);
            fails ++;
        }
        
        word_t scalar = 1;
        mask_t res = decaf_montgomery_ladder(serf2,serf,&scalar,1+(i%31));
        if (~res | ~field_eq(serf2,serf)) {
            youfail();
            printf("Decaf Montgomery ladder i=%d res=%d\n", 1+(i%31), (int)res);
            field_print("    s", serf);
            field_print("    o", serf2);
            printf("\n");
        }
    }
    if (hits < 1000) {
        youfail();
        printf("   Fail: only %d successes in decaf_deser\n", hits);
        return -1;
    } else if (fails) {
        return -1;
    } else {
        return 0;
    }
}

int test_pointops (void) {
    struct affine_t base, pbase;
    field_a_t serf;
    
    struct crandom_state_t crand;
    crandom_init_from_buffer(&crand, "test_pointops random initializer");
    
    struct extensible_t ext_base;
    if (!validate_affine(goldilocks_base_point)) {
        youfail();
        printf("  Base point isn't on the curve.\n");
        return -1;
    }
    convert_affine_to_extensible(&ext_base, goldilocks_base_point);
    if (!validate_ext(&ext_base, 2, "base")) return -1;
    
    int i, ret;
    for (i=0; i<1000; i++) {
        uint8_t ser[FIELD_BYTES];
        crandom_generate(&crand, ser, sizeof(ser));


        #if (FIELD_BITS % 8)
            ser[FIELD_BYTES-1] &= (1<<(FIELD_BITS%8)) - 1;
        #endif
        
        /* TODO: we need a field generate, which can return random or pathological. */
        mask_t succ = field_deserialize(serf, ser);
        if (!succ) {
            youfail();
            printf("   Unlikely: fail at field_deserialize\n");
            return -1;
        }
        
        if (i) {
            copy_affine(&pbase, &base);
        }
        elligator_2s_inject(&base, serf);
        
        if (i) {
            ret = add_double_test(&base, &pbase);
            if (ret) return ret;
        }
        
        ret = single_twisting_test(&base);
        if (ret) return ret;
    }
    
    return 0;
}
