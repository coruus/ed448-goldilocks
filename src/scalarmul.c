/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#include "word.h"

#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "intrinsics.h"
#include "scalarmul.h"
#include "barrett_field.h"

mask_t
montgomery_ladder (
    struct p448_t *out,
    const struct p448_t *in,
    const word_t *scalar,
    unsigned int nbits,
    unsigned int n_extra_doubles
) { 
    struct montgomery_t mont;
    deserialize_montgomery(&mont, in);
    
    int i,j,n=(nbits-1)%WORD_BITS;
    mask_t pflip = 0;
    for (j=(nbits+WORD_BITS-1)/WORD_BITS-1; j>=0; j--) {
        word_t w = scalar[j];
        for (i=n; i>=0; i--) {
            mask_t flip = -((w>>i)&1);
            p448_cond_swap(&mont.xa,&mont.xd,flip^pflip);
            p448_cond_swap(&mont.za,&mont.zd,flip^pflip);
            montgomery_step(&mont);
            pflip = flip;
        }
        n = WORD_BITS-1;
    }
    p448_cond_swap(&mont.xa,&mont.xd,pflip);
    p448_cond_swap(&mont.za,&mont.zd,pflip);
    
    assert(n_extra_doubles < INT_MAX);
    for (j=0; j<(int)n_extra_doubles; j++) {
        montgomery_step(&mont);
    }
    
    return serialize_montgomery(out, &mont, in);
}

static __inline__ void
cond_negate_tw_niels (
    struct tw_niels_t *n,
    mask_t doNegate
) {
    p448_cond_swap(&n->a, &n->b, doNegate);
    p448_cond_neg(&n->c, doNegate);
}

static __inline__ void
cond_negate_tw_pniels (
    struct tw_pniels_t *n,
    mask_t doNegate
) {
    cond_negate_tw_niels(&n->n, doNegate);
}

void    
constant_time_lookup_tw_pniels (
    struct tw_pniels_t *out,
    const struct tw_pniels_t *in,
    int nin,
    int idx
) {
    big_register_t big_one = 1, big_i = idx;
    big_register_t *o = (big_register_t *)out;
    const big_register_t *i = (const big_register_t *)in;
    int j;
    unsigned int k;
    
    memset(out, 0, sizeof(*out));
    for (j=0; j<nin; j++, big_i-=big_one) {
        big_register_t mask = br_is_zero(big_i);
        for (k=0; k<sizeof(*out)/sizeof(*o); k++) {
            o[k] |= mask & i[k+j*sizeof(*out)/sizeof(*o)];
        }
    }
}

static __inline__ void    
constant_time_lookup_tw_niels (
    struct tw_niels_t *out,
    const struct tw_niels_t *in,
    int nin,
    int idx
) {
    big_register_t big_one = 1, big_i = idx;
    big_register_t *o = (big_register_t *)out;
    const big_register_t *i = (const big_register_t *)in;
    int j;
    unsigned int k;
    
    memset(out, 0, sizeof(*out));
    for (j=0; j<nin; j++, big_i-=big_one) {
        big_register_t mask = br_is_zero(big_i);
        for (k=0; k<sizeof(*out)/sizeof(*o); k++) {
            o[k] |= mask & i[k+j*sizeof(*out)/sizeof(*o)];
        }
    }
}

static void
convert_to_signed_window_form (
    word_t *out,
    const word_t *scalar,
    int nwords_scalar,
    const word_t *prepared_data,
    int nwords_pd
) {
    assert(nwords_pd <= nwords_scalar);
    mask_t mask = -(scalar[0]&1);

    word_t carry = add_nr_ext_packed(out, scalar, nwords_scalar, prepared_data, nwords_pd, ~mask);
    carry += add_nr_ext_packed(out, out, nwords_scalar, prepared_data+nwords_pd, nwords_pd, mask);
    
    assert(!(out[0]&1));
    
    int i;
    for (i=0; i<nwords_scalar; i++) {
        out[i] >>= 1;
        if (i<nwords_scalar-1) {
            out[i] |= out[i+1]<<(WORD_BITS-1);
        } else {
            out[i] |= carry<<(WORD_BITS-1);
        }
    }
}

void
scalarmul (
    struct tw_extensible_t *working,
    const word_t scalar[448/WORD_BITS]
) {

    const int nbits=448; /* HACK? */
    word_t prepared_data[448*2/WORD_BITS] = {
        U64LE(0x9595b847fdf73126),
        U64LE(0x9bb9b8a856af5200),
        U64LE(0xb3136e22f37d5c4f),
        U64LE(0x0000000189a19442),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000),
        U64LE(0x4000000000000000),

        U64LE(0x721cf5b5529eec33),
        U64LE(0x7a4cf635c8e9c2ab),
        U64LE(0xeec492d944a725bf),
        U64LE(0x000000020cd77058),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000)
    }; /* TODO: split off */
    
    word_t scalar2[448/WORD_BITS];
    convert_to_signed_window_form(scalar2,scalar,448/WORD_BITS,prepared_data,448/WORD_BITS);

    struct tw_extensible_t tabulator;
    copy_tw_extensible(&tabulator, working);
    double_tw_extensible(&tabulator);

    struct tw_pniels_t pn, multiples[8];
    convert_tw_extensible_to_tw_pniels(&pn, &tabulator);
    convert_tw_extensible_to_tw_pniels(&multiples[0], working);

    int i;
    for (i=1; i<8; i++) {
        add_tw_pniels_to_tw_extensible(working, &pn);
        convert_tw_extensible_to_tw_pniels(&multiples[i], working);
    }

    i = nbits - 4;
    int bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & 0xF,
        inv = (bits>>3)-1;
    bits ^= inv;
    
    constant_time_lookup_tw_pniels(&pn, multiples, 8, bits&7);
    cond_negate_tw_pniels(&pn, inv);
    convert_tw_pniels_to_tw_extensible(working, &pn);
		

    for (i-=4; i>=0; i-=4) {
        double_tw_extensible(working);
        double_tw_extensible(working);
        double_tw_extensible(working);
        double_tw_extensible(working);

        bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & 0xF;
        inv = (bits>>3)-1;
        bits ^= inv;
    
        constant_time_lookup_tw_pniels(&pn, multiples, 8, bits&7);
        cond_negate_tw_pniels(&pn, inv);
        add_tw_pniels_to_tw_extensible(working, &pn);
    }
}

void
scalarmul_vlook (
    struct tw_extensible_t *working,
    const word_t scalar[448/WORD_BITS]
) {

    const int nbits=448; /* HACK? */
    word_t prepared_data[448*2/WORD_BITS] = {
        U64LE(0x9595b847fdf73126),
        U64LE(0x9bb9b8a856af5200),
        U64LE(0xb3136e22f37d5c4f),
        U64LE(0x0000000189a19442),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000),
        U64LE(0x4000000000000000),

        U64LE(0x721cf5b5529eec33),
        U64LE(0x7a4cf635c8e9c2ab),
        U64LE(0xeec492d944a725bf),
        U64LE(0x000000020cd77058),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000),
        U64LE(0x0000000000000000)
    }; /* TODO: split off */
    
    word_t scalar2[448/WORD_BITS];
    convert_to_signed_window_form(scalar2,scalar,448/WORD_BITS,prepared_data,448/WORD_BITS);

    struct tw_extensible_t tabulator;
    copy_tw_extensible(&tabulator, working);
    double_tw_extensible(&tabulator);

    struct tw_pniels_t pn, multiples[8];
    convert_tw_extensible_to_tw_pniels(&pn, &tabulator);
    convert_tw_extensible_to_tw_pniels(&multiples[0], working);

    int i;
    for (i=1; i<8; i++) {
        add_tw_pniels_to_tw_extensible(working, &pn);
        convert_tw_extensible_to_tw_pniels(&multiples[i], working);
    }

    i = nbits - 4;
    int bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & 0xF,
        inv = (bits>>3)-1;
    bits ^= inv;

	copy_tw_pniels(&pn, &multiples[bits&7]);
    cond_negate_tw_pniels(&pn, inv);
    convert_tw_pniels_to_tw_extensible(working, &pn);
		

    for (i-=4; i>=0; i-=4) {
        double_tw_extensible(working);
        double_tw_extensible(working);
        double_tw_extensible(working);
        double_tw_extensible(working);

        bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & 0xF;
        inv = (bits>>3)-1;
        bits ^= inv;
    
		copy_tw_pniels(&pn, &multiples[bits&7]);
        cond_negate_tw_pniels(&pn, inv);
        add_tw_pniels_to_tw_extensible(working, &pn);
    }
}


mask_t
scalarmul_fixed_base (
    struct tw_extensible_t *out,
    const word_t scalar[448/WORD_BITS],
    unsigned int nbits,
    const struct fixed_base_table_t *table
) {
    unsigned int n = table->n, t = table->t, s = table->s;
    assert(n >= 1 && t >= 1 && s >= 1);
    
    if (n*t*s < nbits) {
        return MASK_FAILURE;
    }
    
    unsigned int scalar_words = (nbits + WORD_BITS - 1)/WORD_BITS,
        scalar2_words = scalar_words;
    if (scalar2_words < 448 / WORD_BITS)
        scalar2_words = 448 / WORD_BITS;
    word_t scalar2[scalar2_words], scalar3[scalar2_words];
    
    /* Copy scalar to scalar3, but clear its high bits (if there are any) */
    unsigned int i,j,k;
    for (i=0; i<scalar_words; i++) {
        scalar3[i] = scalar[i];
    }
    if (likely(i) && (nbits % WORD_BITS)) {
        scalar3[i-1] &= (((word_t)1) << (nbits%WORD_BITS)) - 1;
    }
    for (; i<scalar2_words; i++) {
        scalar3[i] = 0;
    }
    
    convert_to_signed_window_form (
        scalar2,
        scalar3, scalar2_words,
        table->scalar_adjustments , 448 / WORD_BITS
    );
    
    struct tw_niels_t ni;
    
    for (i=0; i<s; i++) {
        if (i) double_tw_extensible(out);
        
        for (j=0; j<n; j++) {
            int tab = 0;
			
			/*
             * PERF: This computation takes about 1.5µs on SBR, i.e. 2-3% of the
			 * time of a keygen or sign op.  Surely it is possible to speed it up.
             */
            for (k=0; k<t; k++) {
                unsigned int bit = (s-1-i) + k*s + j*(s*t);
                if (bit < scalar2_words * WORD_BITS) {
                    tab |= (scalar2[bit/WORD_BITS] >> (bit%WORD_BITS) & 1) << k;
                }
            }
            
            mask_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;
            
            constant_time_lookup_tw_niels(&ni, table->table + (j<<(t-1)), 1<<(t-1), tab);
            cond_negate_tw_niels(&ni, invert);
            if (i||j) {
                add_tw_niels_to_tw_extensible(out, &ni);
            } else {
                convert_tw_niels_to_tw_extensible(out, &ni);
            }
        }
    }
    
    return MASK_SUCCESS;
}

mask_t
precompute_fixed_base (
  struct fixed_base_table_t *out,
  const struct tw_extensible_t *base,
  unsigned int n,
  unsigned int t,
  unsigned int s,
  struct tw_niels_t *prealloc
) {
    if (s < 1 || t < 1 || n < 1 || n*t*s < 446) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    
    out->n = n;
    out->t = t;
    out->s = s;
  
    struct tw_extensible_t working, start;
    copy_tw_extensible(&working, base);
    struct tw_pniels_t pn_tmp;
  
    struct tw_pniels_t *doubles = (struct tw_pniels_t *) malloc_vector(sizeof(*doubles) * (t-1));
    struct p448_t *zs  = (struct p448_t *) malloc_vector(sizeof(*zs) * (n<<(t-1)));
    struct p448_t *zis = (struct p448_t *) malloc_vector(sizeof(*zis) * (n<<(t-1)));
    
    struct tw_niels_t *table = prealloc;
    if (prealloc) {
        out->own_table = 0;
    } else {
        table = (struct tw_niels_t *) malloc_vector(sizeof(*table) * (n<<(t-1)));
        out->own_table = 1;
    }
    out->table = table;
  
    if (!doubles || !zs || !zis || !table) {
        free(doubles);
        free(zs);
        free(zis);
        memset(out, 0, sizeof(*out));
        memset(table, 0, sizeof(*table) * (n<<(t-1)));
        if (!prealloc) free(table);
        return 0;
    }
  
    unsigned int i,j,k;
    
    /* Compute the scalar adjustments, equal to 2^nbits-1 mod q */
    unsigned int adjustment_size = (n*t*s)/WORD_BITS + 1;
    assert(adjustment_size >= 448/WORD_BITS);
    word_t adjustment[adjustment_size];
    for (i=0; i<adjustment_size; i++) {
        adjustment[i] = -1;
    }
    
    adjustment[(n*t*s) / WORD_BITS] += ((word_t)1) << ((n*t*s) % WORD_BITS);

    /* FIXME: factor out somehow */
    const word_t goldi_q448_lo[(224+WORD_BITS-1)/WORD_BITS] = {
        U64LE(0xdc873d6d54a7bb0d),
        U64LE(0xde933d8d723a70aa),
        U64LE(0x3bb124b65129c96f),
        0x8335dc16
    };
    const struct barrett_prime_t goldi_q448 = {
        448/WORD_BITS, 62 % WORD_BITS, sizeof(goldi_q448_lo)/sizeof(word_t), goldi_q448_lo
    };
    
    /* The low adjustment is 2^nbits - 1 mod q */
    barrett_reduce(adjustment, adjustment_size, 0, &goldi_q448);
    word_t *low_adjustment = &out->scalar_adjustments[(448/WORD_BITS)*(adjustment[0] & 1)],
        *high_adjustment = &out->scalar_adjustments[(448/WORD_BITS)*((~adjustment[0]) & 1)];
    for (i=0; i<448/WORD_BITS; i++) {
        low_adjustment[i] = adjustment[i];
    }
    
    /* The high adjustment is low + q = low - q_lo + 2^big */
    (void)
    sub_nr_ext_packed(
        high_adjustment,
        adjustment, 448/WORD_BITS,
        goldi_q448.p_lo, goldi_q448.nwords_lo,
        -1
    );
    if (goldi_q448.p_shift) {
        high_adjustment[goldi_q448.nwords_p - 1] += ((word_t)1)<<goldi_q448.p_shift;
    }
    
    /* OK, now compute the tables */
    for (i=0; i<n; i++) {

        /* doubling phase */
        for (j=0; j<t; j++) {
            if (j) {
                convert_tw_extensible_to_tw_pniels(&pn_tmp, &working);
                add_tw_pniels_to_tw_extensible(&start, &pn_tmp);
            } else {
                copy_tw_extensible(&start, &working);
            }

            if (j==t-1 && i==n-1) {
                break;
            }

            double_tw_extensible(&working);
            if (j<t-1) {
                convert_tw_extensible_to_tw_pniels(&doubles[j], &working);
            }

            for (k=0; k<s-1; k++) {
                double_tw_extensible(&working);
            }
        }

        /* Gray-code phase */
        for (j=0;; j++) {
            int gray = j ^ (j>>1);
            int idx = ((i+1)<<(t-1))-1 ^ gray;

            convert_tw_extensible_to_tw_pniels(&pn_tmp, &start);
            copy_tw_niels(&table[idx], &pn_tmp.n);
            p448_copy(&zs[idx], &pn_tmp.z);
			
            if (j >= (1<<(t-1)) - 1) break;
            int delta = (j+1) ^ ((j+1)>>1) ^ gray;

            for (k=0; delta>1; k++)
                delta >>=1;
            
            if (gray & (1<<k)) {
                /* start += doubles[k] */
                add_tw_pniels_to_tw_extensible(&start, &doubles[k]);
            } else {
                /* start -= doubles[k] */
                sub_tw_pniels_from_tw_extensible(&start, &doubles[k]);
            }
            
            
        }
    }
	
    simultaneous_invert_p448(zis, zs, n<<(t-1));

    p448_t product;
    for (i=0; i<n<<(t-1); i++) {
        p448_mul(&product, &table[i].a, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&table[i].a, &product);
        
        p448_mul(&product, &table[i].b, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&table[i].b, &product);
        
        p448_mul(&product, &table[i].c, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&table[i].c, &product);
    }
	
	mask_t ret = ~p448_is_zero(&zis[0]);

    free(doubles);
    free(zs);
    free(zis);

    if (unlikely(!ret)) {
        memset(table, 0, sizeof(*table) * (n<<(t-1)));
        if (!prealloc) free(table);
        memset(out, 0, sizeof(*out));
        return 0;
    }

    return ret;
}

void
destroy_fixed_base (
    struct fixed_base_table_t *table
) {
    if (table->table) {
        memset(table->table,0,sizeof(*table->table)*(table->n<<(table->t-1)));
    }
    if (table->own_table) {
        free(table->table);
    }
    memset(table,0,sizeof(*table));
}

mask_t
precompute_fixed_base_wnaf (
    struct tw_niels_t *out,
    const struct tw_extensible_t *const_base,
    unsigned int tbits
) {
    int i;
    struct p448_t *zs  = (struct p448_t *) malloc_vector(sizeof(*zs)<<tbits);
    struct p448_t *zis = (struct p448_t *) malloc_vector(sizeof(*zis)<<tbits);

    if (!zs || !zis) {
        free(zs);
        free(zis);
        return 0;
    }

    struct tw_extensible_t base;
    copy_tw_extensible(&base,const_base);
    
    struct tw_pniels_t twop, tmp;
    
    convert_tw_extensible_to_tw_pniels(&tmp, &base);
    p448_copy(&zs[0], &tmp.z);
    copy_tw_niels(&out[0], &tmp.n);

    if (tbits > 0) {
        double_tw_extensible(&base);
        convert_tw_extensible_to_tw_pniels(&twop, &base);
        add_tw_pniels_to_tw_extensible(&base, &tmp);
        
        convert_tw_extensible_to_tw_pniels(&tmp, &base);
        p448_copy(&zs[1], &tmp.z);
        copy_tw_niels(&out[1], &tmp.n);

        for (i=2; i < 1<<tbits; i++) {
            add_tw_pniels_to_tw_extensible(&base, &twop);
            convert_tw_extensible_to_tw_pniels(&tmp, &base);
            p448_copy(&zs[i], &tmp.z);
            copy_tw_niels(&out[i], &tmp.n);
        }
    }
    
    simultaneous_invert_p448(zis, zs, 1<<tbits);

    p448_t product;
    for (i=0; i<1<<tbits; i++) {
        p448_mul(&product, &out[i].a, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&out[i].a, &product);
        
        p448_mul(&product, &out[i].b, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&out[i].b, &product);
        
        p448_mul(&product, &out[i].c, &zis[i]);
        p448_strong_reduce(&product);
        p448_copy(&out[i].c, &product);
    }

    free(zs);
    free(zis);

    return -1;
}

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int
recode_wnaf(
    struct smvt_control *control, /* [nbits/(tableBits+1) + 3] */
    const word_t *scalar,
    unsigned int nbits,
    unsigned int tableBits)
{
    int current = 0, i, j;
    unsigned int position = 0;

    /* PERF: negate scalar if it's large
     * PERF: this is a pretty simplistic algorithm.  I'm sure there's a faster one...
     */
    for (i=nbits-1; i >= 0; i--) {
        int bit = (scalar[i/WORD_BITS] >> (i%WORD_BITS)) & 1;
        current = 2*current + bit;

        /*
         * Sizing: |current| >= 2^(tableBits+1) -> |current| = 2^0
         * So current loses (tableBits+1) bits every time.  It otherwise gains
         * 1 bit per iteration.  The number of iterations is
         * (nbits + 2 + tableBits), and an additional control word is added at
         * the end.  So the total number of control words is at most
         * ceil((nbits+1) / (tableBits+1)) + 2 = floor((nbits)/(tableBits+1)) + 2.
         * There's also the stopper with power -1, for a total of +3.
         */
        if (current >= (2<<tableBits) || current <= -1 - (2<<tableBits)) {
            int delta = (current + 1) >> 1; // |delta| < 2^tablebits
            current = -(current & 1);

            for (j=i; (delta & 1) == 0; j++) {
                delta >>= 1;
            }
            control[position].power = j+1;
            control[position].addend = delta;
            position++;
            assert(position <= nbits/(tableBits+1) + 2);
        }
    }
    
    if (current) {
        for (j=0; (current & 1) == 0; j++) {
            current >>= 1;
        }
        control[position].power = j;
        control[position].addend = current;
        position++;
        assert(position <= nbits/(tableBits+1) + 2);
    }
    
  
    control[position].power = -1;
    control[position].addend = 0;
    return position;
}


static void
prepare_wnaf_table(
    struct tw_pniels_t *output,
    struct tw_extensible_t *working,
    unsigned int tbits
) {
    convert_tw_extensible_to_tw_pniels(&output[0], working);

    if (tbits == 0) return;

    double_tw_extensible(working);
    struct tw_pniels_t twop;
    convert_tw_extensible_to_tw_pniels(&twop, working);

    add_tw_pniels_to_tw_extensible(working, &output[0]);
    convert_tw_extensible_to_tw_pniels(&output[1], working);

    for (int i=2; i < 1<<tbits; i++) {
        add_tw_pniels_to_tw_extensible(working, &twop);
        convert_tw_extensible_to_tw_pniels(&output[i], working);
    }
}

void
scalarmul_vt (
    struct tw_extensible_t *working,
    const word_t scalar[448/WORD_BITS]
) {
    /* HACK: not 448? */
    const int nbits=448, table_bits = 3;
    struct smvt_control control[nbits/(table_bits+1)+3];
    
    int control_bits = recode_wnaf(control, scalar, nbits, table_bits);
  
    struct tw_pniels_t precmp[1<<table_bits];
    prepare_wnaf_table(precmp, working, table_bits);
  
    if (control_bits > 0) {
        assert(control[0].addend > 0);
        assert(control[0].power >= 0);
        convert_tw_pniels_to_tw_extensible(working, &precmp[control[0].addend >> 1]);
    } else {
        set_identity_tw_extensible(working);
        return;
    }
  
    int conti = 1, i;
    for (i = control[0].power - 1; i >= 0; i--) {
        double_tw_extensible(working);

        if (i == control[conti].power) {
            assert(control[conti].addend);

            if (control[conti].addend > 0) {
                add_tw_pniels_to_tw_extensible(working, &precmp[control[conti].addend >> 1]);
            } else {
                sub_tw_pniels_from_tw_extensible(working, &precmp[(-control[conti].addend) >> 1]);
            }
            conti++;
            assert(conti <= control_bits);
        }
    }
}

void
scalarmul_fixed_base_wnaf_vt (
    struct tw_extensible_t *working,
    const word_t scalar[448/WORD_BITS],
    unsigned int nbits,
    const struct tw_niels_t *precmp,
    unsigned int table_bits
) {
    struct smvt_control control[nbits/(table_bits+1)+3];
    
    int control_bits = recode_wnaf(control, scalar, nbits, table_bits);
  
    if (control_bits > 0) {
        assert(control[0].addend > 0);
        assert(control[0].power >= 0);
        convert_tw_niels_to_tw_extensible(working, &precmp[control[0].addend >> 1]);
    } else {
        set_identity_tw_extensible(working);
        return;
    }
  
    int conti = 1, i;
    for (; control[conti].power >= 0; conti++) {
        assert(conti <= control_bits);
        for (i = control[conti-1].power - control[conti].power; i; i--) {
            double_tw_extensible(working);
        }
        
        assert(control[conti].addend);
        if (control[conti].addend > 0) {
            add_tw_niels_to_tw_extensible(working, &precmp[control[conti].addend >> 1]);
        } else {
            sub_tw_niels_from_tw_extensible(working, &precmp[(-control[conti].addend) >> 1]);
        }
    }

    for (i = control[conti-1].power; i; i--) {
        double_tw_extensible(working);
    }
}

void
linear_combo_var_fixed_vt(
    struct tw_extensible_t *working,
    const word_t scalar_var[448/WORD_BITS],
    unsigned int nbits_var,
    const word_t scalar_pre[448/WORD_BITS],
    unsigned int nbits_pre,
    const struct tw_niels_t *precmp,
    unsigned int table_bits_pre
) {
    const int table_bits_var = 3;
    struct smvt_control control_var[nbits_var/(table_bits_var+1)+3];
    struct smvt_control control_pre[nbits_pre/(table_bits_pre+1)+3];
    
    int ncb_var = recode_wnaf(control_var, scalar_var, nbits_var, table_bits_var);
    int ncb_pre = recode_wnaf(control_pre, scalar_pre, nbits_pre, table_bits_pre);
    (void)ncb_var;
    (void)ncb_pre;
  
    struct tw_pniels_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, working, table_bits_var);
  
    int contp=0, contv=0, i;
  
    i = control_var[0].power;
    if (i > control_pre[0].power) {
        convert_tw_pniels_to_tw_extensible(working, &precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        convert_tw_pniels_to_tw_extensible(working, &precmp_var[control_var[0].addend >> 1]);
        add_tw_niels_to_tw_extensible(working, &precmp[control_pre[0].addend >> 1]);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        convert_tw_niels_to_tw_extensible(working, &precmp[control_pre[0].addend >> 1]);
        contp++;
    }
    
    if (i < 0) {
        set_identity_tw_extensible(working);
        return;
    }
    
    for (i--; i >= 0; i--) {
        double_tw_extensible(working);

        if (i == control_var[contv].power) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                add_tw_pniels_to_tw_extensible(working, &precmp_var[control_var[contv].addend >> 1]);
            } else {
                sub_tw_pniels_from_tw_extensible(working, &precmp_var[(-control_var[contv].addend) >> 1]);
            }
            contv++;
        }

        if (i == control_pre[contp].power) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                add_tw_niels_to_tw_extensible(working, &precmp[control_pre[contp].addend >> 1]);
            } else {
                sub_tw_niels_from_tw_extensible(working, &precmp[(-control_pre[contp].addend) >> 1]);
            }
            contp++;
        }
    }
    
    assert(contv == ncb_var);
    assert(contp == ncb_pre);
}



