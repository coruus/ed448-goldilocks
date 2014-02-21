/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */
#include <stdlib.h>

#include "scalarmul.h"
#include "string.h"
#include "barrett_field.h"

mask_t
p448_montgomery_ladder(
    struct p448_t *out,
    const struct p448_t *in,
    const uint64_t *scalar,
    int nbits,
    int n_extra_doubles
) {
    struct montgomery_t mont;
    p448_sqr(&mont.z0,in);
    p448_copy(&mont.za,&mont.z0);
    p448_set_ui(&mont.xa,1);
    p448_set_ui(&mont.zd,0);
    p448_set_ui(&mont.xd,1);
    
    int i,j,n=(nbits-1)&63;
    mask_t pflip = 0;
    for (j=(nbits+63)/64-1; j>=0; j--) {
        uint64_t w = scalar[j];
        for (i=n; i>=0; i--) {
            mask_t flip = -((w>>i)&1);
            p448_cond_swap(&mont.xa,&mont.xd,flip^pflip);
            p448_cond_swap(&mont.za,&mont.zd,flip^pflip);
            p448_montgomery_step(&mont);
            pflip = flip;
        }
        n = 63;
    }
    p448_cond_swap(&mont.xa,&mont.xd,pflip);
    p448_cond_swap(&mont.za,&mont.zd,pflip);
    
    for (j=0; j<n_extra_doubles; j++) {
        p448_montgomery_step(&mont);
    }
    
    struct p448_t sign;
    p448_montgomery_serialize(&sign, out, &mont, in);
    
    p448_addw(&sign,1);
    return ~p448_is_zero(&sign);
}

static __inline__ void
niels_cond_negate(
    struct tw_niels_t *n,
    mask_t doNegate
) {
    p448_cond_swap(&n->a, &n->b, doNegate);
    p448_cond_neg(&n->c, doNegate); /* TODO: bias amt? */
}

static __inline__ void
pniels_cond_negate(
    struct tw_pniels_t *n,
    mask_t doNegate
) {
    niels_cond_negate(&n->n, doNegate);
}

void    
constant_time_lookup_pniels(
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
constant_time_lookup_niels(
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
convert_to_signed_window_form(
    word_t *out,
    const word_t *scalar,
    const word_t *prepared_data,
    int nwords
) {
    mask_t mask = -(scalar[0]&1);

    word_t carry = add_nr_ext_packed(out, scalar, nwords, prepared_data, nwords, ~mask);
    carry += add_nr_ext_packed(out, out, nwords, prepared_data+nwords, nwords, mask);
    
    assert(!(out[0]&1));
    
    int i;
    for (i=0; i<nwords; i++) {
        out[i] >>= 1;
        if (i<nwords-1) {
            out[i] |= out[i+1]<<(WORD_BITS-1);
        } else {
            out[i] |= carry<<(WORD_BITS-1);
        }
    }
}

void
edwards_scalar_multiply(
    struct tw_extensible_t *working,
    const uint64_t scalar[7]
) {

    const int nbits=448; /* HACK? */
    word_t prepared_data[14] = {
        0x9595b847fdf73126ull,
        0x9bb9b8a856af5200ull,
        0xb3136e22f37d5c4full,
        0x0000000189a19442ull,
        0x0000000000000000ull,
        0x0000000000000000ull,
        0x4000000000000000ull,

        0x721cf5b5529eec33ull,
        0x7a4cf635c8e9c2abull,
        0xeec492d944a725bfull,
        0x000000020cd77058ull,
        0x0000000000000000ull,
        0x0000000000000000ull,
        0x0000000000000000ull
    }; /* TODO: split off */
    
    uint64_t scalar2[7];
    convert_to_signed_window_form(scalar2,scalar,prepared_data,7);

    struct tw_extensible_t tabulator;
    copy_tw_extensible(&tabulator, working);
    p448_tw_extensible_double(&tabulator);

    struct tw_pniels_t pn, multiples[8];
    convert_tw_extensible_to_tw_pniels(&pn, &tabulator);
    convert_tw_extensible_to_tw_pniels(&multiples[0], working);

    int i;
    for (i=1; i<8; i++) {
        p448_tw_extensible_add_pniels(working, &pn);
        convert_tw_extensible_to_tw_pniels(&multiples[i], working);
    }

    i = nbits - 4;
    int bits = scalar2[i/64] >> (i%64) & 0xF,
        inv = (bits>>3)-1;
    bits ^= inv;
    
    constant_time_lookup_pniels(&pn, multiples, 8, bits&7);
    pniels_cond_negate(&pn, inv);
    convert_tw_pniels_to_tw_extensible(working, &pn);
		

    for (i-=4; i>=0; i-=4) {
        p448_tw_extensible_double(working);
        p448_tw_extensible_double(working);
        p448_tw_extensible_double(working);
        p448_tw_extensible_double(working);

        bits = scalar2[i/64] >> (i%64) & 0xF;
        inv = (bits>>3)-1;
        bits ^= inv;
    
        constant_time_lookup_pniels(&pn, multiples, 8, bits&7);
        pniels_cond_negate(&pn, inv);
        p448_tw_extensible_add_pniels(working, &pn);
    }
}


void
edwards_comb(
    struct tw_extensible_t *working,
    const word_t scalar[7],
    const struct tw_niels_t *table,
    int n,
    int t,
    int s
) {
    word_t prepared_data[14] = {
        0xebec9967f5d3f5c2ull,
        0x0aa09b49b16c9a02ull,
        0x7f6126aec172cd8eull,
        0x00000007b027e54dull,
        0x0000000000000000ull,
        0x0000000000000000ull,
        0x4000000000000000ull,

        0xc873d6d54a7bb0cfull,
        0xe933d8d723a70aadull,
        0xbb124b65129c96fdull,
        0x00000008335dc163ull,
        0x0000000000000000ull,
        0x0000000000000000ull,
        0x0000000000000000ull
    }; /* TODO: split off.  Above is for 450 bits */
    
    word_t scalar2[7];
    convert_to_signed_window_form(scalar2,scalar,prepared_data,7);
    
    /* const int n=3, t=5, s=30; */
    int i,j,k;
    
    struct tw_niels_t ni;
    
    for (i=0; i<s; i++) {
        if (i) p448_tw_extensible_double(working);
        
        for (j=0; j<n; j++) {
            int tab = 0;
			
			/*
             * PERF: This computation takes about 1.5µs on SBR, i.e. 2-3% of the
			 * time of a keygen or sign op.  Surely it is possible to speed it up.
             */
            for (k=0; k<t; k++) {
                int bit = (s-1-i) + k*s + j*(s*t);
                if (bit < 7*WORD_BITS) {
                    tab |= (scalar2[bit/WORD_BITS] >> (bit%WORD_BITS) & 1) << k;
                }
            }
            
            mask_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;
            
            constant_time_lookup_niels(&ni, table + (j<<(t-1)), 1<<(t-1), tab);
            niels_cond_negate(&ni, invert);
            if (i||j) {
                p448_tw_extensible_add_niels(working, &ni);
            } else {
                convert_tw_niels_to_tw_extensible(working, &ni);
            }
        }
    }
}

void
simultaneous_invert_p448(
    struct p448_t *out,
    const struct p448_t *in,
    int n
) {
  if (!n) return;
  
  p448_copy(&out[1], &in[0]);
  int i;
  for (i=1; i<n-1; i++) {
      p448_mul(&out[i+1], &out[i], &in[i]);
  }
  p448_mul(&out[0], &out[n-1], &in[n-1]);
  
  struct p448_t tmp;
  p448_inverse(&tmp, &out[0]);
  p448_copy(&out[0], &tmp);
  
  /* at this point, out[0] = product(in[i]) ^ -1
   * out[i] = product(in[0]..in[i-1]) if i != 0
   */
  for (i=n-1; i>0; i--) {
      p448_mul(&tmp, &out[i], &out[0]);
      p448_copy(&out[i], &tmp);
      
      p448_mul(&tmp, &out[0], &in[i]);
      p448_copy(&out[0], &tmp);
  }
}

mask_t
precompute_for_combs(
  struct tw_niels_t *out,
  const struct tw_extensible_t *const_base,
  int n,
  int t,
  int s
) {
    if (s < 1) return 0;
  
    struct tw_extensible_t working, start;
    copy_tw_extensible(&working, const_base);
    struct tw_pniels_t pn_tmp;
  
    struct tw_pniels_t *doubles = (struct tw_pniels_t *) malloc(sizeof(*doubles) * (t-1));
    struct p448_t *zs  = (struct p448_t *) malloc(sizeof(*zs) * (n<<(t-1)));
    struct p448_t *zis = (struct p448_t *) malloc(sizeof(*zis) * (n<<(t-1)));
  
    if (!doubles || !zs || !zis) {
        free(doubles);
        free(zs);
        free(zis);
        return 0;
    }
  
    int i,j,k;
    for (i=0; i<n; i++) {

        /* doubling phase */
        for (j=0; j<t; j++) {
            if (j) {
                convert_tw_extensible_to_tw_pniels(&pn_tmp, &working);
                p448_tw_extensible_add_pniels(&start, &pn_tmp);
            } else {
                copy_tw_extensible(&start, &working);
            }

            if (j==t-1 && i==n-1) {
                break;
            }

            p448_tw_extensible_double(&working);
            if (j<t-1) {
                convert_tw_extensible_to_tw_pniels(&doubles[j], &working);
            }

            for (k=0; k<s-1; k++) {
                p448_tw_extensible_double(&working);
            }
        }

        /* Gray-code phase */
        for (j=0;; j++) {
            int gray = j ^ (j>>1);
            int idx = ((i+1)<<(t-1))-1 ^ gray;

            convert_tw_extensible_to_tw_pniels(&pn_tmp, &start);
            copy_tw_niels(&out[idx], &pn_tmp.n);
            p448_copy(&zs[idx], &pn_tmp.z);
			
            if (j >= (1<<(t-1)) - 1) break;
            int delta = (j+1) ^ ((j+1)>>1) ^ gray;

            for (k=0; delta>1; k++)
                delta >>=1;
            
            if (gray & (1<<k)) {
                /* start += doubles[k] */
                p448_tw_extensible_add_pniels(&start, &doubles[k]);
            } else {
                /* start -= doubles[k] */
                /* PERF: uncond negate */
                copy_tw_pniels(&pn_tmp, &doubles[k]);
                pniels_cond_negate(&pn_tmp, -1);
                p448_tw_extensible_add_pniels(&start, &pn_tmp);
            }
            
            
        }
    }
	
    simultaneous_invert_p448(zis, zs, n<<(t-1));

    p448_t product;
    for (i=0; i<n<<(t-1); i++) {
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
	
	mask_t ret = ~p448_is_zero(&zis[0]);

    free(doubles);
    free(zs);
    free(zis);

    return ret;
}

mask_t
precompute_for_wnaf(
    struct tw_niels_t *out,
    const struct tw_extensible_t *const_base,
    int tbits
) {
    int i;
    struct p448_t *zs  = (struct p448_t *) malloc(sizeof(*zs)<<tbits);
    struct p448_t *zis = (struct p448_t *) malloc(sizeof(*zis)<<tbits);

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
        p448_tw_extensible_double(&base);
        convert_tw_extensible_to_tw_pniels(&twop, &base);
        p448_tw_extensible_add_pniels(&base, &tmp);
        
        convert_tw_extensible_to_tw_pniels(&tmp, &base);
        p448_copy(&zs[1], &tmp.z);
        copy_tw_niels(&out[1], &tmp.n);

        for (i=2; i < 1<<tbits; i++) {
            p448_tw_extensible_add_pniels(&base, &twop);
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

struct smvt_control {
  int power, addend;
};

static int
recode_wnaf(
    struct smvt_control *control, /* [nbits/(tableBits+1) + 3] */
    const word_t *scalar,
    int nbits,
    int tableBits)
{
    int current = 0, position=0, i;

    /* PERF: negate scalar if it's large
     * PERF: this is a pretty simplistic algorithm.  I'm sure there's a faster one...
     */
    for (i=nbits-1; i >= -2 - tableBits; i--) {
        int bit = (i >= 0)
            ? (scalar[i/WORD_BITS] >> (i%WORD_BITS)) & 1
            : 0;

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
            int delta = (current + 1) >> 1;
            current = -(current & 1);

            int j;
            for (j=i; (delta & 1) == 0; j++) {
                delta >>= 1;
            }
            control[position].power = j+1;
            control[position].addend = delta;
            position++;
            assert(position <= nbits/(tableBits+1) + 2);
        }
    }
  
    control[position].power = -1;
    control[position].addend = 0;
    return position;
}


static void
prepare_wnaf_table(
    struct tw_pniels_t *output,
    struct tw_extensible_t *working,
    int tbits
) {
    convert_tw_extensible_to_tw_pniels(&output[0], working);

    if (tbits == 0) return;

    p448_tw_extensible_double(working);
    struct tw_pniels_t twop;
    convert_tw_extensible_to_tw_pniels(&twop, working);

    p448_tw_extensible_add_pniels(working, &output[0]);
    convert_tw_extensible_to_tw_pniels(&output[1], working);

    for (int i=2; i < 1<<tbits; i++) {
        p448_tw_extensible_add_pniels(working, &twop);
        convert_tw_extensible_to_tw_pniels(&output[i], working);
    }
}

int
edwards_scalar_multiply_vt(
    struct tw_extensible_t *working,
    const uint64_t scalar[7]
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
        return control_bits;
    }
  
    int conti = 1, i;
  
    struct tw_pniels_t neg;
    for (i = control[0].power - 1; i >= 0; i--) {
        p448_tw_extensible_double(working);

        if (i == control[conti].power) {
            assert(control[conti].addend);

            if (control[conti].addend > 0) {
                p448_tw_extensible_add_pniels(working, &precmp[control[conti].addend >> 1]);
            } else {
                /* PERF: uncond negate */
                copy_tw_pniels(&neg, &precmp[(-control[conti].addend) >> 1]);
                pniels_cond_negate(&neg, -1);
                p448_tw_extensible_add_pniels(working, &neg);
            }
            conti++;
            assert(conti <= control_bits);
        }
    }
    return control_bits; /* TODO: don't return anything, this is just for testing */
}

void
edwards_scalar_multiply_vt_pre(
    struct tw_extensible_t *working,
    const uint64_t scalar[7],
    const struct tw_niels_t *precmp,
    int table_bits
) {
    /* HACK: not 448? */
    const int nbits=448;
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
  
    struct tw_niels_t neg;
    for (i = control[0].power - 1; i >= 0; i--) {
        p448_tw_extensible_double(working);

        if (i == control[conti].power) {
            assert(control[conti].addend);

            if (control[conti].addend > 0) {
                p448_tw_extensible_add_niels(working, &precmp[control[conti].addend >> 1]);
            } else {
                /* PERF: uncond negate */
                copy_tw_niels(&neg, &precmp[(-control[conti].addend) >> 1]);
                niels_cond_negate(&neg, -1);
                p448_tw_extensible_add_niels(working, &neg);
            }
            conti++;
            assert(conti <= control_bits);
        }
    }
}

int
edwards_combo_var_fixed_vt(
    struct tw_extensible_t *working,
    const uint64_t scalar_var[7],
    const uint64_t scalar_pre[7],
    const struct tw_niels_t *precmp,
    int table_bits_pre
) {
    /* HACK: not 448? */
    const int nbits_var=448, nbits_pre=448, table_bits_var = 3;
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
        p448_tw_extensible_add_niels(working, &precmp[control_pre[0].addend >> 1]);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        convert_tw_niels_to_tw_extensible(working, &precmp[control_pre[0].addend >> 1]);
        contp++;
    }
    
    if (i < 0) {
        set_identity_tw_extensible(working);
        return ncb_pre;
    }
    
    struct tw_pniels_t pneg;
    struct tw_niels_t neg;
    for (i--; i >= 0; i--) {
        p448_tw_extensible_double(working);

        if (i == control_var[contv].power) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                p448_tw_extensible_add_pniels(working, &precmp_var[control_var[contv].addend >> 1]);
            } else {
                /* PERF: uncond negate */
                copy_tw_pniels(&pneg, &precmp_var[(-control_var[contv].addend) >> 1]);
                pniels_cond_negate(&pneg, -1);
                p448_tw_extensible_add_pniels(working, &pneg);
            }
            contv++;
        }

        if (i == control_pre[contp].power) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                p448_tw_extensible_add_niels(working, &precmp[control_pre[contp].addend >> 1]);
            } else {
                /* PERF: uncond negate */
                copy_tw_niels(&neg, &precmp[(-control_pre[contp].addend) >> 1]);
                niels_cond_negate(&neg, -1);
                p448_tw_extensible_add_niels(working, &neg);
            }
            contp++;
        }
    }
    
    assert(contv == ncb_var);
    assert(contp == ncb_pre);
    
    return ncb_pre;
}



