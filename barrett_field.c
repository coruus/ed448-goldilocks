/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "barrett_field.h"
#include <assert.h>

word_t
add_nr_ext_packed(
    word_t *out,
    const word_t *a,
    int nwords_a,
    const word_t *c,
    int nwords_c,
    word_t mask
) {
    int i;
    dword_t carry = 0;
    for (i=0; i<nwords_c; i++) {
        out[i] = carry = carry + a[i] + (c[i]&mask);
        carry >>= WORD_BITS;
    }
    for (; i<nwords_a; i++) {
        out[i] = carry = carry + a[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

static __inline__ word_t
add_nr_packed(
    word_t *a,
    const word_t *c,
    int nwords
) {
    int i;
    dword_t carry = 0;
    for (i=0; i<nwords; i++) {
        a[i] = carry = carry + a[i] + c[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

static __inline__ word_t
sub_nr_packed(
    word_t *a,
    const word_t *c,
    int nwords
) {
    int i;
    dsword_t carry = 0;
    for (i=0; i<nwords; i++) {
        a[i] = carry = carry + a[i] - c[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

word_t
sub_nr_ext_packed(
    word_t *out,
    const word_t *a,
    int nwords_a,
    const word_t *c,
    int nwords_c,
    word_t mask
) {
    int i;
    dsword_t carry = 0;
    for (i=0; i<nwords_c; i++) {
        out[i] = carry = carry + a[i] - (c[i]&mask);
        carry >>= WORD_BITS;
    }
    for (; i<nwords_a; i++) {
        out[i] = carry = carry + a[i];
        carry >>= WORD_BITS;
    }
    return carry;
}

static word_t
widemac(
    word_t *accum,
    int nwords_accum,
    const word_t *mier,
    int nwords_mier,
    word_t mand,
    word_t carry
) {
    int i;
    assert(nwords_accum >= nwords_mier);
    
    for (i=0; i<nwords_mier; i++) {
        /* UMAAL chain for the wordy part of p */
        dword_t product = ((dword_t)mand) * mier[i];
        product += accum[i];
        product += carry;
        accum[i] = product;
        carry = product >> WORD_BITS;
    }
    
    for (; i<nwords_accum; i++) {
        dword_t sum = ((dword_t)carry) + accum[i];
        accum[i] = sum;
        carry = sum >> WORD_BITS;
    }
    
    return carry;
}

void
barrett_negate (
    word_t *a,
    int nwords_a,
    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
) {
    int i;
    dsword_t carry = 0;
    
    barrett_reduce(a,nwords_a,0,p_lo,nwords_p,nwords_lo,p_shift);
    
    /* Have p = 2^big - p_lo.  Want p - a = 2^big - p_lo - a */
    
    for (i=0; i<nwords_lo; i++) {
        a[i] = carry = carry - p_lo[i] - a[i];
        carry >>= WORD_BITS;
    }
    for (; i<nwords_p; i++) {
        a[i] = carry = carry - a[i];
        if (i<nwords_p-1) {
            carry >>= WORD_BITS;
        }
    }
    
    a[nwords_p-1] = carry = carry + (((word_t)1) << p_shift);
    
    for (; i<nwords_a; i++) {
        assert(!a[i]);
    }
    
    assert(!(carry>>64));
}

void
barrett_reduce(
    word_t *a,
    int nwords_a,
    word_t a_carry,
    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift
) {
    /* TODO: non 2^k-c primes. */
    int repeat, nwords_left_in_a=nwords_a;
    
    /* TODO: is there a point to this a_carry business? */
    assert(a_carry < ((word_t)1)<<p_shift && nwords_a >= nwords_p);
    
    for (; nwords_left_in_a >= nwords_p; nwords_left_in_a--) {
        for (repeat=0; repeat<2; repeat++) {
            /* PERF: surely a more careful implementation could
             * avoid this double round
             */
            word_t mand = a[nwords_left_in_a-1] >> p_shift;
            a[nwords_left_in_a-1] &= (((word_t)1)<<p_shift)-1;
            if (p_shift && !repeat) {
                /* collect high bits when there are any */
                if (nwords_left_in_a < nwords_a) {
                    mand |= a[nwords_left_in_a] << (WORD_BITS-p_shift);
                    a[nwords_left_in_a] = 0;
                } else {
                    mand |= a_carry << (WORD_BITS-p_shift);
                }
            }
            
            word_t carry = widemac(a+nwords_left_in_a-nwords_p, nwords_p, p_lo, nwords_lo, mand, 0);
            assert(!carry);
            (void)carry;
        }
    }
    
    assert(nwords_left_in_a == nwords_p-1);
    
    /* OK, but it still isn't reduced.  Add and subtract p_lo. */
    word_t cout = add_nr_ext_packed(a,a,nwords_p,p_lo,nwords_lo,-1);
    if (p_shift) {
        cout = (cout<<(WORD_BITS-p_shift)) + (a[nwords_p-1]>>p_shift);
        a[nwords_p-1] &= (((word_t)1)<<p_shift)-1;
    }
    
    /* mask = carry-1: if no carry then do sub, otherwise don't */
    sub_nr_ext_packed(a,a,nwords_p,p_lo,nwords_lo,cout-1);
}

/* PERF: This function is horribly slow.  Enough to break 1%. */
void
barrett_mul_or_mac(
    word_t *accum,
    int nwords_accum,
    
    const word_t *a,
    int nwords_a,
    
    const word_t *b,
    int nwords_b,
    
    const word_t *p_lo,
    int nwords_p,
    int nwords_lo,
    int p_shift,
    
    mask_t doMac
) {
    assert(nwords_accum >= nwords_p);
    
    /* nwords_tmp = max(nwords_a + 1, nwords_p + 1, nwords_accum if doMac); */
    int nwords_tmp = (nwords_a > nwords_p) ? nwords_a : nwords_p;
    nwords_tmp++;
    if (nwords_tmp < nwords_accum && doMac)
        nwords_tmp = nwords_accum;
    
    word_t tmp[nwords_tmp];
    int bpos, i;
    
    for (i=0; i<nwords_tmp; i++) {
        tmp[i] = 0;
    }
    
    for (bpos=nwords_b-1; bpos >= 0; bpos--) {
        /* Invariant at the beginning of the loop: the high word is unused. */
        assert(tmp[nwords_tmp-1] == 0);
        
        /* shift up */
        for (i=nwords_tmp-2; i>=0; i--) {
            tmp[i+1] = tmp[i];
        }
        tmp[0] = 0;

        /* mac and reduce */
        word_t carry = widemac(tmp, nwords_tmp, a, nwords_a, b[bpos], 0);
        
        /* the mac can't carry, because nwords_tmp >= nwords_a+1 and its high word is clear */
        assert(!carry);
        barrett_reduce(tmp, nwords_tmp, carry, p_lo, nwords_p, nwords_lo, p_shift);
        
        /* at this point, the number of words used is nwords_p <= nwords_tmp-1,
         * so the high word is again clear */
    }
    
    if (doMac) {
        word_t cout = add_nr_packed(tmp, accum, nwords_accum);
        barrett_reduce(tmp, nwords_tmp, cout, p_lo, nwords_p, nwords_lo, p_shift);
    }
    
    for (i=0; i<nwords_tmp && i<nwords_accum; i++) {
        accum[i] = tmp[i];
    }
    for (; i<nwords_tmp; i++) {
        assert(tmp[i] == 0);
    }
    for (; i<nwords_accum; i++) {
        accum[i] = 0;
    }
}
