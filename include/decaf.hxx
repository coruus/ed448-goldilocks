/**
 * @file decaf.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, C++ version.
 *
 * The Decaf library implements cryptographic operations on a an elliptic curve
 * group of prime order p.  It accomplishes this by using a twisted Edwards
 * curve (isogenous to Ed448-Goldilocks) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases, except that
 * decaf_448_decode can fail because not every sequence of bytes is a valid group
 * element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_448_base_double_scalarmul_non_secret.
 *
 * This library may support multiple curves eventually.  The Ed448-Goldilocks
 * specific identifiers are prefixed with DECAF_448 or decaf_448.
 */
#ifndef __DECAF_448_HXX__
#define __DECAF_448_HXX__ 1

#include "decaf.h"

template<unsigned int bits = 448> struct decaf;

/* TODO: document */
/* TODO: This is incomplete */

template<> struct decaf<448> {

class Scalar {
public:
    decaf_448_scalar_t s;
    inline Scalar() {}
    inline Scalar(const decaf_word_t w) {  decaf_448_scalar_set(s,w); } 
    inline Scalar(const decaf_448_scalar_t &t) {  decaf_448_scalar_copy(s,t); } 
    inline Scalar(const Scalar &x) {  decaf_448_scalar_copy(s,x.s); }
    inline Scalar& operator=(const Scalar &x) {  decaf_448_scalar_copy(s,x.s); return *this; } 
    inline ~Scalar() {  decaf_448_scalar_destroy(s); }
    
    inline Scalar operator+ (const Scalar &q) { Scalar r; decaf_448_scalar_add(r.s,s,q.s); return r; }
    inline Scalar operator+=(const Scalar &q) { decaf_448_scalar_add(s,s,q.s); return *this; }
    inline Scalar operator- (const Scalar &q) { Scalar r; decaf_448_scalar_sub(r.s,s,q.s); return r; }
    inline Scalar operator-=(const Scalar &q) { decaf_448_scalar_sub(s,s,q.s); return *this; }
    inline Scalar operator* (const Scalar &q) { Scalar r; decaf_448_scalar_mul(r.s,s,q.s); return r; }
    inline Scalar operator*=(const Scalar &q) { decaf_448_scalar_mul(s,s,q.s); return *this; }
    inline Scalar operator-() { Scalar r; decaf_448_scalar_sub(r.s,decaf_448_scalar_zero,s); return r; }
    inline bool operator==(const Scalar &q) { return !!decaf_448_scalar_eq(s,q.s); }
};

class Point {
public:
    decaf_448_point_t p;
    inline Point() {}
    inline Point(const decaf_448_point_t &q) { decaf_448_point_copy(p,q); } /* TODO: not memcpy? */
    inline Point(const Point &q) { decaf_448_point_copy(p,q.p); }
    inline Point& operator=(const Point &q) { decaf_448_point_copy(p,q.p); return *this; }
    inline ~Point() { decaf_448_point_destroy(p); }
    
    inline Point operator+(const Point &q) { Point r; decaf_448_point_add(r.p,p,q.p); return r; }
    inline Point operator+=(const Point &q) { decaf_448_point_add(p,p,q.p); return *this; }
    inline Point operator-(const Point &q) { Point r; decaf_448_point_sub(r.p,p,q.p); return r; }
    inline Point operator-=(const Point &q) { decaf_448_point_sub(p,p,q.p); return *this; }
    inline Point operator-() { Point r; decaf_448_point_negate(r.p,p); return r; }
    inline Point operator*(const Scalar &s) { Point r; decaf_448_point_scalarmul(r.p,p,s.s); return r; }
    inline Point operator*=(const Scalar &s) { decaf_448_point_scalarmul(p,p,s.s); return *this; }
    inline Point times_two() { Point r; decaf_448_point_double(r.p,p); return r; }
    inline Point &double_in_place() { decaf_448_point_double(p,p); return *this; }
    inline bool operator==(const Point &q) { return !!decaf_448_point_eq(p,q.p); }
    
    static inline Point double_scalar_mul(
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) {
        Point p; decaf_448_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
};

}; /* struct decaf<448> */

#endif /* __DECAF_448_HXX__ */
