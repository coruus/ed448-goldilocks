/**
 * @file decaf.hxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief A group of prime order p, C++ wrapper.
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
 */
#ifndef __DECAF_448_HXX__
#define __DECAF_448_HXX__ 1

#define _XOPEN_SOURCE 600 /* for posix_memalign */
#include <stdlib.h>
#include <string.h> /* for memcpy */

#include "decaf.h"
#include <string>

/* TODO: document */
/* TODO: This is incomplete */
/* TODO: attribute nonnull */

#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#define EXPLICIT_CON explicit
#define GET_DATA(str) ((const unsigned char *)&(str)[0])
#else
#define NOEXCEPT
#define EXPLICIT_CON
#define GET_DATA(str) ((const unsigned char *)((str).data()))
#endif

namespace decaf {

void really_bzero(void *data, size_t size);
    
template<unsigned int bits = 448> struct decaf;
template<> struct decaf<448> {

class Scalar {
public:
    decaf_448_scalar_t s;
    inline Scalar() NOEXCEPT {}
    inline Scalar(const decaf_word_t w) NOEXCEPT {  decaf_448_scalar_set(s,w); } 
    inline Scalar(const decaf_448_scalar_t &t) NOEXCEPT {  decaf_448_scalar_copy(s,t); } 
    inline Scalar(const Scalar &x) NOEXCEPT {  decaf_448_scalar_copy(s,x.s); }
    inline Scalar& operator=(const Scalar &x) NOEXCEPT {  decaf_448_scalar_copy(s,x.s); return *this; } 
    inline ~Scalar() NOEXCEPT {  decaf_448_scalar_destroy(s); }
    
    /* Initialize from buffer */
    inline explicit Scalar(const std::string &str) NOEXCEPT { decaf_448_scalar_decode_long(s,GET_DATA(str),str.length()); }
    inline Scalar(const unsigned char *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,buffer,n); }
    inline Scalar(const char *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,(const unsigned char *)buffer,n); }
    inline Scalar(const void *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,(const unsigned char *)buffer,n); }
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const unsigned char buffer[DECAF_448_SCALAR_BYTES]
    ) NOEXCEPT {
        return decaf_448_scalar_decode(sc.s,buffer);
    }
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const std::string buffer
    ) NOEXCEPT {
        if (buffer.size() != DECAF_448_SCALAR_BYTES) return DECAF_FAILURE;
        return decaf_448_scalar_decode(sc.s,GET_DATA(buffer));
    }
    inline EXPLICIT_CON operator std::string() const NOEXCEPT {
        unsigned char buffer[DECAF_448_SCALAR_BYTES];
        decaf_448_scalar_encode(buffer, s);
        return std::string((char*)buffer,sizeof(buffer));
    }
    inline void write_to_buffer(unsigned char buffer[DECAF_448_SCALAR_BYTES]) const NOEXCEPT{
        decaf_448_scalar_encode(buffer, s);
    }
    
    /* Arithmetic */
    inline Scalar operator+ (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_add(r.s,s,q.s); return r; }
    inline Scalar operator+=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_add(s,s,q.s); return *this; }
    inline Scalar operator- (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_sub(r.s,s,q.s); return r; }
    inline Scalar operator-=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_sub(s,s,q.s); return *this; }
    inline Scalar operator* (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_mul(r.s,s,q.s); return r; }
    inline Scalar operator*=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_mul(s,s,q.s); return *this; }
    inline Scalar operator- ()                const NOEXCEPT { Scalar r; decaf_448_scalar_sub(r.s,decaf_448_scalar_zero,s); return r; }
    inline bool   operator==(const Scalar &q) const NOEXCEPT { return !!decaf_448_scalar_eq(s,q.s); }
};

class Point {
public:
    decaf_448_point_t p;
    inline Point() {}
    inline Point(const decaf_448_point_t &q) { decaf_448_point_copy(p,q); } /* TODO: not memcpy? */
    inline Point(const Point &q) { decaf_448_point_copy(p,q.p); }
    inline Point& operator=(const Point &q) { decaf_448_point_copy(p,q.p); return *this; }
    inline ~Point() { decaf_448_point_destroy(p); }
    
    /* serialize / deserialize */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Point &p, const unsigned char buffer[DECAF_448_SER_BYTES], decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        return decaf_448_point_decode(p.p,buffer,allow_identity);
    }
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Point &p, const std::string &buffer, decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        if (buffer.size() != DECAF_448_SER_BYTES) return DECAF_FAILURE;
        return decaf_448_point_decode(p.p,GET_DATA(buffer),allow_identity);
    }
    inline EXPLICIT_CON operator std::string() const NOEXCEPT {
        unsigned char buffer[DECAF_448_SER_BYTES];
        decaf_448_point_encode(buffer, p);
        return std::string((char*)buffer,sizeof(buffer));
    }
    inline void write_to_buffer(unsigned char buffer[DECAF_448_SER_BYTES]) const NOEXCEPT{
        decaf_448_point_encode(buffer, p);
    }
    
    /* Point/point arithmetic */
    inline Point operator+ (const Point &q)  const NOEXCEPT { Point r; decaf_448_point_add(r.p,p,q.p); return r; }
    inline Point operator+=(const Point &q)        NOEXCEPT { decaf_448_point_add(p,p,q.p); return *this; }
    inline Point operator- (const Point &q)  const NOEXCEPT { Point r; decaf_448_point_sub(r.p,p,q.p); return r; }
    inline Point operator-=(const Point &q)        NOEXCEPT { decaf_448_point_sub(p,p,q.p); return *this; }
    inline Point operator- ()                const NOEXCEPT { Point r; decaf_448_point_negate(r.p,p); return r; }
    inline Point times_two ()                const NOEXCEPT { Point r; decaf_448_point_double(r.p,p); return r; }
    inline Point &double_in_place()                NOEXCEPT { decaf_448_point_double(p,p); return *this; }
    inline bool  operator==(const Point &q)  const NOEXCEPT { return !!decaf_448_point_eq(p,q.p); }
    
    /* Scalarmul */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_448_point_scalarmul(r.p,p,s.s); return r; }
    inline Point operator*=(const Scalar &s)       NOEXCEPT { decaf_448_point_scalarmul(p,p,s.s); return *this; }
    
    static inline Point double_scalar_mul (
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) NOEXCEPT {
        Point p; decaf_448_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /* FIXME: are these defined to be correct? */
    static inline const Point &base() NOEXCEPT { return (const Point &)decaf_448_point_base; }
    static inline const Point &identity() NOEXCEPT { return (const Point &)decaf_448_point_identity; }
};

class Precomputed {
public:
    union {
        decaf_448_precomputed_s *mine;
        const decaf_448_precomputed_s *yours;
    } ours;
    bool isMine;
    
private:
    inline void clear() NOEXCEPT {
        if (isMine) {
            decaf_448_precomputed_destroy(ours.mine);
            free(ours.mine);
            ours.yours = decaf_448_precomputed_base;
            isMine = false;
        }
    }
    inline void alloc() {
        if (isMine) return;
        int ret = posix_memalign((void**)&ours.mine, alignof_decaf_448_precomputed_s,sizeof_decaf_448_precomputed_s);
        if (ret || !ours.mine) {
            isMine = false;
            throw std::bad_alloc();
        }
        isMine = true;
    }
    inline const decaf_448_precomputed_s *get() const NOEXCEPT { return isMine ? ours.mine : ours.yours; }
    
public:
    inline ~Precomputed() NOEXCEPT { clear(); }
    inline Precomputed(const decaf_448_precomputed_s *yours = decaf_448_precomputed_base) NOEXCEPT {
        ours.yours = yours;
        isMine = false;
    }
    inline Precomputed &operator=(const Precomputed &it) {
        if (this == &it) return *this;
        if (it.isMine) {
            alloc();
            memcpy(ours.mine,it.ours.mine,sizeof_decaf_448_precomputed_s);
        } else {
            clear();
            ours.yours = it.ours.yours;
        }
        isMine = it.isMine;
        return *this;
    }
    inline Precomputed &operator=(const Point &it) {
        alloc();
        decaf_448_precompute(ours.mine,it.p);
        return *this;
    }
    inline Precomputed(const Precomputed &it) NOEXCEPT : isMine(false) { *this = it; }
    inline Precomputed(const Point &it) NOEXCEPT : isMine(false) { *this = it; }
#if __cplusplus >= 201103L
    inline Precomputed &operator=(Precomputed &&it) NOEXCEPT {
        if (this == &it) return *this;
        clear();
        ours = it.ours;
        isMine = it.isMine;
        it.isMine = false;
        it.ours.yours = decaf_448_precomputed_base;
        return *this;
    }
    inline Precomputed(Precomputed &&it) NOEXCEPT : isMine(false) { *this = it; }
#endif
    
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_448_precomputed_scalarmul(r.p,get(),s.s); return r; }
    
    static inline const Precomputed base() NOEXCEPT { return Precomputed(decaf_448_precomputed_base); }
};

#undef NOEXCEPT

}; /* struct decaf<448> */
}; /* namespace decaf */

#endif /* __DECAF_448_HXX__ */
