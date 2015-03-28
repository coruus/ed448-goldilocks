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

/** This code uses posix_memalign. */
#define _XOPEN_SOURCE 600 
#include <stdlib.h>
#include <string.h> /* for memcpy */

#include "decaf.h"
#include <string>
#include <sys/types.h>
#include <limits.h>

/* TODO: This is incomplete */
/* TODO: attribute nonnull */

/** @cond internal */
#if __cplusplus >= 201103L
#define NOEXCEPT noexcept
#define EXPLICIT_CON explicit
#define GET_DATA(str) ((const unsigned char *)&(str)[0])
#else
#define NOEXCEPT throw()
#define EXPLICIT_CON
#define GET_DATA(str) ((const unsigned char *)((str).data()))
#endif
/** @endcond */

namespace decaf {

/**
 * Securely erase contents of memory.
 */
void really_bzero(void *data, size_t size);
    
/**
 * @brief Group with prime order.
 * @todo Move declarations of functions up here?
 */
template<unsigned int bits = 448> struct decaf;

/**
 * @brief Ed448-Goldilocks/Decaf instantiation of group.
 */
template<> struct decaf<448> {

/** @brief An exception for when crypto (ie point decode) has failed. */
class CryptoException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const NOEXCEPT { return "CryptoException"; }
};

/** @cond internal */
class Point;
class Precomputed;
/** @endcond */

/**
 * @brief A scalar modulo the curve order.
 * Supports the usual arithmetic operations, all in constant time.
 */
class Scalar {
public:
    /** @brief access to the underlying scalar object */
    decaf_448_scalar_t s;
    
    /** @brief Set to an unsigned word */
    inline Scalar(const decaf_word_t w) NOEXCEPT { *this = w; }

    /** @brief Set to a signed word */
    inline Scalar(const int w) NOEXCEPT { *this = w; } 
    
    /** @brief Construct from decaf_scalar_t object. */
    inline Scalar(const decaf_448_scalar_t &t = decaf_448_scalar_zero) NOEXCEPT {  decaf_448_scalar_copy(s,t); } 
    
    /** @brief Copy constructor. */
    inline Scalar(const Scalar &x) NOEXCEPT {  decaf_448_scalar_copy(s,x.s); }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline explicit Scalar(const std::string &str) NOEXCEPT { *this = str; }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const unsigned char *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,buffer,n); }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const char *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,(const unsigned char *)buffer,n); }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const void *buffer, size_t n) NOEXCEPT { decaf_448_scalar_decode_long(s,(const unsigned char *)buffer,n); }
    
    /** @brief Assignment. */
    inline Scalar& operator=(const Scalar &x) NOEXCEPT {  decaf_448_scalar_copy(s,x.s); return *this; }
    
    /** @brief Assign from unsigned word. */
    inline Scalar& operator=(decaf_word_t w) NOEXCEPT {  decaf_448_scalar_set(s,w); return *this; }
    
    /** @brief Assign from signed int. */
    inline Scalar& operator=(int w) {
        Scalar t(-(decaf_word_t)INT_MIN);
        decaf_448_scalar_set(s,(decaf_word_t)w - (decaf_word_t)INT_MIN);
        *this -= t;
        return *this;
    }
    
    /** Destructor securely erases the scalar. */
    inline ~Scalar() NOEXCEPT { decaf_448_scalar_destroy(s); }
    
    /** @brief Assign from arbitrary-length little-endian byte sequence in C++ string. */
    inline Scalar &operator=(const std::string &str) NOEXCEPT {
        decaf_448_scalar_decode_long(s,GET_DATA(str),str.length()); return *this;
    }
    
    /**
     * @brief Decode from correct-length little-endian byte sequence.
     * @return DECAF_FAILURE if the scalar is greater than or equal to the group order q.
     */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const unsigned char buffer[DECAF_448_SCALAR_BYTES]
    ) NOEXCEPT {
        return decaf_448_scalar_decode(sc.s,buffer);
    }
    
    /** @brief Decode from correct-length little-endian byte sequence in C++ string. */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const std::string buffer
    ) NOEXCEPT {
        if (buffer.size() != DECAF_448_SCALAR_BYTES) return DECAF_FAILURE;
        return decaf_448_scalar_decode(sc.s,GET_DATA(buffer));
    }
    
    /** @brief Encode to fixed-length string */
    inline EXPLICIT_CON operator std::string() const NOEXCEPT {
        unsigned char buffer[DECAF_448_SCALAR_BYTES];
        decaf_448_scalar_encode(buffer, s);
        return std::string((char*)buffer,sizeof(buffer));
    }
    
    /** @brief Encode to fixed-length buffer */
    inline void encode(unsigned char buffer[DECAF_448_SCALAR_BYTES]) const NOEXCEPT{
        decaf_448_scalar_encode(buffer, s);
    }
    
    /** Add. */
    inline Scalar operator+ (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_add(r.s,s,q.s); return r; }
    
    /** Add to this. */
    inline Scalar operator+=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_add(s,s,q.s); return *this; }
    
    /** Subtract. */
    inline Scalar operator- (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_sub(r.s,s,q.s); return r; }
    
    /** Subtract from this. */
    inline Scalar operator-=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_sub(s,s,q.s); return *this; }
    
    /** Multiply */
    inline Scalar operator* (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_mul(r.s,s,q.s); return r; }
    
    /** Multiply into this. */
    inline Scalar operator*=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_mul(s,s,q.s); return *this; }
    
    /** Negate */
    inline Scalar operator- ()                const NOEXCEPT { Scalar r; decaf_448_scalar_sub(r.s,decaf_448_scalar_zero,s); return r; }
    
    /** @brief Invert with Fermat's Little Theorem (slow!).  If *this == 0, return 0. */
    inline Scalar inverse() const NOEXCEPT { Scalar r; decaf_448_scalar_invert(r.s,s); return r; }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar operator/ (const Scalar &q) const NOEXCEPT { Scalar r; decaf_448_scalar_mul(r.s,s,q.inverse().s); return r; }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar operator/=(const Scalar &q)       NOEXCEPT { decaf_448_scalar_mul(s,s,q.inverse().s); return *this; }
    
    /** @brief Compare in constant time */
    inline bool   operator!=(const Scalar &q) const NOEXCEPT { return ! decaf_448_scalar_eq(s,q.s); }
    
    /** @brief Compare in constant time */
    inline bool   operator==(const Scalar &q) const NOEXCEPT { return !!decaf_448_scalar_eq(s,q.s); }
    
    /** @brief Scalarmul with scalar on left. */
    inline Point operator* (const Point &q) const NOEXCEPT { return q * (*this); }
    
    /** @brief Scalarmul-precomputed with scalar on left. */
    inline Point operator* (const Precomputed &q) const NOEXCEPT { return q * (*this); }
};

/**
 * @brief Element of prime-order group.
 */
class Point {
public:
    /** The c-level object. */
    decaf_448_point_t p;
    
    /** @brief Constructor sets to identity by default. */
    inline Point(const decaf_448_point_t &q = decaf_448_point_identity) { decaf_448_point_copy(p,q); }
    
    /** @brief Copy constructor. */
    inline Point(const Point &q) { decaf_448_point_copy(p,q.p); }
    
    /** @brief Assignment. */
    inline Point& operator=(const Point &q) { decaf_448_point_copy(p,q.p); return *this; }
    
    /** @brief Destructor securely erases the point. */
    inline ~Point() { decaf_448_point_destroy(p); }
    
    /**
     * @brief Initialize from C++ fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
     * or was the identity and allow_identity was DECAF_FALSE.
     */
    inline explicit Point(const std::string &s, decaf_bool_t allow_identity=DECAF_TRUE) throw(CryptoException) {
        if (!decode(*this,s,allow_identity)) throw CryptoException();
    }
   
   /**
    * @brief Initialize from C fixed-length byte string.
     * The all-zero string maps to the identity.
     *
    * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
    * or was the identity and allow_identity was DECAF_FALSE.
    */
    inline explicit Point(const unsigned char buffer[DECAF_448_SER_BYTES], decaf_bool_t allow_identity=DECAF_TRUE)
        throw(CryptoException) { if (!decode(*this,buffer,allow_identity)) throw CryptoException(); }
    
    /**
     * @brief Initialize from C fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @retval DECAF_SUCCESS the string was successfully decoded.
     * @return DECAF_FAILURE the string wasn't the encoding of a point, or was the identity
     * and allow_identity was DECAF_FALSE.  Contents of the buffer are undefined.
     */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Point &p, const unsigned char buffer[DECAF_448_SER_BYTES], decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        return decaf_448_point_decode(p.p,buffer,allow_identity);
    }
    
    /**
     * @brief Initialize from C++ fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @retval DECAF_SUCCESS the string was successfully decoded.
     * @return DECAF_FAILURE the string was the wrong length, or wasn't the encoding of a point,
     * or was the identity and allow_identity was DECAF_FALSE.  Contents of the buffer are undefined.
     */    
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Point &p, const std::string &buffer, decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        if (buffer.size() != DECAF_448_SER_BYTES) return DECAF_FAILURE;
        return decaf_448_point_decode(p.p,GET_DATA(buffer),allow_identity);
    }

    /**
     * @brief Map to the curve from a C buffer.
     * The all-zero buffer maps to the identity, as does the buffer {1,0...}
     */
    static inline Point from_hash_nonuniform ( const unsigned char buffer[DECAF_448_SER_BYTES] ) NOEXCEPT {
        Point p; decaf_448_point_from_hash_nonuniform(p.p,buffer); return p;
    }
    
    /**
     * @brief Map to the curve from a C++ string buffer.
     * The empty or all-zero string maps to the identity, as does the string "\x01".
     * If the buffer is shorter than (TODO) DECAF_448_SER_BYTES, it will be zero-padded on the right.
     */
    static inline Point from_hash_nonuniform ( const std::string &s ) NOEXCEPT {
        std::string t = s;
        if (t.size() < DECAF_448_SER_BYTES) t.insert(t.size(),DECAF_448_SER_BYTES-t.size(),0);
        Point p; decaf_448_point_from_hash_nonuniform(p.p,GET_DATA(t)); return p;
    }
    
   
    /**
     * @brief Map uniformly to the curve from a C buffer.
     * The all-zero buffer maps to the identity, as does the buffer {1,0...}.
     */
    static inline Point from_hash ( const unsigned char buffer[2*DECAF_448_SER_BYTES] ) NOEXCEPT {
        Point p; decaf_448_point_from_hash_uniform(p.p,buffer); return p;
    }
   
    /**
     * @brief Map uniformly to the curve from a C++ buffer.
     * The empty or all-zero string maps to the identity, as does the string "\x01".
     * If the buffer is shorter than (TODO) 2*DECAF_448_SER_BYTES, well, it won't be as uniform,
     * but the buffer will be zero-padded on the right.
     */
    static inline Point from_hash ( const std::string &s ) NOEXCEPT {
        std::string t = s;
        if (t.size() < DECAF_448_SER_BYTES) return from_hash_nonuniform(s);
        if (t.size() < 2*DECAF_448_SER_BYTES) t.insert(t.size(),2*DECAF_448_SER_BYTES-t.size(),0);
        Point p; decaf_448_point_from_hash_uniform(p.p,GET_DATA(t)); return p;
    }
    
    /**
     * @brief Encode to string.  The identity encodes to the all-zero string.
     */
    inline EXPLICIT_CON operator std::string() const NOEXCEPT {
        unsigned char buffer[DECAF_448_SER_BYTES];
        decaf_448_point_encode(buffer, p);
        return std::string((char*)buffer,sizeof(buffer));
    }
   
   /**
    * @brief Encode to a C buffer.  The identity encodes to all zeros.
    */
    inline void encode(unsigned char buffer[DECAF_448_SER_BYTES]) const NOEXCEPT{
        decaf_448_point_encode(buffer, p);
    }
    
    /** @brief Point add. */
    inline Point operator+ (const Point &q)  const NOEXCEPT { Point r; decaf_448_point_add(r.p,p,q.p); return r; }
    
    /** @brief Point add. */
    inline Point operator+=(const Point &q)        NOEXCEPT { decaf_448_point_add(p,p,q.p); return *this; }
    
    /** @brief Point subtract. */
    inline Point operator- (const Point &q)  const NOEXCEPT { Point r; decaf_448_point_sub(r.p,p,q.p); return r; }
    
    /** @brief Point subtract. */
    inline Point operator-=(const Point &q)        NOEXCEPT { decaf_448_point_sub(p,p,q.p); return *this; }
    
    /** @brief Point negate. */
    inline Point operator- ()                const NOEXCEPT { Point r; decaf_448_point_negate(r.p,p); return r; }
    
    /** @brief Double the point out of place. */
    inline Point times_two ()                const NOEXCEPT { Point r; decaf_448_point_double(r.p,p); return r; }
    
    /** @brief Double the point in place. */
    inline Point &double_in_place()                NOEXCEPT { decaf_448_point_double(p,p); return *this; }
    
    /** @brief Constant-time compare. */
    inline bool  operator!=(const Point &q)  const NOEXCEPT { return ! decaf_448_point_eq(p,q.p); }

    /** @brief Constant-time compare. */
    inline bool  operator==(const Point &q)  const NOEXCEPT { return !!decaf_448_point_eq(p,q.p); }
    
    /** @brief Scalar multiply. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_448_point_scalarmul(r.p,p,s.s); return r; }
    
    /** @brief Scalar multiply in place. */
    inline Point operator*=(const Scalar &s)       NOEXCEPT { decaf_448_point_scalarmul(p,p,s.s); return *this; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
    /** @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster. */
    static inline Point double_scalarmul (
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) NOEXCEPT {
        Point p; decaf_448_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /**
     * @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster.
     * For those who like their scalars before the point.
     */
    static inline Point double_scalarmul (
        const Scalar &qs, const Point &q, const Scalar &rs, const Point &r
    ) NOEXCEPT {
        Point p; decaf_448_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /**
     * @brief Double-scalar multiply: this point by the first scalar and base by the second scalar.
     * @warning This function takes variable time, and may leak the scalars (or points, but currently
     * it doesn't).
     */
    inline Point non_secret_combo_with_base(const Scalar &s, const Scalar &s_base) {
        Point r; decaf_448_base_double_scalarmul_non_secret(r.p,s_base.s,p,s.s); return r;
    }
    
    /** @brief Return the base point */
    static inline const Point base() NOEXCEPT { return Point(decaf_448_point_base); }
    
    /** @brief Return the identity point */
    static inline const Point identity() NOEXCEPT { return Point(decaf_448_point_identity); }
};

/**
 * @brief Precomputed table of points.
 * Minor difficulties arise here because the decaf API doesn't expose, as a constant, how big such an object is.
 * Therefore we have to call malloc() or friends, but that's probably for the best, because you don't want to
 * stack-allocate a 15kiB object anyway.
 */
class Precomputed {
private:
    /** @cond internal */
    union {
        decaf_448_precomputed_s *mine;
        const decaf_448_precomputed_s *yours;
    } ours;
    bool isMine;
    
    inline void clear() NOEXCEPT {
        if (isMine) {
            decaf_448_precomputed_destroy(ours.mine);
            free(ours.mine);
            ours.yours = decaf_448_precomputed_base;
            isMine = false;
        }
    }
    inline void alloc() throw(std::bad_alloc) {
        if (isMine) return;
        int ret = posix_memalign((void**)&ours.mine, alignof_decaf_448_precomputed_s,sizeof_decaf_448_precomputed_s);
        if (ret || !ours.mine) {
            isMine = false;
            throw std::bad_alloc();
        }
        isMine = true;
    }
    inline const decaf_448_precomputed_s *get() const NOEXCEPT { return isMine ? ours.mine : ours.yours; }
    /** @endcond */
public:
    /** Destructor securely erases the memory. */
    inline ~Precomputed() NOEXCEPT { clear(); }
    
    /**
     * @brief Initialize from underlying type, declared as a reference to prevent
     * it from being called with 0, thereby breaking override.
     *
     * The underlying object must remain valid throughout the lifetime of this one.
     *
     * By default, initializes to the table for the base point.
     *
     * @warning The empty initializer makes this equal to base, unlike the empty
     * initializer for points which makes this equal to the identity.
     */ 
    inline Precomputed(
        const decaf_448_precomputed_s &yours = *decaf_448_precomputed_base
    ) NOEXCEPT {
        ours.yours = &yours;
        isMine = false;
    }
    
    /**
     * @brief Assign.  This may require an allocation and memcpy.
     */ 
    inline Precomputed &operator=(const Precomputed &it) throw(std::bad_alloc) {
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
    
    /**
     * @brief Initilaize from point.  Must allocate memory, and may throw.
     */
    inline Precomputed &operator=(const Point &it) throw(std::bad_alloc) {
        alloc();
        decaf_448_precompute(ours.mine,it.p);
        return *this;
    }
    
    /**
     * @brief Copy constructor.
     */
    inline Precomputed(const Precomputed &it) throw(std::bad_alloc) : isMine(false) { *this = it; }
   
    /**
     * @brief Constructor which initializes from point.
     */
    inline explicit Precomputed(const Point &it) throw(std::bad_alloc) : isMine(false) { *this = it; }
    
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
    
    /** @brief Fixed base scalarmul. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_448_precomputed_scalarmul(r.p,get(),s.s); return r; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
    /** @brief Return the table for the base point. */
    static inline const Precomputed base() NOEXCEPT { return Precomputed(*decaf_448_precomputed_base); }
};

}; /* struct decaf<448> */

#undef NOEXCEPT
#undef EXPLICIT_CON
#undef GET_DATA
} /* namespace decaf */

#endif /* __DECAF_448_HXX__ */
