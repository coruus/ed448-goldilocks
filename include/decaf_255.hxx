/**
 * @file decaf_255.hxx
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
 * curve (isogenous to Ed255-Goldilocks) and wiping out the cofactor.
 *
 * The formulas are all complete and have no special cases, except that
 * decaf_255_decode can fail because not every sequence of bytes is a valid group
 * element.
 *
 * The formulas contain no data-dependent branches, timing or memory accesses,
 * except for decaf_255_base_double_scalarmul_non_secret.
 */
#ifndef __DECAF_255_HXX__
#define __DECAF_255_HXX__ 1

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

/** @brief An exception for when crypto (ie point decode) has failed. */
class CryptoException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const NOEXCEPT { return "CryptoException"; }
};

/** @brief An exception for when crypto (ie point decode) has failed. */
class LengthException : public std::exception {
public:
    /** @return "CryptoException" */
    virtual const char * what() const NOEXCEPT { return "LengthException"; }
};

/**
 * Securely erase contents of memory.
 */
static inline void really_bzero(void *data, size_t size) { decaf_bzero(data,size); }

/** Block object */
class Block {
protected:
    unsigned char *data_;
    size_t size_;

public:
    /** Empty init */
    inline Block() NOEXCEPT : data_(NULL), size_(0) {}
    
    /** Init from C string */
    inline Block(const char *data) NOEXCEPT : data_((unsigned char *)data), size_(strlen(data)) {}

    /** Unowned init */
    inline Block(const unsigned char *data, size_t size) NOEXCEPT : data_((unsigned char *)data), size_(size) {}
    
    /** Block from std::string */
    inline Block(const std::string &s) : data_((unsigned char *)GET_DATA(s)), size_(s.size()) {}

    /** Get const data */
    inline const unsigned char *data() const NOEXCEPT { return data_; }

    /** Get the size */
    inline size_t size() const NOEXCEPT { return size_; }

    /** Autocast to const unsigned char * */
    inline operator const unsigned char*() const NOEXCEPT { return data_; }

    /** Convert to C++ string */
    inline std::string get_string() const {
        return std::string((const char *)data_,size_);
    }

    /** Slice the buffer*/
    inline Block slice(size_t off, size_t length) const throw(LengthException) {
        if (off > size() || length > size() - off)
            throw LengthException();
        return Block(data()+off, length);
    }
    
    /* Content-wise comparison; constant-time if they are the same length.
     * FIXME: is it wise to have a content-wise compare on objects that may be mutable?
     */ 
    inline decaf_bool_t operator==(const Block &b) const NOEXCEPT {
        return ~(*this != b);
    }
    
    inline decaf_bool_t operator!=(const Block &b) const NOEXCEPT {
        if (b.size() != size()) return true;
        return ~decaf_memeq(b,*this,size());
    }

    /** Virtual destructor for SecureBlock. TODO: probably means vtable?  Make bool? */
    inline virtual ~Block() {};
};

class TmpBuffer;

class Buffer : public Block {
public:
    /** Null init */
    inline Buffer() NOEXCEPT : Block() {}

    /** Unowned init */
    inline Buffer(unsigned char *data, size_t size) NOEXCEPT : Block(data,size) {}

    /** Get unconst data */
    inline unsigned char *data() NOEXCEPT { return data_; }

    /** Get const data */
    inline const unsigned char *data() const NOEXCEPT { return data_; }

    /** Autocast to const unsigned char * */
    inline operator const unsigned char*() const NOEXCEPT { return data_; }

    /** Autocast to unsigned char */
    inline operator unsigned char*() NOEXCEPT { return data_; }

    /** Slice the buffer*/
    inline TmpBuffer slice(size_t off, size_t length) throw(LengthException);
};

class TmpBuffer : public Buffer {
public:
    /** Unowned init */
    inline TmpBuffer(unsigned char *data, size_t size) NOEXCEPT : Buffer(data,size) {}
};

TmpBuffer Buffer::slice(size_t off, size_t length) throw(LengthException) {
    if (off > size() || length > size() - off) throw LengthException();
    return TmpBuffer(data()+off, length);
}

/** A self-erasing block of data */
class SecureBuffer : public Buffer {
public:
    /** Null secure block */
    inline SecureBuffer() NOEXCEPT : Buffer() {}

    /** Construct empty from size */
    inline SecureBuffer(size_t size) {
        data_ = new unsigned char[size_ = size];
        memset(data_,0,size);
    }

    /** Construct from data */
    inline SecureBuffer(const unsigned char *data, size_t size){
        data_ = new unsigned char[size_ = size];
        memcpy(data_, data, size);
    }

    /** Copy constructor */
    inline SecureBuffer(const Block &copy) : Buffer() { *this = copy; }

    /** Copy-assign constructor */
    inline SecureBuffer& operator=(const Block &copy) throw(std::bad_alloc) {
        if (&copy == this) return *this;
        clear();
        data_ = new unsigned char[size_ = copy.size()];
        memcpy(data_,copy.data(),size_);
        return *this;
    }

    /** Copy-assign constructor */
    inline SecureBuffer& operator=(const SecureBuffer &copy) throw(std::bad_alloc) {
        if (&copy == this) return *this;
        clear();
        data_ = new unsigned char[size_ = copy.size()];
        memcpy(data_,copy.data(),size_);
        return *this;
    }

    /** Destructor erases data */
    ~SecureBuffer() NOEXCEPT { clear(); }

    /** Clear data */
    inline void clear() NOEXCEPT {
        if (data_ == NULL) return;
        really_bzero(data_,size_);
        delete[] data_;
        data_ = NULL;
        size_ = 0;
    }

#if __cplusplus >= 201103L
    /** Move constructor */
    inline SecureBuffer(SecureBuffer &&move) { *this = move; }

    /** Move non-constructor */
    inline SecureBuffer(Block &&move) { *this = (Block &)move; }

    /** Move-assign constructor. TODO: check that this actually gets used.*/ 
    inline SecureBuffer& operator=(SecureBuffer &&move) {
        clear();
        data_ = move.data_; move.data_ = NULL;
        size_ = move.size_; move.size_ = 0;
        return *this;
    }

    /** C++11-only explicit cast */
    inline explicit operator std::string() const { return get_string(); }
#endif
};


/** @brief Passed to constructors to avoid (conservative) initialization */
struct NOINIT {};

/**@cond internal*/
/** Forward-declare sponge RNG object */
class SpongeRng;
/**@endcond*/


/**
 * @brief Ed255-Goldilocks/Decaf instantiation of group.
 */
struct Ed255 {

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
    /** @brief Size of a serialized element */
    static const size_t SER_BYTES = DECAF_255_SCALAR_BYTES;
    
    /** @brief access to the underlying scalar object */
    decaf_255_scalar_t s;
    
    /** @brief Don't initialize. */
    inline Scalar(const NOINIT &) NOEXCEPT {}
    
    /** @brief Set to an unsigned word */
    inline Scalar(const decaf_word_t w) NOEXCEPT { *this = w; }

    /** @brief Set to a signed word */
    inline Scalar(const int w) NOEXCEPT { *this = w; } 
    
    /** @brief Construct from RNG */
    inline explicit Scalar(SpongeRng &rng) NOEXCEPT;
    
    /** @brief Construct from decaf_scalar_t object. */
    inline Scalar(const decaf_255_scalar_t &t = decaf_255_scalar_zero) NOEXCEPT {  decaf_255_scalar_copy(s,t); } 
    
    /** @brief Copy constructor. */
    inline Scalar(const Scalar &x) NOEXCEPT {  *this = x; }
    
    /** @brief Construct from arbitrary-length little-endian byte sequence. */
    inline Scalar(const Block &buffer) NOEXCEPT { *this = buffer; }
    
    /** @brief Assignment. */
    inline Scalar& operator=(const Scalar &x) NOEXCEPT {  decaf_255_scalar_copy(s,x.s); return *this; }
    
    /** @brief Assign from unsigned word. */
    inline Scalar& operator=(decaf_word_t w) NOEXCEPT {  decaf_255_scalar_set(s,w); return *this; }
    
    /** @brief Assign from signed int. */
    inline Scalar& operator=(int w) NOEXCEPT {
        Scalar t(-(decaf_word_t)INT_MIN);
        decaf_255_scalar_set(s,(decaf_word_t)w - (decaf_word_t)INT_MIN);
        *this -= t;
        return *this;
    }
    
    /** Destructor securely erases the scalar. */
    inline ~Scalar() NOEXCEPT { decaf_255_scalar_destroy(s); }
    
    /** @brief Assign from arbitrary-length little-endian byte sequence in a Block. */
    inline Scalar &operator=(const Block &bl) NOEXCEPT {
        decaf_255_scalar_decode_long(s,bl.data(),bl.size()); return *this;
    }
    
    /**
     * @brief Decode from correct-length little-endian byte sequence.
     * @return DECAF_FAILURE if the scalar is greater than or equal to the group order q.
     */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const unsigned char buffer[SER_BYTES]
    ) NOEXCEPT {
        return decaf_255_scalar_decode(sc.s,buffer);
    }
    
    /** @brief Decode from correct-length little-endian byte sequence in C++ string. */
    static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
        Scalar &sc, const Block &buffer
    ) NOEXCEPT {
        if (buffer.size() != SER_BYTES) return DECAF_FAILURE;
        return decaf_255_scalar_decode(sc.s,buffer);
    }
    
    /** @brief Encode to fixed-length string */
    inline EXPLICIT_CON operator SecureBuffer() const NOEXCEPT {
        SecureBuffer buf(SER_BYTES); decaf_255_scalar_encode(buf,s); return buf;
    }
    
    /** @brief Encode to fixed-length buffer */
    inline void encode(unsigned char buffer[SER_BYTES]) const NOEXCEPT{
        decaf_255_scalar_encode(buffer, s);
    }
    
    /** Add. */
    inline Scalar  operator+ (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_add(r.s,s,q.s); return r; }
    
    /** Add to this. */
    inline Scalar &operator+=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_add(s,s,q.s); return *this; }
    
    /** Subtract. */
    inline Scalar  operator- (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_sub(r.s,s,q.s); return r; }
    
    /** Subtract from this. */
    inline Scalar &operator-=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_sub(s,s,q.s); return *this; }
    
    /** Multiply */
    inline Scalar  operator* (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_mul(r.s,s,q.s); return r; }
    
    /** Multiply into this. */
    inline Scalar &operator*=(const Scalar &q)       NOEXCEPT { decaf_255_scalar_mul(s,s,q.s); return *this; }
    
    /** Negate */
    inline Scalar operator- ()                const NOEXCEPT { Scalar r((NOINIT())); decaf_255_scalar_sub(r.s,decaf_255_scalar_zero,s); return r; }
    
    /** @brief Invert with Fermat's Little Theorem (slow!).  If *this == 0, return 0. */
    inline Scalar inverse() const NOEXCEPT { Scalar r; decaf_255_scalar_invert(r.s,s); return r; }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar operator/ (const Scalar &q) const NOEXCEPT { return *this * q.inverse(); }
    
    /** @brief Divide by inverting q. If q == 0, return 0.  */
    inline Scalar &operator/=(const Scalar &q)       NOEXCEPT { return *this *= q.inverse(); }
    
    /** @brief Compare in constant time */
    inline bool   operator!=(const Scalar &q) const NOEXCEPT { return !(*this == q); }
    
    /** @brief Compare in constant time */
    inline bool   operator==(const Scalar &q) const NOEXCEPT { return !!decaf_255_scalar_eq(s,q.s); }
    
    /** @brief Scalarmul with scalar on left. */
    inline Point operator* (const Point &q) const NOEXCEPT { return q * (*this); }
    
    /** @brief Scalarmul-precomputed with scalar on left. */
    inline Point operator* (const Precomputed &q) const NOEXCEPT { return q * (*this); }
    
    /** @brief Direct scalar multiplication. */
    inline SecureBuffer direct_scalarmul(
        const Block &in,
        decaf_bool_t allow_identity=DECAF_FALSE,
        decaf_bool_t short_circuit=DECAF_TRUE    
    ) const throw(CryptoException) {
        SecureBuffer out(/*FIXME Point::*/SER_BYTES);
        if (!decaf_255_direct_scalarmul(out, in.data(), s, allow_identity, short_circuit))
            throw CryptoException();
        return out;
    }
};

/**
 * @brief Element of prime-order group.
 */
class Point {
public:
    /** @brief Size of a serialized element */
    static const size_t SER_BYTES = DECAF_255_SER_BYTES;
    
    /** @brief Size of a stegged element */
    static const size_t STEG_BYTES = DECAF_255_SER_BYTES + 8;
    
    /** @brief Bytes required for hash */
    static const size_t HASH_BYTES = DECAF_255_SER_BYTES;
    
    /** The c-level object. */
    decaf_255_point_t p;
    
    /** @brief Don't initialize. */
    inline Point(const NOINIT &) NOEXCEPT {}
    
    /** @brief Constructor sets to identity by default. */
    inline Point(const decaf_255_point_t &q = decaf_255_point_identity) NOEXCEPT { decaf_255_point_copy(p,q); }
    
    /** @brief Copy constructor. */
    inline Point(const Point &q) NOEXCEPT { decaf_255_point_copy(p,q.p); }
    
    /** @brief Assignment. */
    inline Point& operator=(const Point &q) NOEXCEPT { decaf_255_point_copy(p,q.p); return *this; }
    
    /** @brief Destructor securely erases the point. */
    inline ~Point() NOEXCEPT { decaf_255_point_destroy(p); }
    
    /** @brief Construct from RNG */
    inline explicit Point(SpongeRng &rng, bool uniform = true) NOEXCEPT;
    
    /**
     * @brief Initialize from C++ fixed-length byte string.
     * The all-zero string maps to the identity.
     *
     * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
     * or was the identity and allow_identity was DECAF_FALSE.
     */
    inline explicit Point(const Block &s, decaf_bool_t allow_identity=DECAF_TRUE) throw(CryptoException) {
        if (!decode(*this,s,allow_identity)) throw CryptoException();
    }
   
   /**
    * @brief Initialize from C fixed-length byte string.
     * The all-zero string maps to the identity.
     *
    * @throw CryptoException the string was the wrong length, or wasn't the encoding of a point,
    * or was the identity and allow_identity was DECAF_FALSE.
    */
    inline explicit Point(const unsigned char buffer[SER_BYTES], decaf_bool_t allow_identity=DECAF_TRUE)
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
        Point &p, const unsigned char buffer[SER_BYTES], decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        return decaf_255_point_decode(p.p,buffer,allow_identity);
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
        Point &p, const Block &buffer, decaf_bool_t allow_identity=DECAF_TRUE
    ) NOEXCEPT {
        if (buffer.size() != SER_BYTES) return DECAF_FAILURE;
        return decaf_255_point_decode(p.p,buffer.data(),allow_identity);
    }
   
    /**
     * @brief Map uniformly to the curve from a hash buffer.
     * The empty or all-zero string maps to the identity, as does the string "\x01".
     * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
     * but the buffer will be zero-padded on the right.
     */
    static inline Point from_hash ( const Block &s ) NOEXCEPT {
        Point p((NOINIT())); p.set_to_hash(s); return p;
    }

   /**
    * @brief Map to the curve from a hash buffer.
    * The empty or all-zero string maps to the identity, as does the string "\x01".
    * If the buffer is shorter than 2*HASH_BYTES, well, it won't be as uniform,
    * but the buffer will be zero-padded on the right.
    */
    inline unsigned char set_to_hash( const Block &s ) NOEXCEPT {
        if (s.size() < HASH_BYTES) {
            SecureBuffer b(HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            return decaf_255_point_from_hash_nonuniform(p,b);
        } else if (s.size() == HASH_BYTES) {
            return decaf_255_point_from_hash_nonuniform(p,s);
        } else if (s.size() < 2*HASH_BYTES) {
            SecureBuffer b(2*HASH_BYTES);
            memcpy(b.data(), s.data(), s.size());
            return decaf_255_point_from_hash_uniform(p,b);
        } else {
            return decaf_255_point_from_hash_uniform(p,s);
        }
    }
    
    /**
     * @brief Encode to string.  The identity encodes to the all-zero string.
     */
    inline EXPLICIT_CON operator SecureBuffer() const NOEXCEPT {
        SecureBuffer buffer(SER_BYTES);
        decaf_255_point_encode(buffer, p);
        return buffer;
    }
   
   /**
    * @brief Encode to a C buffer.  The identity encodes to all zeros.
    */
    inline void encode(unsigned char buffer[SER_BYTES]) const NOEXCEPT{
        decaf_255_point_encode(buffer, p);
    }
    
    /** @brief Point add. */
    inline Point  operator+ (const Point &q)  const NOEXCEPT { Point r((NOINIT())); decaf_255_point_add(r.p,p,q.p); return r; }
    
    /** @brief Point add. */
    inline Point &operator+=(const Point &q)        NOEXCEPT { decaf_255_point_add(p,p,q.p); return *this; }
    
    /** @brief Point subtract. */
    inline Point  operator- (const Point &q)  const NOEXCEPT { Point r((NOINIT())); decaf_255_point_sub(r.p,p,q.p); return r; }
    
    /** @brief Point subtract. */
    inline Point &operator-=(const Point &q)        NOEXCEPT { decaf_255_point_sub(p,p,q.p); return *this; }
    
    /** @brief Point negate. */
    inline Point  operator- ()                const NOEXCEPT { Point r((NOINIT())); decaf_255_point_negate(r.p,p); return r; }
    
    /** @brief Double the point out of place. */
    inline Point  times_two ()                const NOEXCEPT { Point r((NOINIT())); decaf_255_point_double(r.p,p); return r; }
    
    /** @brief Double the point in place. */
    inline Point &double_in_place()                NOEXCEPT { decaf_255_point_double(p,p); return *this; }
    
    /** @brief Constant-time compare. */
    inline bool  operator!=(const Point &q)  const NOEXCEPT { return ! decaf_255_point_eq(p,q.p); }

    /** @brief Constant-time compare. */
    inline bool  operator==(const Point &q)  const NOEXCEPT { return !!decaf_255_point_eq(p,q.p); }
    
    /** @brief Scalar multiply. */
    inline Point  operator* (const Scalar &s) const NOEXCEPT { Point r((NOINIT())); decaf_255_point_scalarmul(r.p,p,s.s); return r; }
    
    /** @brief Scalar multiply in place. */
    inline Point &operator*=(const Scalar &s)       NOEXCEPT { decaf_255_point_scalarmul(p,p,s.s); return *this; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point  operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point &operator/=(const Scalar &s)       NOEXCEPT { return (*this) *= s.inverse(); }
    
    /** @brief Validate / sanity check */
    inline bool validate() const NOEXCEPT { return !!decaf_255_point_valid(p); }
    
    /** @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster. */
    static inline Point double_scalarmul (
        const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
    ) NOEXCEPT {
        Point p((NOINIT())); decaf_255_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /**
     * @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster.
     * For those who like their scalars before the point.
     */
    static inline Point double_scalarmul (
        const Scalar &qs, const Point &q, const Scalar &rs, const Point &r
    ) NOEXCEPT {
        Point p((NOINIT())); decaf_255_point_double_scalarmul(p.p,q.p,qs.s,r.p,rs.s); return p;
    }
    
    /**
     * @brief Double-scalar multiply: this point by the first scalar and base by the second scalar.
     * @warning This function takes variable time, and may leak the scalars (or points, but currently
     * it doesn't).
     */
    inline Point non_secret_combo_with_base(const Scalar &s, const Scalar &s_base) NOEXCEPT {
        Point r((NOINIT())); decaf_255_base_double_scalarmul_non_secret(r.p,s_base.s,p,s.s); return r;
    }
    
    inline Point& debugging_torque_in_place() {
        decaf_255_point_debugging_torque(p,p);
        return *this;
    }
    
    inline bool invert_elligator (
        Buffer &buf, uint16_t hint
    ) const NOEXCEPT {
        unsigned char buf2[2*HASH_BYTES];
        memset(buf2,0,sizeof(buf2));
        memcpy(buf2,buf,(buf.size() > 2*HASH_BYTES) ? 2*HASH_BYTES : buf.size());
        decaf_bool_t ret;
        if (buf.size() > HASH_BYTES) {
            ret = decaf_255_invert_elligator_uniform(buf2, p, hint);
        } else {
            ret = decaf_255_invert_elligator_nonuniform(buf2, p, hint);
        }
        if (buf.size() < HASH_BYTES) {
            ret &= decaf_memeq(&buf2[buf.size()], &buf2[HASH_BYTES], HASH_BYTES - buf.size());
        }
        memcpy(buf,buf2,(buf.size() < HASH_BYTES) ? buf.size() : HASH_BYTES);
        decaf_bzero(buf2,sizeof(buf2));
        return !!ret;
    }
    
    /** @brief Steganographically encode this */
    inline SecureBuffer steg_encode(SpongeRng &rng) const NOEXCEPT;
    
    /** @brief Return the base point */
    static inline const Point base() NOEXCEPT { return Point(decaf_255_point_base); }
    
    /** @brief Return the identity point */
    static inline const Point identity() NOEXCEPT { return Point(decaf_255_point_identity); }
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
        decaf_255_precomputed_s *mine;
        const decaf_255_precomputed_s *yours;
    } ours;
    bool isMine;
    
    inline void clear() NOEXCEPT {
        if (isMine) {
            decaf_255_precomputed_destroy(ours.mine);
            free(ours.mine);
            ours.yours = decaf_255_precomputed_base;
            isMine = false;
        }
    }
    inline void alloc() throw(std::bad_alloc) {
        if (isMine) return;
        int ret = posix_memalign((void**)&ours.mine, alignof_decaf_255_precomputed_s,sizeof_decaf_255_precomputed_s);
        if (ret || !ours.mine) {
            isMine = false;
            throw std::bad_alloc();
        }
        isMine = true;
    }
    inline const decaf_255_precomputed_s *get() const NOEXCEPT { return isMine ? ours.mine : ours.yours; }
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
        const decaf_255_precomputed_s &yours = *decaf_255_precomputed_base
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
            memcpy(ours.mine,it.ours.mine,sizeof_decaf_255_precomputed_s);
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
        decaf_255_precompute(ours.mine,it.p);
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
        it.ours.yours = decaf_255_precomputed_base;
        return *this;
    }
    inline Precomputed(Precomputed &&it) NOEXCEPT : isMine(false) { *this = it; }
#endif
    
    /** @brief Fixed base scalarmul. */
    inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; decaf_255_precomputed_scalarmul(r.p,get(),s.s); return r; }
    
    /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
    inline Point operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
    /** @brief Return the table for the base point. */
    static inline const Precomputed base() NOEXCEPT { return Precomputed(*decaf_255_precomputed_base); }
};

}; /* struct Decaf255 */

#undef NOEXCEPT
#undef EXPLICIT_CON
#undef GET_DATA
} /* namespace decaf */

#endif /* __DECAF_255_HXX__ */
