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

typedef uint32_t GroupId;

static const GroupId Ed448Goldilocks = 448;

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


template<GroupId group> struct WrappedTypes;

/**
 * @brief Group with prime order.
 * @todo Move declarations of functions up here?
 */
template<GroupId group = Ed448Goldilocks> struct EcGroup {
    /** @cond internal */
    class Point;
    class Precomputed;
    /** @endcond */

   /**
    * @brief A scalar modulo the curve order.
    * Supports the usual arithmetic operations, all in constant time.
    */
    class Scalar {
    private:
        /** @cond internal */
        /** @brief Wrapped C object */
        friend class Point;
        friend class Precomputed;
        typedef typename WrappedTypes<group>::Scalar Wrapped;
        static inline const Wrapped &ZERO() NOEXCEPT;
        static inline const Wrapped &ONE() NOEXCEPT;
        static inline void add3(Wrapped&, const Wrapped&, const Wrapped&) NOEXCEPT;
        static inline void setu(Wrapped&, decaf_word_t) NOEXCEPT;
        static inline void sub3(Wrapped&, const Wrapped&, const Wrapped&) NOEXCEPT;
        static inline void mul3(Wrapped&, const Wrapped&, const Wrapped&) NOEXCEPT;
        static inline void dl3(Wrapped&, const unsigned char *buffer, size_t size) NOEXCEPT;
        static inline decaf_word_t eq2(const Wrapped&, const Wrapped&) NOEXCEPT;
        static inline void assign2(Wrapped&, const Wrapped&) NOEXCEPT;
        static inline void inv2(Wrapped&, const Wrapped&) NOEXCEPT;
        /** @endcond */
        
    public:
        /** @brief Size of a serialized element */
        static const size_t SER_BYTES = WrappedTypes<group>::SCALAR_SER_BYTES;
        
        /** @brief access to the Wrapped scalar object */
        Wrapped s;
    
        /** @brief Don't initialize. */
        inline Scalar(const NOINIT &) {}
    
        /** @brief Set to an unsigned word */
        inline Scalar(const decaf_word_t w = 0) NOEXCEPT { *this = w; }

        /** @brief Set to a signed word */
        inline Scalar(const int w) NOEXCEPT { *this = w; } 
    
        /** @brief Construct from RNG */
        inline explicit Scalar(SpongeRng &rng) NOEXCEPT;
    
        /** @brief Construct from decaf_scalar_t object. */
        inline Scalar(const Wrapped &x) NOEXCEPT {  *this = x; } 
    
        /** @brief Copy constructor. */
        inline Scalar(const Scalar &x) NOEXCEPT {  *this = x; }
    
        /** @brief Construct from arbitrary-length little-endian byte sequence. */
        inline Scalar(const Block &buffer) NOEXCEPT { *this = buffer; }
    
        /** Destructor securely erases the scalar. */
        inline ~Scalar() NOEXCEPT;
    
        /** @brief Assign from arbitrary-length little-endian byte sequence in a Block. */
        inline Scalar &operator=(const Block &bl) NOEXCEPT { dl3(s, bl, bl.size()); return *this; }
    
        /** @brief Assignment. */
        inline Scalar &operator=(const Scalar &t) NOEXCEPT { assign2(s, t.s); return *this; }
    
        /** @brief Assignment. */
        inline Scalar &operator=(decaf_word_t w) NOEXCEPT { setu(s, w); return *this; }
    
        /** @brief Assignment. */
        inline Scalar &operator=(int w) NOEXCEPT {
            Scalar t(-(decaf_word_t)INT_MIN);
            setu(s,(decaf_word_t)w - (decaf_word_t)INT_MIN);
            *this -= t;
            return *this;
        }
    
        /**
         * @brief Decode from correct-length little-endian byte sequence.
         * @return DECAF_FAILURE if the scalar is greater than or equal to the group order q.
         */
        static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
            Scalar &sc, const unsigned char buffer[SER_BYTES]
        ) NOEXCEPT;
    
        /** @brief Decode from correct-length little-endian byte sequence in C++ string. */
        static inline decaf_bool_t __attribute__((warn_unused_result)) decode (
            Scalar &sc, const Block &buffer
        ) NOEXCEPT {
            if (buffer.size() != SER_BYTES) return DECAF_FAILURE;
            return decode(sc.s,(const unsigned char *)buffer);
        }
    
        /** @brief Encode to fixed-length buffer */
        inline void encode(unsigned char buffer[SER_BYTES]) const NOEXCEPT;
    
        /** @brief Encode to fixed-length string */
        inline EXPLICIT_CON operator SecureBuffer() const NOEXCEPT {
            SecureBuffer buf(SER_BYTES); encode((unsigned char *)buf,s); return buf;
        }
    
    public:
        /** Add. */
        inline Scalar  operator+ (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); add3(r.s,s,q.s); return r; }
    
        /** Add to this. */
        inline Scalar &operator+=(const Scalar &q)       NOEXCEPT { add3(s,s,q.s); return *this; }
    
        /** Subtract. */
        inline Scalar  operator- (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); sub3(r.s,s,q.s); return r; }
    
        /** Subtract from this. */
        inline Scalar &operator-=(const Scalar &q)       NOEXCEPT { sub3(s,s,q.s); return *this; }
    
        /** Multiply */
        inline Scalar  operator* (const Scalar &q) const NOEXCEPT { Scalar r((NOINIT())); mul3(r.s,s,q.s); return r; }
    
        /** Multiply into this. */
        inline Scalar &operator*=(const Scalar &q)       NOEXCEPT { mul3(s,s,q.s); return *this; }
    
        /** Negate */
        inline Scalar operator- ()                const NOEXCEPT { Scalar r((NOINIT())); sub3(r.s,ZERO(),s); return r; }
    
        /** @brief Invert with Fermat's Little Theorem (slow!).  If *this == 0, return 0. */
        inline Scalar inverse() const NOEXCEPT { Scalar q((NOINIT())); inv2(q.s,s); return q; }
    
        /** @brief Divide by inverting q. If q == 0, return 0.  */
        inline Scalar  operator/ (const Scalar &q) const NOEXCEPT { return *this * q.inverse(); }
    
        /** @brief Divide by inverting q. If q == 0, return 0.  */
        inline Scalar &operator/=(const Scalar &q)       NOEXCEPT { return *this *= q.inverse(); }
    
        /** @brief Compare in constant time */
        inline bool    operator==(const Scalar &q) const NOEXCEPT { return !!eq2(s,q.s); }
    
        /** @brief Compare in constant time */
        inline bool    operator!=(const Scalar &q) const NOEXCEPT { return !(*this == q); }
    
        /** @brief Scalarmul with scalar on left. */
        inline Point operator* (const Point &q) const NOEXCEPT { return q * (*this); }
    
        /** @brief Scalarmul-precomputed with scalar on left. */
        inline Point operator* (const Precomputed &q) const NOEXCEPT { return q * (*this); }
    
        /** @brief Direct scalar multiplication. */
        inline SecureBuffer direct_scalarmul(
            const Block &in,
            decaf_bool_t allow_identity=DECAF_FALSE,
            decaf_bool_t short_circuit=DECAF_TRUE    
        ) const throw(CryptoException);
    };
    
    
   /**
    * @brief Element of prime-order group.
    */
   class Point {
   private:
       /** @cond internal */
       typedef typename WrappedTypes<group>::Point Wrapped;
       friend class Scalar;
       friend class Precomputed;
       static inline void add3(Wrapped&, const Wrapped&, const Wrapped&) NOEXCEPT;
       static inline void sub3(Wrapped&, const Wrapped&, const Wrapped&) NOEXCEPT;
       static inline void dbl2(Wrapped&, const Wrapped&) NOEXCEPT;
       static inline void neg2(Wrapped&, const Wrapped&) NOEXCEPT;
       static inline decaf_word_t eq2(const Wrapped&, const Wrapped&) NOEXCEPT;
       static inline void assign2(Wrapped&, const Wrapped&) NOEXCEPT;
       static inline void sm3(Wrapped&, const Wrapped&, const typename Scalar::Wrapped&) NOEXCEPT;
       static inline void dsm5(
           Wrapped&,
           const Wrapped&, const typename Scalar::Wrapped&,
           const Wrapped&, const typename Scalar::Wrapped&
       ) NOEXCEPT;
       static inline void dsmns(
           Wrapped&,
           const typename Scalar::Wrapped&,
           const Wrapped&, const typename Scalar::Wrapped&
       ) NOEXCEPT;
       /** @endcond */
       
   public:
       /** @brief Size of a serialized element */
       static const size_t SER_BYTES = WrappedTypes<group>::POINT_SER_BYTES;
    
       /** @brief Bytes required for hash */
       static const size_t HASH_BYTES = WrappedTypes<group>::POINT_HASH_BYTES;
    
       /** The c-level object. */
       Wrapped p;
    
       /** @brief Don't initialize. */
       inline Point(const NOINIT &) {}
    
       /** @brief Constructor sets to identity by default. */
       inline Point(const decaf_448_point_s &q) { *this = q; }
    
       /** @brief Copy constructor. */
       inline Point(const Point &q = identity()) { *this = q; }
    
       /** @brief Assignment. */
       inline Point& operator=(const Point &q) NOEXCEPT { assign2(p,q.p); return *this; }
    
       /** @brief Assignment from Wrapped. */
       inline Point& operator=(const Wrapped &q) NOEXCEPT { assign2(p,q); return *this; }
    
       /** @brief Destructor securely erases the point. */
       inline ~Point() NOEXCEPT;
    
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
       ) NOEXCEPT;
    
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
           return decode(p,buffer.data(),allow_identity);
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
       inline void set_to_hash( const Block &s ) NOEXCEPT;
   
      /**
       * @brief Encode to a C buffer.  The identity encodes to all zeros.
       */
       inline void encode(unsigned char buffer[/*SER_BYTES*/]) const NOEXCEPT{
           decaf_448_point_encode(buffer, p);
       }
    
       /**
        * @brief Encode to string.  The identity encodes to the all-zero string.
        */
       inline operator SecureBuffer() const NOEXCEPT {
           SecureBuffer buffer(SER_BYTES); encode(buffer.data()); return buffer;
       }
    
       /** @brief Point add. */
       inline Point  operator+ (const Point &q)  const NOEXCEPT { Point r((NOINIT())); add3(r.p,p,q.p); return r; }
    
       /** @brief Point add. */
       inline Point &operator+=(const Point &q)        NOEXCEPT { add3(p,p,q.p); return *this; }
    
       /** @brief Point subtract. */
       inline Point  operator- (const Point &q)  const NOEXCEPT { Point r((NOINIT())); sub3(r.p,p,q.p); return r; }
    
       /** @brief Point subtract. */
       inline Point &operator-=(const Point &q)        NOEXCEPT { sub3(p,p,q.p); return *this; }
    
       /** @brief Point negate. */
       inline Point  operator- ()                const NOEXCEPT { Point r((NOINIT())); neg2(r.p,p); return r; }
    
       /** @brief Double the point out of place. */
       inline Point  times_two ()                const NOEXCEPT { Point r((NOINIT())); dbl2(r.p,p); return r; }
    
       /** @brief Double the point in place. */
       inline Point &double_in_place()                NOEXCEPT { dbl2(p,p); return *this; }
    
       /** @brief Constant-time compare. */
       inline bool  operator!=(const Point &q)  const NOEXCEPT { return !eq2(p,q.p); }

       /** @brief Constant-time compare. */
       inline bool  operator==(const Point &q)  const NOEXCEPT { return !!eq2(p,q.p); }
    
       /** @brief Scalar multiply. */
       inline Point  operator* (const Scalar &s) const NOEXCEPT { Point r((NOINIT())); sm3(r.p,p,s.s); return r; }
    
       /** @brief Scalar multiply in place. */
       inline Point &operator*=(const Scalar &s)       NOEXCEPT { sm3(p,p,s.s); return *this; }
    
       /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
       inline Point  operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
       /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
       inline Point &operator/=(const Scalar &s)       NOEXCEPT { return (*this) *= s.inverse(); }
    
       /** @brief Validate / sanity check */
       inline bool validate() const NOEXCEPT;
    
       /** @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster. */
       static inline Point double_scalarmul (
           const Point &q, const Scalar &qs, const Point &r, const Scalar &rs
       ) NOEXCEPT {
           Point p((NOINIT())); dsm5(p.p,q.p,qs.s,r.p,rs.s); return p;
       }
    
       /**
        * @brief Double-scalar multiply, equivalent to q*qs + r*rs but faster.
        * For those who like their scalars before the point.
        */
       static inline Point double_scalarmul (
           const Scalar &qs, const Point &q, const Scalar &rs, const Point &r
       ) NOEXCEPT {
           Point p((NOINIT())); dsm5(p.p,q.p,qs.s,r.p,rs.s); return p;
       }
    
       /**
        * @brief Double-scalar multiply: this point by the first scalar and base by the second scalar.
        * @warning This function takes variable time, and may leak the scalars (or points, but currently
        * it doesn't).
        */
       inline Point non_secret_combo_with_base(const Scalar &s, const Scalar &s_base) {
           Point r((NOINIT())); dsmns(r.p,s_base.s,p,s.s); return r;
       }
    
       /** @brief Return the base point */
       static inline Point base() NOEXCEPT;
    
       /** @brief Return the identity point */
       static inline Point identity() NOEXCEPT;
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
      static inline size_t sizeof_this() NOEXCEPT;
      static inline size_t alignof_this() NOEXCEPT;
      typedef typename WrappedTypes<group>::Precomputed Wrapped;
      static inline const Wrapped *GENERATOR() NOEXCEPT;
      static inline void destroy(Wrapped*) NOEXCEPT;
      static inline void precompute(Wrapped*, const typename Point::Wrapped&) NOEXCEPT;
      static inline void psmul3(typename Point::Wrapped&, const Wrapped*, const typename Scalar::Wrapped&) NOEXCEPT;
      
      union {
          Wrapped *mine;
          const Wrapped *yours;
      } ours;
      bool isMine;
    
      inline void clear() NOEXCEPT {
          if (isMine) {
              destroy(ours.mine);
              free(ours.mine);
              ours.yours = GENERATOR();
              isMine = false;
          }
      }
      inline void alloc() throw(std::bad_alloc) {
          if (isMine) return;
          int ret = posix_memalign((void**)&ours.mine, alignof_this(),sizeof_this());
          if (ret || !ours.mine) {
              isMine = false;
              throw std::bad_alloc();
          }
          isMine = true;
      }
      inline const Wrapped *get() const NOEXCEPT { return isMine ? ours.mine : ours.yours; }
      /** @endcond */
  public:
      /** Destructor securely erases the memory. */
      inline ~Precomputed() NOEXCEPT { clear(); }
    
      /**
       * @brief Initialize from Wrapped type, declared as a reference to prevent
       * it from being called with 0, thereby breaking override.
       *
       * The Wrapped object must remain valid throughout the lifetime of this one.
       *
       * By default, initializes to the table for the base point.
       *
       * @warning The empty initializer makes this equal to base, unlike the empty
       * initializer for points which makes this equal to the identity.
       */ 
      inline Precomputed(
          const Wrapped &yours = *GENERATOR()
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
              memcpy(ours.mine,it.ours.mine,sizeof_this());
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
          alloc(); precompute(ours.mine,it.p); return *this;
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
          it.ours.yours = base;
          return *this;
      }
      inline Precomputed(Precomputed &&it) NOEXCEPT : isMine(false) { *this = it; }
  #endif
    
      /** @brief Fixed base scalarmul. */
      inline Point operator* (const Scalar &s) const NOEXCEPT { Point r; psmul3(r.p,get(),s.s); return r; }
    
      /** @brief Multiply by s.inverse().  If s=0, maps to the identity. */
      inline Point operator/ (const Scalar &s) const NOEXCEPT { return (*this) * s.inverse(); }
    
      /** @brief Return the table for the base point. */
      static inline const Precomputed base() NOEXCEPT { return Precomputed(*GENERATOR()); }
  };
};

/***************************************************************/
/*                        Instantiation                        */
/***************************************************************/


/** @cond internal */
template<> struct WrappedTypes<Ed448Goldilocks> {
    typedef decaf_448_point_s Point;
    typedef decaf_448_scalar_s Scalar;
    typedef decaf_448_precomputed_s Precomputed;
    static const size_t SCALAR_SER_BYTES = 56;
    static const size_t POINT_SER_BYTES = 56;
    static const size_t POINT_HASH_BYTES = 56;
};

/* Scalar instantiation */

template<> inline void EcGroup<Ed448Goldilocks>::Scalar::add3(
    Wrapped& a, const Wrapped& b, const Wrapped& c
) NOEXCEPT { decaf_448_scalar_add(&a,&b,&c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::sub3(
    Wrapped& a, const Wrapped& b, const Wrapped& c
) NOEXCEPT { decaf_448_scalar_sub(&a,&b,&c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::mul3(
    Wrapped& a, const Wrapped& b, const Wrapped& c
) NOEXCEPT { decaf_448_scalar_mul(&a,&b,&c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::dl3(
    Wrapped& a, const unsigned char *b, size_t c
) NOEXCEPT { decaf_448_scalar_decode_long(&a,b,c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::assign2(
    Wrapped& a, const Wrapped& b
) NOEXCEPT { decaf_448_scalar_copy(&a,&b); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::setu(
    Wrapped& a, decaf_word_t w
) NOEXCEPT { decaf_448_scalar_set(&a,w); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Scalar::inv2(
    Wrapped& a, const Wrapped& b
) NOEXCEPT { decaf_448_scalar_invert(&a,&b); }
    
template<> inline decaf_word_t EcGroup<Ed448Goldilocks>::Scalar::eq2(
    const Wrapped& a, const Wrapped& b
) NOEXCEPT { return decaf_448_scalar_eq(&a,&b); }

    /* CLASSY */
template<> inline SecureBuffer EcGroup<Ed448Goldilocks>::Scalar::direct_scalarmul(
    const Block &in, decaf_bool_t allow_identity, decaf_bool_t short_circuit
) const throw(CryptoException) {
    SecureBuffer out(SER_BYTES);
    if (!decaf_448_direct_scalarmul(out, in.data(), &s, allow_identity, short_circuit))
        throw CryptoException();
    return out;
}

template<> inline void EcGroup<Ed448Goldilocks>::Scalar::encode(
    unsigned char buffer[SER_BYTES]
) const NOEXCEPT {
    decaf_448_scalar_encode(buffer,&s);
}

template<> inline decaf_bool_t __attribute__((warn_unused_result))
EcGroup<Ed448Goldilocks>::Scalar::decode (
    Scalar &s, const unsigned char buffer[SER_BYTES]
) NOEXCEPT {
    return decaf_448_scalar_decode(&s.s,buffer);
}

    /* CLASSY */
template<> inline EcGroup<Ed448Goldilocks>::Scalar::~Scalar() NOEXCEPT { decaf_448_scalar_destroy(&s); }
template<> inline const EcGroup<Ed448Goldilocks>::Scalar::Wrapped&
    EcGroup<Ed448Goldilocks>::Scalar::ZERO() NOEXCEPT { return decaf_448_scalar_zero[0]; }
template<> inline const EcGroup<Ed448Goldilocks>::Scalar::Wrapped&
    EcGroup<Ed448Goldilocks>::Scalar::ONE() NOEXCEPT { return decaf_448_scalar_one[0]; }
    
    

/* Point instantiation */

    /* CLASSY */
template<> inline EcGroup<Ed448Goldilocks>::Point::~Point() NOEXCEPT { decaf_448_point_destroy(&p); }

template<> inline void EcGroup<Ed448Goldilocks>::Point::add3(
    Wrapped& a, const Wrapped& b, const Wrapped& c
) NOEXCEPT { decaf_448_point_add(&a,&b,&c); }

template<> inline void EcGroup<Ed448Goldilocks>::Point::sub3(
    Wrapped& a, const Wrapped& b, const Wrapped& c
) NOEXCEPT { decaf_448_point_sub(&a,&b,&c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Point::assign2(
    Wrapped& a, const Wrapped& b
) NOEXCEPT { decaf_448_point_copy(&a,&b); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Point::dbl2(
    Wrapped& a, const Wrapped& b
) NOEXCEPT { decaf_448_point_double(&a,&b); }
    
template<> inline decaf_word_t EcGroup<Ed448Goldilocks>::Point::eq2(
    const Wrapped& a, const Wrapped& b
) NOEXCEPT { return decaf_448_point_eq(&a,&b); }

    /* CLASSY */
template<> inline bool EcGroup<Ed448Goldilocks>::Point::validate() const NOEXCEPT { return !!decaf_448_point_valid(&p); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Point::sm3(
    Wrapped& a, const Wrapped& b, const Scalar::Wrapped &c
) NOEXCEPT { decaf_448_point_scalarmul(&a,&b,&c); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Point::dsm5(
    Wrapped& a, const Wrapped& b, const Scalar::Wrapped &c, const Wrapped& d, const Scalar::Wrapped &e
) NOEXCEPT { decaf_448_point_double_scalarmul(&a,&b,&c,&d,&e); }
    
template<> inline void EcGroup<Ed448Goldilocks>::Point::dsmns(
    Wrapped& a, const Scalar::Wrapped &b, const Wrapped& c, const Scalar::Wrapped &d
) NOEXCEPT { decaf_448_base_double_scalarmul_non_secret(&a,&b,&c,&d); }

    /* CLASSY */
template<> inline decaf_bool_t __attribute__((warn_unused_result))
EcGroup<Ed448Goldilocks>::Point::decode (
    Point &p, const unsigned char buffer[SER_BYTES], decaf_bool_t allow_identity
) NOEXCEPT {
    return decaf_448_point_decode(&p.p,buffer,allow_identity);
}
    /* CLASSY */
template<> inline void EcGroup<Ed448Goldilocks>::Point::set_to_hash( const Block &s ) NOEXCEPT {
    if (s.size() < HASH_BYTES) {
        SecureBuffer b(HASH_BYTES);
        memcpy(b.data(), s.data(), s.size());
        decaf_448_point_from_hash_nonuniform(&p,b);
    } else if (s.size() == HASH_BYTES) {
        decaf_448_point_from_hash_nonuniform(&p,s);
    } else if (s.size() < 2*HASH_BYTES) {
        SecureBuffer b(2*HASH_BYTES);
        memcpy(b.data(), s.data(), s.size());
        decaf_448_point_from_hash_uniform(&p,b);
    } else {
        decaf_448_point_from_hash_uniform(&p,s);
    }
}

    /* CLASSY */
template<> inline void EcGroup<Ed448Goldilocks>::Point::encode(
    unsigned char buffer[SER_BYTES]
) const NOEXCEPT {
    decaf_448_point_encode(buffer,&p);
}

template<> inline EcGroup<Ed448Goldilocks>::Point
    EcGroup<Ed448Goldilocks>::Point::identity() NOEXCEPT { return decaf_448_point_identity[0]; }
    
template<> inline EcGroup<Ed448Goldilocks>::Point
    EcGroup<Ed448Goldilocks>::Point::base() NOEXCEPT { return decaf_448_point_base[0]; }

/* Precomputed instantiation */
template<> inline void EcGroup<Ed448Goldilocks>::Precomputed::destroy(
    Wrapped *doomed
) NOEXCEPT {
    decaf_448_precomputed_destroy(doomed);
}

/* Precomputed instantiation */
template<> inline void EcGroup<Ed448Goldilocks>::Precomputed::precompute(
    Wrapped *pre, const Point::Wrapped &point
) NOEXCEPT {
    decaf_448_precompute(pre,&point);
}

template<> inline void EcGroup<Ed448Goldilocks>::Precomputed::psmul3(
    Point::Wrapped &out, const Wrapped *pre, const Scalar::Wrapped &sc
) NOEXCEPT {
    decaf_448_precomputed_scalarmul(&out,pre,&sc);
}

template<> inline size_t EcGroup<Ed448Goldilocks>::Precomputed:: sizeof_this() NOEXCEPT
    { return sizeof_decaf_448_precomputed_s; }
template<> inline size_t EcGroup<Ed448Goldilocks>::Precomputed::alignof_this() NOEXCEPT
    { return alignof_decaf_448_precomputed_s; }
template<> inline const EcGroup<Ed448Goldilocks>::Precomputed::Wrapped*
    EcGroup<Ed448Goldilocks>::Precomputed::GENERATOR() NOEXCEPT { return decaf_448_precomputed_base; }

/** @endcond */

#undef NOEXCEPT
#undef EXPLICIT_CON
#undef GET_DATA
} /* namespace decaf */

#endif /* __DECAF_448_HXX__ */
