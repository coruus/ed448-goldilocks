/**
 * @file shake.hxx
 * @copyright
 *   Based on CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances, C++ wrapper.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#ifndef __SHAKE_HXX__
#define __SHAKE_HXX__

#include "shake.h"
#include <string>
#include <sys/types.h>

/** @cond internal */
#if __cplusplus >= 201103L
#define DELETE = delete
#define NOEXCEPT noexcept
#define EXPLICIT_CON explicit
#define GET_DATA(str) ((const unsigned char *)&(str)[0])
#else
#define DELETE
#define NOEXCEPT throw()
#define EXPLICIT_CON
#define GET_DATA(str) ((const unsigned char *)((str).data()))
#endif
/** @endcond */

namespace decaf {

/** A Keccak sponge internal class */
class KeccakSponge {
protected:
    /** The C-wrapper sponge state */
    keccak_sponge_t sp;

    /** Initialize from parameters */
    inline KeccakSponge(const struct kparams_s *params) NOEXCEPT { sponge_init(sp, params); }
    
    /** No initialization */
    inline KeccakSponge(const NOINIT &) NOEXCEPT { }

public:
    /** Destructor zeroizes state */
    inline ~KeccakSponge() NOEXCEPT { sponge_destroy(sp); }
};

/**
 * Hash function derived from Keccak
 * @todo throw exceptions when hash is misused.
 */
class KeccakHash : public KeccakSponge {
protected:
    /** Initialize from parameters */
    inline KeccakHash(const kparams_s *params) NOEXCEPT : KeccakSponge(params) {}
    
public:
    /** Add more data to running hash */
    inline void update(const uint8_t *__restrict__ in, size_t len) { sha3_update(sp,in,len); }

    /** Add more data to running hash, C++ version. */
    inline void update(const Block &s) { sha3_update(sp,s.data(),s.size()); }
    
    /** Add more data, stream version. */
    inline KeccakHash &operator<<(const Block &s) { update(s); return *this; }
    
    /** Same as <<. */
    inline KeccakHash &operator+=(const Block &s) { return *this << s; }
    
    /**
     * @brief Output bytes from the sponge.
     * @todo make this throw exceptions.
     */
    inline void output(TmpBuffer b) { sha3_output(sp,b.data(),b.size()); }
    
    /**
     * @brief Output bytes from the sponge.
     * @todo make this throw exceptions.
     */
    inline void output(Buffer &b) { sha3_output(sp,b.data(),b.size()); }
    
    /** @brief Output bytes from the sponge. */
    inline SecureBuffer output(size_t len) {
        SecureBuffer buffer(len);
        sha3_output(sp,buffer,len);
        return buffer;
    }
    
    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const NOEXCEPT {
        return sponge_default_output_bytes(sp);
    }
    
    /** Output the default number of bytes. */
    inline SecureBuffer output() {
        return output(default_output_size());
    }
};

/** Fixed-output-length SHA3 */
template<int bits> class SHA3 : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    const struct kparams_s *get_params();
public:
    /** Initializer */
    inline SHA3() NOEXCEPT : KeccakHash(get_params()) {}

    /** Reset the hash to the empty string */
    inline void reset() NOEXCEPT { sponge_init(sp, get_params()); }
};

/** Variable-output-length SHAKE */
template<int bits>
class SHAKE : public KeccakHash {
private:
    /** Get the parameter template block for this hash */
    const struct kparams_s *get_params();
public:
    /** Initializer */
    inline SHAKE() NOEXCEPT : KeccakHash(get_params()) {}

    /** Reset the hash to the empty string */
    inline void reset() NOEXCEPT { sponge_init(sp, get_params()); }
};

/** @cond internal */
template<> const struct kparams_s *SHAKE<128>::get_params() { return &SHAKE128_params_s; }
template<> const struct kparams_s *SHAKE<256>::get_params() { return &SHAKE256_params_s; }
template<> const struct kparams_s *SHA3<224>::get_params() { return &SHA3_224_params_s; }
template<> const struct kparams_s *SHA3<256>::get_params() { return &SHA3_256_params_s; }
template<> const struct kparams_s *SHA3<384>::get_params() { return &SHA3_384_params_s; }
template<> const struct kparams_s *SHA3<512>::get_params() { return &SHA3_512_params_s; }
/** @endcond */

/** @brief An exception for misused protocol, eg encrypt with no key. */
class ProtocolException : public std::exception {
public:
    /** @return "ProtocolException" */
    virtual const char * what() const NOEXCEPT { return "ProtocolException"; }
};
    
/** Sponge-based random-number generator */
class SpongeRng : private KeccakSponge {
public:
    class RngException : public std::exception {
    private:
        const char *const what_;
    public:
        const int err_code;
        const char *what() const NOEXCEPT { return what_; }
        RngException(int err_code, const char *what_) NOEXCEPT : what_(what_), err_code(err_code) {}
    };
    
    /** Initialize, deterministically by default, from block */
    inline SpongeRng( const Block &in, bool deterministic = true )
    : KeccakSponge((NOINIT())) {
        spongerng_init_from_buffer(sp,in.data(),in.size(),deterministic);
    }
    
    /** Initialize, non-deterministically by default, from C/C++ filename */
    inline SpongeRng( const std::string &in = "/dev/urandom", size_t len = 32, bool deterministic = false )
        throw(RngException)
    : KeccakSponge((NOINIT())) {
        int ret = spongerng_init_from_file(sp,in.c_str(),len,deterministic);
        if (ret) {
            throw RngException(ret, "Couldn't load from file");
        }
    }
    
    /** Read data to a buffer. */
    inline void read(Buffer &buffer) { spongerng_next(sp,buffer.data(),buffer.size()); }
    
    /** Read data to a buffer. */
    inline void read(TmpBuffer buffer) { read((Buffer &)buffer); }
    
    /** Read data to a C++ string 
     * @warning TODO Future versions of this function may throw RngException if a
     * nondeterministic RNG fails a reseed.
     */
    inline SecureBuffer read(size_t length) throw(std::bad_alloc) {
        SecureBuffer out(length); read(out); return out;
    }
    
private:
    SpongeRng(const SpongeRng &) DELETE;
    SpongeRng &operator=(const SpongeRng &) DELETE;
};

/**@cond internal*/
/* FIXME: multiple sizes */
EcGroup<448>::Scalar::Scalar(SpongeRng &rng) {
    *this = rng.read(SER_BYTES);
}

EcGroup<448>::Point::Point(SpongeRng &rng, bool uniform) {
    SecureBuffer buffer((uniform ? 2 : 1) * HASH_BYTES);
    rng.read(buffer);
    if (uniform) {
        decaf_448_point_from_hash_uniform(p,buffer);
    } else {
        decaf_448_point_from_hash_nonuniform(p,buffer);
    }
}
/**@endcond*/

class Strobe : private KeccakSponge {
public:
    /* TODO: pull out parameters */
    
    /** Am I a server or a client? */
    enum client_or_server { SERVER, CLIENT };
    
    inline Strobe (
        client_or_server whoami,
        const kparams_s &params = STROBE_256
    ) NOEXCEPT : KeccakSponge(NOINIT()) {
        strobe_init(sp, &params, whoami == CLIENT);
    }

    inline void key (
        const Block &data, bool more = false
    ) throw(ProtocolException) {
        if (!strobe_key(sp, data, data.size(), more)) throw ProtocolException();
    }

    inline void nonce(const Block &data, bool more = false
    ) throw(ProtocolException) {
        if (!strobe_nonce(sp, data, data.size(), more)) throw ProtocolException();
    }

    inline void send_plaintext(const Block &data, bool more = false
    ) throw(ProtocolException) {
        if (!strobe_plaintext(sp, data, data.size(), true, more))
            throw(ProtocolException());
    }

    inline void recv_plaintext(const Block &data, bool more = false
    ) throw(ProtocolException) {
        if (!strobe_plaintext(sp, data, data.size(), false, more))
            throw(ProtocolException());
    }

    inline void ad(const Block &data, bool more = false
    ) throw(ProtocolException) {
        if (!strobe_ad(sp, data, data.size(), more))
            throw(ProtocolException());
    }
    
    inline void encrypt_no_auth(
        Buffer &out, const Block &data, bool more = false
    ) throw(LengthException,ProtocolException) {
        if (out.size() != data.size()) throw LengthException();
        if (!strobe_encrypt(sp, out, data, data.size(), more)) throw(ProtocolException());
    }
    
    inline void encrypt_no_auth(
        TmpBuffer out, const Block &data, bool more = false
    ) throw(LengthException,ProtocolException) {
        encrypt_no_auth((Buffer &)out, data, more);
    }
    
    inline SecureBuffer encrypt_no_auth(const Block &data, bool more = false
    ) throw(ProtocolException) {
        SecureBuffer out(data.size()); encrypt_no_auth(out, data, more); return out;
    }
    
    inline void decrypt_no_auth(
        Buffer &out, const Block &data, bool more = false
    ) throw(LengthException,ProtocolException) {
        if (out.size() != data.size()) throw LengthException();
        if (!strobe_decrypt(sp, out, data, data.size(), more)) throw ProtocolException();
    }
    
    inline void decrypt_no_auth(
        TmpBuffer out, const Block &data, bool more = false
    ) throw(LengthException,ProtocolException) {
        decrypt_no_auth((Buffer &)out, data, more);
    }
    
    inline SecureBuffer decrypt_no_auth(const Block &data, bool more = false
    ) throw(ProtocolException) {
        SecureBuffer out(data.size()); decrypt_no_auth(out, data, more); return out;
    }
    
    inline void produce_auth(Buffer &out) throw(LengthException,ProtocolException) {
        if (out.size() > STROBE_MAX_AUTH_BYTES) throw LengthException();
        if (!strobe_produce_auth(sp, out, out.size())) throw ProtocolException();
    }
    
    inline void produce_auth(TmpBuffer out) throw(LengthException,ProtocolException) {
        produce_auth((Buffer &)out);
    }
    
    inline SecureBuffer produce_auth(
        uint8_t bytes = 8
    ) throw(ProtocolException) {
        SecureBuffer out(bytes); produce_auth(out); return out;
    }
    
    inline void encrypt(
        Buffer &out, const Block &data, uint8_t auth = 8
    ) throw(LengthException,ProtocolException) {
        if (out.size() < data.size() || out.size() != data.size() + auth) throw LengthException();
        encrypt_no_auth(out.slice(0,data.size()), data);
        produce_auth(out.slice(data.size(),auth));
    }
    
    inline void encrypt (
        TmpBuffer out, const Block &data, uint8_t auth = 8
    ) throw(LengthException,ProtocolException) {
        encrypt((Buffer &)out, data, auth);
    }
    
    inline SecureBuffer encrypt (
        const Block &data, uint8_t auth = 8
    ) throw(LengthException,ProtocolException,std::bad_alloc ){
        SecureBuffer out(data.size() + auth); encrypt(out, data, auth); return out;
    }
    
    inline void decrypt (
        Buffer &out, const Block &data, uint8_t bytes = 8
    ) throw(LengthException, CryptoException, ProtocolException) {
        if (out.size() > data.size() || out.size() != data.size() - bytes) throw LengthException();
        decrypt_no_auth(out, data.slice(0,out.size()));
        verify_auth(data.slice(out.size(),bytes));
    }
    
    inline void decrypt (
        TmpBuffer out, const Block &data, uint8_t bytes = 8
    ) throw(LengthException,CryptoException,ProtocolException) {
        decrypt((Buffer &)out, data, bytes);
    }
    
    inline SecureBuffer decrypt (
        const Block &data, uint8_t bytes = 8
    ) throw(LengthException,CryptoException,ProtocolException,std::bad_alloc) {
        if (data.size() < bytes) throw LengthException();
        SecureBuffer out(data.size() - bytes); decrypt(out, data, bytes); return out;
    }
    
    inline void verify_auth(const Block &auth) throw(LengthException,CryptoException) {
        if (auth.size() == 0 || auth.size() > STROBE_MAX_AUTH_BYTES) throw LengthException();
        if (!strobe_verify_auth(sp, auth, auth.size())) throw CryptoException();
    }
    
    inline void prng(Buffer &out, bool more = false) NOEXCEPT {
        (void)strobe_prng(sp, out, out.size(), more);
    }
    
    inline void prng(TmpBuffer out, bool more = false) NOEXCEPT {
        prng((Buffer &)out, more);
    }
    
    inline SecureBuffer prng(size_t bytes, bool more = false) {
        SecureBuffer out(bytes); prng(out, more); return out;
    }
    
    inline void respec(const kparams_s &params) throw(ProtocolException) {
        if (!strobe_respec(sp, &params)) throw(ProtocolException());
    }
};
  
} /* namespace decaf */

#undef NOEXCEPT
#undef EXPLICIT_CON
#undef GET_DATA
#undef DELETE

#endif /* __SHAKE_HXX__ */
