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
    inline void update(const std::string &s) { sha3_update(sp,GET_DATA(s),s.size()); }
    
    /** Add more data, stream version. */
    inline KeccakHash &operator<<(const std::string &s) { update(s); return *this; }
    
    /** Same as <<. */
    inline KeccakHash &operator+=(const std::string &s) { return *this << s; }
    
    /**
     * @brief Output bytes from the sponge.
     * @todo make this throw exceptions.
     */
    inline void output(unsigned char *c, size_t len) {
        sha3_output(sp,c,len);
    }
    
    /** @brief Output bytes from the sponge. */
    inline std::string output(size_t len) {
        unsigned char *buffer = new unsigned char[len];
        sha3_output(sp,buffer,len);
        std::string out((char *)buffer, len);
        delete[] buffer;
        return out;
    }
    
    /** @brief Return the sponge's default output size. */
    inline size_t default_output_size() const NOEXCEPT {
        return sponge_default_output_bytes(sp);
    }
    
    /** Output the default number of bytes. */
    inline std::string output() {
        return output(default_output_size());
    }
};

/** Fixed-output-length SHA3 */
template<int bits> class SHA3 : public KeccakSponge {
private:
    /** Get the parameter template block for this hash */
    const struct kparams_s *get_params();
public:
    /** Initializer */
    inline SHA3() NOEXCEPT : KeccakHash(get_params()) {}
};

/** Variable-output-length SHAKE */
template<int bits>
class SHAKE : public KeccakSponge {
private:
    /** Get the parameter template block for this hash */
    const struct kparams_s *get_params();
public:
    /** Initializer */
    inline SHAKE() NOEXCEPT : KeccakHash(get_params()) {}
};

/** @cond internal */
template<> const struct kparams_s *SHAKE<128>::get_params() { return &SHAKE128_params_s; }
template<> const struct kparams_s *SHAKE<256>::get_params() { return &SHAKE256_params_s; }
template<> const struct kparams_s *SHA3<224>::get_params() { return &SHA3_224_params_s; }
template<> const struct kparams_s *SHA3<256>::get_params() { return &SHA3_256_params_s; }
template<> const struct kparams_s *SHA3<384>::get_params() { return &SHA3_384_params_s; }
template<> const struct kparams_s *SHA3<512>::get_params() { return &SHA3_512_params_s; }
/** @endcond */

/** Sponge-based random-number generator */
class SpongeRng : public KeccakSponge {
public:
    /** Initialize, deterministically by default, from C buffer */
    inline SpongeRng( const uint8_t *in, size_t len, bool deterministic = true ) NOEXCEPT
    : KeccakSponge(NI) {
        spongerng_init_from_buffer(sp,in,len,deterministic);
    }
    
    /** Initialize, deterministically by default, from C++ string */
    inline SpongeRng( const std::string &in, bool deterministic = true ) NOEXCEPT
    : KeccakSponge(NI) {
        spongerng_init_from_buffer(sp,GET_DATA(in),in.size(),deterministic);
    }
};
  
} /* namespace decaf */

#undef NOEXCEPT
#undef EXPLICIT_CON
#undef GET_DATA

#endif /* __SHAKE_HXX__ */
