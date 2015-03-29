/**
 * @cond internal
 * @file shake.c
 * @copyright
 *   Uses public domain code by Mathias Panzenböck \n
 *   Uses CC0 code by David Leon Gil, 2015 \n
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA-3-n and SHAKE-n instances.
 * @warning EXPERIMENTAL!  The names, parameter orders etc are likely to change.
 */

#define __STDC_WANT_LIB_EXT1__ 1 /* for memset_s */
#define _BSD_SOURCE 1 /* for endian */
#include <assert.h>
#include <stdint.h>
#include <string.h>

/* to open and read from /dev/urandom */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

/* Subset of Mathias Panzenböck's portable endian code, public domain */
#if defined(__linux__) || defined(__CYGWIN__)
#	include <endian.h>
#elif defined(__OpenBSD__)
#	include <sys/endian.h>
#elif defined(__APPLE__)
#	include <libkern/OSByteOrder.h>
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#	include <sys/endian.h>
#	define le64toh(x) letoh64(x)
#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64) || defined(__WINDOWS__)
#	include <winsock2.h>
#	include <sys/param.h>
#	if BYTE_ORDER == LITTLE_ENDIAN
#		define htole64(x) (x)
#		define le64toh(x) (x)
#	elif BYTE_ORDER == BIG_ENDIAN
#		define htole64(x) __builtin_bswap64(x)
#		define le64toh(x) __builtin_bswap64(x)
#	else
#		error byte order not supported
#	endif
#else
#	error platform not supported
#endif

/* The internal, non-opaque definition of the sponge struct. */
typedef union {
    uint64_t w[25]; uint8_t b[25*8];
} kdomain_t[1];

typedef struct kparams_s {
    uint8_t position, flags, rate, startRound, pad, ratePad, maxOut, _;
} kparams_t[1];

typedef struct keccak_sponge_s {
    kdomain_t state;
    kparams_t params;
} keccak_sponge_t[1];

#define INTERNAL_SPONGE_STRUCT 1
#include "shake.h"

#define FLAG_ABSORBING 'A'
#define FLAG_SQUEEZING 'Z'
#define FLAG_RNG_SQU   'R'
#define FLAG_DET_SQU   'D'
#define FLAG_RNG_ABS   'r'
#define FLAG_DET_ABS   'd'
#define FLAG_RNG_UNI   'u'
#define FLAG_DET_UNI   'g'

/** Constants. **/
static const uint8_t pi[24] = {
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

#define RC_B(x,n) ((((x##ull)>>n)&1)<<((1<<n)-1))
#define RC_X(x) (RC_B(x,0)|RC_B(x,1)|RC_B(x,2)|RC_B(x,3)|RC_B(x,4)|RC_B(x,5)|RC_B(x,6))
static const uint64_t RC[24] = {
    RC_X(0x01), RC_X(0x1a), RC_X(0x5e), RC_X(0x70), RC_X(0x1f), RC_X(0x21),
    RC_X(0x79), RC_X(0x55), RC_X(0x0e), RC_X(0x0c), RC_X(0x35), RC_X(0x26),
    RC_X(0x3f), RC_X(0x4f), RC_X(0x5d), RC_X(0x53), RC_X(0x52), RC_X(0x48),
    RC_X(0x16), RC_X(0x66), RC_X(0x79), RC_X(0x58), RC_X(0x21), RC_X(0x74)
};

static inline uint64_t rol(uint64_t x, int s) {
    return (x << s) | (x >> (64 - s));
}

/* Helper macros to unroll the permutation.  TODO: opt tradeoffs. */
#define REPEAT5(e) e e e e e
#define FOR51(v, e) v = 0; REPEAT5(e; v += 1;)
//#if (defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__))
#    define FOR55(v, e) v = 0; REPEAT5(e; v += 5;)
#    define REPEAT24(e) e e e e e e e e e e e e e e e e e e e e e e e e
// #else
// #    define FOR55(v, e) for (v=0; v<25; v+= 5) { e; }
// #    define REPEAT24(e) {int _j=0; for (_j=0; _j<24; _j++) { e }}
// #endif

/*** The Keccak-f[1600] permutation ***/
static void
__attribute__((noinline))
keccakf(kdomain_t state, uint8_t startRound) {
    uint64_t* a = state->w;
    uint64_t b[5] = {0}, t, u;
    uint8_t x, y, i;
    
    for (i=0; i<25; i++) a[i] = le64toh(a[i]);

    for (i = startRound; i < 24; i++) {
        FOR51(x, b[x] = 0; FOR55(y, b[x] ^= a[x + y];))
        FOR51(x, FOR55(y,
            a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);
        ))
        // Rho and pi
        t = a[1];
        x = y = 0;
        REPEAT24(u = a[pi[x]]; y += x+1; a[pi[x]] = rol(t, y % 64); t = u; x++; )
        // Chi
        FOR55(y,
             FOR51(x, b[x] = a[y + x];)
             FOR51(x, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);)
        )
        // Iota
        a[0] ^= RC[i];
    }

    for (i=0; i<25; i++) a[i] = htole64(a[i]);
}

static inline void dokeccak (keccak_sponge_t sponge) {
    keccakf(sponge->state, sponge->params->startRound);
    sponge->params->position = 0;
}

void sha3_update (
    struct keccak_sponge_s * __restrict__ sponge,
    const uint8_t *in,
    size_t len
) {
    if (!len) return;
    assert(sponge->params->position < sponge->params->rate);
    assert(sponge->params->rate < sizeof(sponge->state));
    assert(sponge->params->flags == FLAG_ABSORBING);
    while (len) {
        size_t cando = sponge->params->rate - sponge->params->position, i;
        uint8_t* state = &sponge->state->b[sponge->params->position];
        if (cando > len) {
            for (i = 0; i < len; i += 1) state[i] ^= in[i];
            sponge->params->position += len;
            return;
        } else {
            for (i = 0; i < cando; i += 1) state[i] ^= in[i];
            dokeccak(sponge);
            len -= cando;
            in += cando;
        }
    }
}

void sha3_output (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    assert(sponge->params->position < sponge->params->rate);
    assert(sponge->params->rate < sizeof(sponge->state));
    
    if (sponge->params->maxOut != 0xFF) {
        assert(sponge->params->maxOut >= len);
        sponge->params->maxOut -= len;
    }
    
    switch (sponge->params->flags) {
    case FLAG_SQUEEZING: break;
    case FLAG_ABSORBING:
        {
            uint8_t* state = sponge->state->b;
            state[sponge->params->position] ^= sponge->params->pad;
            state[sponge->params->rate - 1] ^= sponge->params->ratePad;
            dokeccak(sponge);
            break;
        }
    default:
        assert(0);
    }
    
    while (len) {
        size_t cando = sponge->params->rate - sponge->params->position;
        uint8_t* state = &sponge->state->b[sponge->params->position];
        if (cando > len) {
            memcpy(out, state, len);
            sponge->params->position += len;
            return;
        } else {
            memcpy(out, state, cando);
            dokeccak(sponge);
            len -= cando;
            out += cando;
        }
    }
}

/** TODO: unify with decaf_bzero? */
void sponge_destroy (
    keccak_sponge_t sponge
) {
#ifdef __STDC_LIB_EXT1__
    memset_s(sponge, sizeof(sponge), 0, sizeof(sponge));
#else
    volatile uint64_t *destroy = (volatile uint64_t *)sponge;
    unsigned i;
    for (i=0; i<sizeof(keccak_sponge_t)/8; i++) {
        destroy[i] = 0;
    }
#endif
}

void sponge_init (
    keccak_sponge_t sponge,
    const struct kparams_s *params
) {
    memset(sponge->state, 0, sizeof(sponge->state));
    sponge->params[0] = params[0];
}

void sponge_hash (
    const uint8_t *in,
    size_t inlen,
    uint8_t *out,
    size_t outlen,
    const struct kparams_s *params
) {
    keccak_sponge_t sponge;
    sponge_init(sponge, params);
    sha3_update(sponge, in, inlen);
    sha3_output(sponge, out, outlen);
    sponge_destroy(sponge);
}

#define DEFSHAKE(n) \
    const struct kparams_s SHAKE##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x1f, 0x80, 0xFF, 0 };
    
#define DEFSHA3(n) \
    const struct kparams_s SHA3_##n##_params_s = \
        { 0, FLAG_ABSORBING, 200-n/4, 0, 0x06, 0x80, n/8, 0 };

size_t sponge_default_output_bytes (
    const keccak_sponge_t s
) {
    return (s->params->maxOut == 0xFF)
        ? (200-s->params->rate)
        : ((200-s->params->rate)/2);
}

DEFSHAKE(128)
DEFSHAKE(256)
DEFSHA3(224)
DEFSHA3(256)
DEFSHA3(384)
DEFSHA3(512)

/** Get entropy from a CPU, preferably in the form of RDRAND, but possibly instead from RDTSC. */
static void get_cpu_entropy(uint8_t *entropy, size_t len) {
# if (defined(__i386__) || defined(__x86_64__))
    static char tested = 0, have_rdrand = 0;
    if (!tested) {
        u_int32_t a,b,c,d;
        a=1; __asm__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
        have_rdrand = (c>>30)&1;
        tested = 1;
    }

    if (have_rdrand) {
        # if defined(__x86_64__)
            uint64_t out, a=0, *eo = (uint64_t *)entropy;
        # elif defined(__i386__)
            uint32_t out, a=0, *eo = (uint64_t *)entropy;
        #endif
        len /= sizeof(out);

        uint32_t tries;
        for (tries = 100+len; tries && len; len--, eo++) {
            for (a = 0; tries && !a; tries--) {
                __asm__ __volatile__ ("rdrand %0\n\tsetc %%al" : "=r"(out), "+a"(a) :: "cc" );
            }
            *eo ^= out;
        }
    } else if (len>8) {
        uint64_t out;
        __asm__ __volatile__ ("rdtsc" : "=A"(out));
        *(uint64_t*) entropy ^= out;
    }

#else
    (void) entropy;
    (void) len;
#endif
}

void spongerng_next (
    keccak_sponge_t sponge,
    uint8_t * __restrict__ out,
    size_t len
) {
    assert(sponge->params->position < sponge->params->rate);
    assert(sponge->params->rate < sizeof(sponge->state));

    switch(sponge->params->flags) {
    case FLAG_DET_SQU: case FLAG_RNG_SQU: break;
    case FLAG_DET_ABS: case FLAG_RNG_ABS:
        {
            uint8_t* state = sponge->state->b;
            state[sponge->params->position] ^= sponge->params->pad;
            state[sponge->params->rate - 1] ^= sponge->params->ratePad;
            dokeccak(sponge);
            sponge->params->flags = (sponge->params->flags == FLAG_DET_ABS) ? FLAG_DET_SQU : FLAG_RNG_SQU;
            break;
        }
    default: assert(0);
    };

    while (len) {
        size_t cando = sponge->params->rate - sponge->params->position;
        uint8_t* state = &sponge->state->b[sponge->params->position];
        if (cando > len) {
            memcpy(out, state, len);
            memset(state, 0, len);
            sponge->params->position += len;
            return;
        } else {
            memcpy(out, state, cando);
            memset(state, 0, cando);
            if (sponge->params->flags == FLAG_RNG_SQU)
                get_cpu_entropy(sponge->state->b, 32);
            dokeccak(sponge);
            len -= cando;
            out += cando;
        }
    }

    /* Anti-rollback */
    if (sponge->params->position < 32) {
        memset(&sponge->state->b, 0, 32);
        sponge->params->position = 32;
    }
}

void spongerng_stir (
    keccak_sponge_t sponge,
    const uint8_t * __restrict__ in,
    size_t len
) {
    assert(sponge->params->position < sponge->params->rate);
    assert(sponge->params->rate < sizeof(sponge->state));

    switch(sponge->params->flags) {
    case FLAG_RNG_SQU:
        get_cpu_entropy(sponge->state->b, 32);
        /* fall through */
    case FLAG_DET_SQU: 
        sponge->params->flags = (sponge->params->flags == FLAG_DET_SQU) ? FLAG_DET_ABS : FLAG_RNG_ABS;
        dokeccak(sponge);
        break;
    case FLAG_DET_ABS: case FLAG_RNG_ABS: break;
    case FLAG_DET_UNI: case FLAG_RNG_UNI: break;
    default: assert(0);
    };

    while (len) {
        size_t i;
        size_t cando = sponge->params->rate - sponge->params->position;
        uint8_t* state = &sponge->state->b[sponge->params->position];
        if (cando > len) {
            for (i = 0; i < len; i += 1) state[i] ^= in[i];
            sponge->params->position += len;
            return;
        } else {
            for (i = 0; i < cando; i += 1) state[i] ^= in[i];
            dokeccak(sponge);
            len -= cando;
            in += cando;
        }
    }
}

static const struct kparams_s spongerng_params = {
    0, FLAG_RNG_UNI, 200-256/4, 0, 0x06, 0x80, 0xFF, 0
};

void spongerng_init_from_buffer (
    keccak_sponge_t sponge,
    const uint8_t * __restrict__ in,
    size_t len,
    int deterministic
) {
    sponge_init(sponge, &spongerng_params);
    sponge->params->flags = deterministic ? FLAG_DET_ABS : FLAG_RNG_ABS;
    spongerng_stir(sponge, in, len);
}

int spongerng_init_from_file (
    keccak_sponge_t sponge,
    const char *file,
    size_t len,
    int deterministic
) {
    sponge_init(sponge, &spongerng_params);
    sponge->params->flags = deterministic ? FLAG_DET_UNI : FLAG_RNG_UNI;
    if (!len) return -2;

    int fd = open(file, O_RDONLY);
    if (fd < 0) return errno ? errno : -1;
    
    uint8_t buffer[128];
    while (len) {
        ssize_t red = read(fd, buffer, (len > sizeof(buffer)) ? sizeof(buffer) : len);
        if (red <= 0) {
            close(fd);
            return errno ? errno : -1;
        }
        spongerng_stir(sponge,buffer,red);
        len -= red;
    };
    close(fd);

    sponge->params->flags = deterministic ? FLAG_DET_ABS : FLAG_RNG_ABS;
    return 0;
}

int spongerng_init_from_dev_urandom (
    keccak_sponge_t sponge
) {
    return spongerng_init_from_file(sponge, "/dev/urandom", 64, 0);
}

/* TODO: Keyak instances, etc */
