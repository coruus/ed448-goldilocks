/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ benchmarks, because that's easier.
 */

#include "decaf.hxx"
#include "shake.hxx"
#include "shake.h"
#include "decaf_crypto.h"
#include <stdio.h>
#include <sys/time.h>
#include <assert.h>
#include <stdint.h>

typedef decaf::decaf<448>::Scalar Scalar;
typedef decaf::decaf<448>::Point Point;
typedef decaf::decaf<448>::Precomputed Precomputed;

static __inline__ void __attribute__((unused)) ignore_result ( int result ) { (void)result; }
static double now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec/1000000.0;
}

// RDTSC from the chacha code
#ifndef __has_builtin
#define __has_builtin(X) 0
#endif
#if defined(__clang__) && __has_builtin(__builtin_readcyclecounter)
#define rdtsc __builtin_readcyclecounter
#else
static inline uint64_t rdtsc(void) {
  u_int64_t out = 0;
# if (defined(__i386__) || defined(__x86_64__))
    __asm__ __volatile__ ("rdtsc" : "=A"(out));
# endif
  return out;
}
#endif

static void printSI(double x, const char *unit, const char *spacer = " ") {
    const char *small[] = {" ","m","µ","n","p"};
    const char *big[] = {" ","k","M","G","T"};
    if (x < 1) {
        unsigned di=0;
        for (di=0; di<sizeof(small)/sizeof(*small)-1 && x && x < 1; di++) { 
            x *= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, small[di], unit);
    } else {
        unsigned di=0;
        for (di=0; di<sizeof(big)/sizeof(*big)-1 && x && x >= 1000; di++) { 
            x /= 1000.0;
        }
        printf("%6.2f%s%s%s", x, spacer, big[di], unit);
    }
}

class Benchmark {
    static const int NTESTS = 1000;
    static double totalCy, totalS;
    /* FIXME Tcy if get descheduled */
public:
    int i, ntests;
    double begin;
    uint64_t tsc_begin;
    Benchmark(const char *s, double factor = 1) {
        printf("%s:", s);
        if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
        fflush(stdout);
        i = 0;
        ntests = NTESTS * factor;
        begin = now();
        tsc_begin = rdtsc();
    }
    ~Benchmark() {
        double tsc = (rdtsc() - tsc_begin) * 1.0;
        double t = (now() - begin);
        
        totalCy += tsc;
        totalS += t;
        
        t /= ntests;
        tsc /= ntests;
        
        printSI(t,"s");
        printf("    ");
        printSI(1/t,"/s");
        if (tsc) { printf("    "); printSI(tsc, "cy"); }
        printf("\n");
    }
    inline bool iter() { return i++ < ntests; }
    static void calib() {
        if (totalS && totalCy) {
            const char *s = "Cycle calibration";
            printf("%s:", s);
            if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
            printSI(totalCy / totalS, "Hz");
            printf("\n");
        }
    }
};

double Benchmark::totalCy = 0, Benchmark::totalS = 0;

static void tdh (
    decaf::SpongeRng &rng,
    Scalar x, const decaf::Block &gx,
    Scalar y, const decaf::Block &gy
) {
    decaf::Strobe client(decaf::Strobe::CLIENT), server(decaf::Strobe::SERVER);
    
    Scalar xe(rng);
    decaf::SecureBuffer gxe = Precomputed::base() * xe;
    client.plaintext(gxe,true);
    server.plaintext(gxe,false);
    
    Scalar ye(rng);
    decaf::SecureBuffer gye = Precomputed::base() * ye;
    server.plaintext(gye,true);
    client.plaintext(gye,false);
    
    Point pgxe(gxe);
    server.key(pgxe*ye);
    decaf::SecureBuffer tag1 = server.produce_auth();
    decaf::SecureBuffer ct = server.encrypt(gy);
    server.key(pgxe*y);
    decaf::SecureBuffer tag2 = server.produce_auth();
    
    Point pgye(gye);
    client.key(pgye*xe);
    client.verify_auth(tag1);
    client.key(Point(client.decrypt(ct)) * xe);
    client.verify_auth(tag2);
    ct = client.encrypt(gx);
    client.key(pgye * x);
    tag1 = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    
    server.key(Point(server.decrypt(ct)) * ye);
    server.verify_auth(tag1);
    server.respec(STROBE_KEYED_128);
}

static void fhmqv (
    decaf::SpongeRng &rng,
    Scalar x, const decaf::Block &gx,
    Scalar y, const decaf::Block &gy
) {
    decaf::Strobe client(decaf::Strobe::CLIENT), server(decaf::Strobe::SERVER);
    
    Scalar xe(rng);
    client.plaintext(gx,true);
    server.plaintext(gx,false);
    decaf::SecureBuffer gxe = Precomputed::base() * xe;
    client.plaintext(gxe,true);
    server.plaintext(gxe,false);

    Scalar ye(rng);
    server.plaintext(gy,true);
    client.plaintext(gy,false);
    decaf::SecureBuffer gye = Precomputed::base() * ye;
    server.plaintext(gye,true);
    
    Scalar schx(server.prng(Scalar::SER_BYTES));
    Scalar schy(server.prng(Scalar::SER_BYTES));
    Scalar yec = y + ye*schy;
    server.key(Point::double_scalarmul(Point(gx),yec,Point(gxe),yec*schx));
    decaf::SecureBuffer as = server.produce_auth();
    
    client.plaintext(gye,false);
    Scalar cchx(client.prng(Scalar::SER_BYTES));
    Scalar cchy(client.prng(Scalar::SER_BYTES));
    Scalar xec = x + xe*schx;
    client.key(Point::double_scalarmul(Point(gy),xec,Point(gye),xec*schy));
    client.verify_auth(as);
    decaf::SecureBuffer ac = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    
    server.verify_auth(ac);
    server.respec(STROBE_KEYED_128);
}

static void spake2ee(const decaf::Block &hashed_password, decaf::SpongeRng &rng, bool aug) {
    decaf::Strobe client(decaf::Strobe::CLIENT), server(decaf::Strobe::SERVER);
    
    Scalar x(rng);
    
    decaf::SHAKE<256> shake;
    unsigned char whose[1] = {0};
    shake.update(hashed_password);
    shake.update(decaf::Block(whose,1));
    decaf::SecureBuffer h0 = shake.output(Point::HASH_BYTES);
    
    shake.reset();
    whose[0] = 1;
    shake.update(hashed_password);
    shake.update(decaf::Block(whose,1));
    decaf::SecureBuffer h1 = shake.output(Point::HASH_BYTES);
    
    shake.reset();
    whose[0] = 2;
    shake.update(hashed_password);
    shake.update(decaf::Block(whose,1));
    decaf::SecureBuffer h2 = shake.output(Scalar::SER_BYTES);
    Scalar gs(h2);
    
    Point hc = Point::from_hash(h0);
    hc = Point::from_hash(h0); // double-count
    Point hs = Point::from_hash(h1);
    hs = Point::from_hash(h1); // double-count
    
    decaf::SecureBuffer gx(Precomputed::base() * x + hc);
    client.plaintext(gx,true);
    server.plaintext(gx,false);
    
    Scalar y(rng);
    decaf::SecureBuffer gy(Precomputed::base() * y + hs);
    server.plaintext(gy,true);
    client.plaintext(gy,false);
    
    server.key(h1);
    server.key((Point(gx) - hc)*y);
    if(aug) {
        /* This step isn't actually online but whatever, it's fastish */
        decaf::SecureBuffer serverAug(Precomputed::base() * gs);
        server.key(Point(serverAug)*y);
    }
    decaf::SecureBuffer tag = server.produce_auth();
    
    client.key(h1);
    Point pgy(gy); pgy -= hs;
    client.key(pgy*x);
    if (aug) client.key(pgy * gs);
    client.verify_auth(tag);    
    tag = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    /* TODO: fork... */
    
    server.verify_auth(tag);
    server.respec(STROBE_KEYED_128);
}

int main(int argc, char **argv) {
    bool micro = false;
    if (argc >= 2 && !strcmp(argv[1], "--micro"))
        micro = true;
    
    decaf_448_public_key_t p1,p2;
    decaf_448_private_key_t s1,s2;
    decaf_448_symmetric_key_t r1,r2;
    decaf_448_signature_t sig1;
    unsigned char ss[32];
    
    memset(r1,1,sizeof(r1));
    memset(r2,2,sizeof(r2)); 
    
    unsigned char umessage[] = {1,2,3,4,5};
    size_t lmessage = sizeof(umessage);


    if (micro) {
        Precomputed pBase;
        Point p,q;
        Scalar s,t;
        decaf::SecureBuffer ep, ep2(Point::SER_BYTES*2);
        
        printf("\nMicro-benchmarks:\n");
        decaf::SHAKE<128> shake1;
        decaf::SHAKE<256> shake2;
        decaf::SHA3<512> sha5;
        decaf::Strobe strobe(decaf::Strobe::CLIENT);
        unsigned char b1024[1024] = {1};
        for (Benchmark b("SHAKE128 1kiB", 30); b.iter(); ) { shake1 += decaf::TmpBuffer(b1024,1024); }
        for (Benchmark b("SHAKE256 1kiB", 30); b.iter(); ) { shake2 += decaf::TmpBuffer(b1024,1024); }
        for (Benchmark b("SHA3-512 1kiB", 30); b.iter(); ) { sha5 += decaf::TmpBuffer(b1024,1024); }
        strobe.key(decaf::TmpBuffer(b1024,1024));
        for (Benchmark b("STROBE256 1kiB", 30); b.iter(); ) {
            strobe.encrypt_no_auth(decaf::TmpBuffer(b1024,1024),decaf::TmpBuffer(b1024,1024),b.i>1);
        }
        strobe.respec(STROBE_KEYED_128);
        for (Benchmark b("STROBEk128 1kiB", 30); b.iter(); ) {
            strobe.encrypt_no_auth(decaf::TmpBuffer(b1024,1024),decaf::TmpBuffer(b1024,1024),b.i>1);
        }
        for (Benchmark b("Scalar add", 1000); b.iter(); ) { s+=t; }
        for (Benchmark b("Scalar times", 100); b.iter(); ) { s*=t; }
        for (Benchmark b("Scalar inv", 1); b.iter(); ) { s.inverse(); }
        for (Benchmark b("Point add", 100); b.iter(); ) { p += q; }
        for (Benchmark b("Point double", 100); b.iter(); ) { p.double_in_place(); }
        for (Benchmark b("Point scalarmul"); b.iter(); ) { p * s; }
        for (Benchmark b("Point encode"); b.iter(); ) { ep = decaf::SecureBuffer(p); }
        for (Benchmark b("Point decode"); b.iter(); ) { p = Point(ep); }
        for (Benchmark b("Point create/destroy"); b.iter(); ) { Point r; }
        for (Benchmark b("Point hash nonuniform"); b.iter(); ) { Point::from_hash(ep); }
        for (Benchmark b("Point hash uniform"); b.iter(); ) { Point::from_hash(ep2); }
        for (Benchmark b("Point double scalarmul"); b.iter(); ) { Point::double_scalarmul(p,s,q,t); }
        for (Benchmark b("Point precmp scalarmul"); b.iter(); ) { pBase * s; }
        /* TODO: scalarmul for verif, etc */
    }

    printf("\nMacro-benchmarks:\n");
    for (Benchmark b("Keygen"); b.iter(); ) {
        decaf_448_derive_private_key(s1,r1);
    }
    
    decaf_448_private_to_public(p1,s1);
    decaf_448_derive_private_key(s2,r2);
    decaf_448_private_to_public(p2,s2);
    
    for (Benchmark b("Shared secret"); b.iter(); ) {
        decaf_bool_t ret = decaf_448_shared_secret(ss,sizeof(ss),s1,p2);
        ignore_result(ret);
        assert(ret);
    }
    
    for (Benchmark b("Sign"); b.iter(); ) {
        decaf_448_sign(sig1,s1,umessage,lmessage);
    }
    
    for (Benchmark b("Verify"); b.iter(); ) {
        decaf_bool_t ret = decaf_448_verify(sig1,p1,umessage,lmessage);
        umessage[0]++;
        umessage[1]^=umessage[0];
        ignore_result(ret);
    }

    printf("\nProtocol benchmarks:\n");
    decaf::SpongeRng rng(decaf::Block("my rng seed"));
    decaf::SecureBuffer hashedPassword("hello world");
    for (Benchmark b("Spake2ee c+s",0.1); b.iter(); ) {
        spake2ee(hashedPassword,rng,false);
    }
    
    for (Benchmark b("Spake2ee c+s aug",0.1); b.iter(); ) {
        spake2ee(hashedPassword,rng,true);
    }
    
    Scalar x(rng);
    decaf::SecureBuffer gx(Precomputed::base() * x);
    Scalar y(rng);
    decaf::SecureBuffer gy(Precomputed::base() * y);
    
    for (Benchmark b("FHMQV c+s",0.1); b.iter(); ) {
        fhmqv(rng,x,gx,y,gy);
    }
    
    for (Benchmark b("TripleDH anon c+s",0.1); b.iter(); ) {
        tdh(rng,x,gx,y,gy);
    }
    
    printf("\n");
    Benchmark::calib();
    printf("\n");
    
    return 0;
}
