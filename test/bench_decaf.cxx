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
#include <vector>
#include <algorithm>

using namespace decaf;
typedef Ed448::Scalar Scalar;
typedef Ed448::Point Point;
typedef Ed448::Precomputed Precomputed;


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
    static const int NTESTS = 20, NSAMPLES=50, DISCARD=2;
    static double totalCy, totalS;
    /* FIXME Tcy if get descheduled */
public:
    int i, j, ntests, nsamples;
    double begin;
    uint64_t tsc_begin;
    std::vector<double> times;
    std::vector<uint64_t> cycles;
    Benchmark(const char *s, double factor = 1) {
        printf("%s:", s);
        if (strlen(s) < 25) printf("%*s",int(25-strlen(s)),"");
        fflush(stdout);
        i = j = 0;
        ntests = NTESTS * factor;
        nsamples = NSAMPLES;
        begin = now();
        tsc_begin = rdtsc();
        times = std::vector<double>(NSAMPLES);
        cycles = std::vector<uint64_t>(NSAMPLES);
    }
    ~Benchmark() {
        double tsc = 0;
        double t = 0;
        
        std::sort(times.begin(), times.end());
        std::sort(cycles.begin(), cycles.end());
        
        for (int k=DISCARD; k<nsamples-DISCARD; k++) {
            tsc += cycles[k];
            t += times[k];
        }
        
        totalCy += tsc;
        totalS += t;
        
        t /= ntests*(nsamples-2*DISCARD);
        tsc /= ntests*(nsamples-2*DISCARD);
        
        printSI(t,"s");
        printf("    ");
        printSI(1/t,"/s");
        if (tsc) { printf("    "); printSI(tsc, "cy"); }
        printf("\n");
    }
    inline bool iter() {
        i++;
        if (i >= ntests) {
            uint64_t tsc = rdtsc() - tsc_begin;
            double t = now() - begin;
            begin += t;
            tsc_begin += tsc;
            assert(j >= 0 && j < nsamples);
            cycles[j] = tsc;
            times[j] = t;
            
            j++;
            i = 0;
        }
        return j < nsamples;
    }
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
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    Scalar x, const Block &gx,
    Scalar y, const Block &gy
) {
    Strobe client(Strobe::CLIENT), server(Strobe::SERVER);
    
    Scalar xe(clientRng);
    SecureBuffer gxe = Precomputed::base() * xe;
    client.send_plaintext(gxe);
    server.recv_plaintext(gxe);
    
    Scalar ye(serverRng);
    SecureBuffer gye = Precomputed::base() * ye;
    server.send_plaintext(gye);
    client.recv_plaintext(gye);
    
    Point pgxe(gxe);
    server.key(pgxe*ye);
    SecureBuffer tag1 = server.produce_auth();
    SecureBuffer ct = server.encrypt(gy);
    server.key(pgxe*y);
    SecureBuffer tag2 = server.produce_auth();
    
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
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    Scalar x, const Block &gx,
    Scalar y, const Block &gy
) {
    /* Don't use this, it's probably patented */
    Strobe client(Strobe::CLIENT), server(Strobe::SERVER);
    
    Scalar xe(clientRng);
    client.send_plaintext(gx);
    server.recv_plaintext(gx);
    SecureBuffer gxe = Precomputed::base() * xe;
    server.send_plaintext(gxe);
    client.recv_plaintext(gxe);

    Scalar ye(serverRng);
    server.send_plaintext(gy);
    client.recv_plaintext(gy);
    SecureBuffer gye = Precomputed::base() * ye;
    server.send_plaintext(gye);
    
    Scalar schx(server.prng(Scalar::SER_BYTES));
    Scalar schy(server.prng(Scalar::SER_BYTES));
    Scalar yec = y + ye*schy;
    server.key(Point::double_scalarmul(Point(gx),yec,Point(gxe),yec*schx));
    SecureBuffer as = server.produce_auth();
    
    client.recv_plaintext(gye);
    Scalar cchx(client.prng(Scalar::SER_BYTES));
    Scalar cchy(client.prng(Scalar::SER_BYTES));
    Scalar xec = x + xe*schx;
    client.key(Point::double_scalarmul(Point(gy),xec,Point(gye),xec*schy));
    client.verify_auth(as);
    SecureBuffer ac = client.produce_auth();
    client.respec(STROBE_KEYED_128);
    
    server.verify_auth(ac);
    server.respec(STROBE_KEYED_128);
}

static void spake2ee(
    SpongeRng &clientRng,
    SpongeRng &serverRng,
    const Block &hashed_password,
    bool aug
) {
    Strobe client(Strobe::CLIENT), server(Strobe::SERVER);
    
    Scalar x(clientRng);
    
    SHAKE<256> shake;
    shake.update(hashed_password);
    SecureBuffer h0 = shake.output(Point::HASH_BYTES);
    SecureBuffer h1 = shake.output(Point::HASH_BYTES);
    SecureBuffer h2 = shake.output(Scalar::SER_BYTES);
    Scalar gs(h2);
    
    Point hc = Point::from_hash(h0);
    hc = Point::from_hash(h0); // double-count
    Point hs = Point::from_hash(h1);
    hs = Point::from_hash(h1); // double-count
    
    SecureBuffer gx(Precomputed::base() * x + hc);
    client.send_plaintext(gx);
    server.recv_plaintext(gx);
    
    Scalar y(serverRng);
    SecureBuffer gy(Precomputed::base() * y + hs);
    server.send_plaintext(gy);
    client.recv_plaintext(gy);
    
    server.key(h1);
    server.key((Point(gx) - hc)*y);
    if(aug) {
        /* This step isn't actually online but whatever, it's fastish */
        SecureBuffer serverAug(Precomputed::base() * gs);
        server.key(Point(serverAug)*y);
    }
    SecureBuffer tag = server.produce_auth();
    
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
        SecureBuffer ep, ep2(Point::SER_BYTES*2);
        SpongeRng rng(Block("micro-benchmarks"));
        
        printf("\nMicro-benchmarks:\n");
        SHAKE<128> shake1;
        SHAKE<256> shake2;
        SHA3<512> sha5;
        Strobe strobe(Strobe::CLIENT);
        unsigned char b1024[1024] = {1};
        for (Benchmark b("SHAKE128 1kiB", 30); b.iter(); ) { shake1 += TmpBuffer(b1024,1024); }
        for (Benchmark b("SHAKE256 1kiB", 30); b.iter(); ) { shake2 += TmpBuffer(b1024,1024); }
        for (Benchmark b("SHA3-512 1kiB", 30); b.iter(); ) { sha5 += TmpBuffer(b1024,1024); }
        strobe.key(TmpBuffer(b1024,1024));
        strobe.respec(STROBE_128);
        for (Benchmark b("STROBE128 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(TmpBuffer(b1024,1024),TmpBuffer(b1024,1024),b.i>1);
        }
        strobe.respec(STROBE_256);
        for (Benchmark b("STROBE256 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(TmpBuffer(b1024,1024),TmpBuffer(b1024,1024),b.i>1);
        }
        strobe.respec(STROBE_KEYED_128);
        for (Benchmark b("STROBEk128 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(TmpBuffer(b1024,1024),TmpBuffer(b1024,1024),b.i>1);
        }
        strobe.respec(STROBE_KEYED_256);
        for (Benchmark b("STROBEk256 1kiB", 10); b.iter(); ) {
            strobe.encrypt_no_auth(TmpBuffer(b1024,1024),TmpBuffer(b1024,1024),b.i>1);
        }
        for (Benchmark b("Scalar add", 1000); b.iter(); ) { s+=t; }
        for (Benchmark b("Scalar times", 100); b.iter(); ) { s*=t; }
        for (Benchmark b("Scalar inv", 1); b.iter(); ) { s.inverse(); }
        for (Benchmark b("Point add", 100); b.iter(); ) { p += q; }
        for (Benchmark b("Point double", 100); b.iter(); ) { p.double_in_place(); }
        for (Benchmark b("Point scalarmul"); b.iter(); ) { p * s; }
        for (Benchmark b("Point encode"); b.iter(); ) { ep = SecureBuffer(p); }
        for (Benchmark b("Point decode"); b.iter(); ) { p = Point(ep); }
        for (Benchmark b("Point create/destroy"); b.iter(); ) { Point r; }
        for (Benchmark b("Point hash nonuniform"); b.iter(); ) { Point::from_hash(ep); }
        for (Benchmark b("Point hash uniform"); b.iter(); ) { Point::from_hash(ep2); }
        for (Benchmark b("Point unhash nonuniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep,0)); }
        for (Benchmark b("Point unhash uniform"); b.iter(); ) { ignore_result(p.invert_elligator(ep2,0)); }
        for (Benchmark b("Point steg"); b.iter(); ) { p.steg_encode(rng); }
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
    SpongeRng clientRng(Block("client rng seed"));
    SpongeRng serverRng(Block("server rng seed"));
    SecureBuffer hashedPassword("hello world");
    for (Benchmark b("Spake2ee c+s",0.1); b.iter(); ) {
        spake2ee(clientRng, serverRng, hashedPassword,false);
    }
    
    for (Benchmark b("Spake2ee c+s aug",0.1); b.iter(); ) {
        spake2ee(clientRng, serverRng, hashedPassword,true);
    }
    
    Scalar x(clientRng);
    SecureBuffer gx(Precomputed::base() * x);
    Scalar y(serverRng);
    SecureBuffer gy(Precomputed::base() * y);
    
    for (Benchmark b("FHMQV c+s",0.1); b.iter(); ) {
        fhmqv(clientRng, serverRng,x,gx,y,gy);
    }
    
    for (Benchmark b("TripleDH anon c+s",0.1); b.iter(); ) {
        tdh(clientRng, serverRng, x,gx,y,gy);
    }
    
    printf("\n");
    Benchmark::calib();
    printf("\n");
    
    return 0;
}
