/**
 * @file test_decaf.cxx
 * @author Mike Hamburg
 *
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 *
 * @brief C++ tests, because that's easier.
 */

#include "decaf.hxx"
#include "shake.hxx"
#include "decaf_crypto.h"
#include <stdio.h>


static bool passing = true;
static const long NTESTS = 10000;

class Test {
public:
    bool passing_now;
    Test(const char *test) {
        passing_now = true;
        printf("%s...", test);
        if (strlen(test) < 27) printf("%*s",int(27-strlen(test)),"");
        fflush(stdout);
    }
    ~Test() {
        if (std::uncaught_exception()) {
            fail();
            printf("  due to uncaught exception.\n");
        }
        if (passing_now) printf("[PASS]\n");
    }
    void fail() {
        if (!passing_now) return;
        passing_now = passing = false;
        printf("[FAIL]\n");
    }
};

template<typename Group> struct Tests {

typedef typename Group::Scalar Scalar;
typedef typename Group::Point Point;
typedef typename Group::Precomputed Precomputed;

static void print(const char *name, const Scalar &x) {
    unsigned char buffer[Scalar::SER_BYTES];
    x.encode(buffer);
    printf("  %s = 0x", name);
    for (int i=sizeof(buffer)-1; i>=0; i--) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static void print(const char *name, const Point &x) {
    unsigned char buffer[Point::SER_BYTES];
    x.encode(buffer);
    printf("  %s = 0x", name);
    for (int i=sizeof(buffer)-1; i>=0; i--) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

static bool arith_check(
    Test &test,
    const Scalar &x,
    const Scalar &y,
    const Scalar &z,
    const Scalar &l,
    const Scalar &r,
    const char *name
) {
    if (l == r) return true;
    test.fail();
    printf("  %s", name);
    print("x", x);
    print("y", y);
    print("z", z);
    print("lhs", l);
    print("rhs", r);
    return false;
}

static bool point_check(
    Test &test,
    const Point &p,
    const Point &q,
    const Point &R,
    const Scalar &x,
    const Scalar &y,
    const Point &l,
    const Point &r,
    const char *name
) {
    bool good = l==r;
    if (!p.validate()) { good = false; printf("  p invalid\n"); }
    if (!q.validate()) { good = false; printf("  q invalid\n"); }
    if (!r.validate()) { good = false; printf("  r invalid\n"); }
    if (!l.validate()) { good = false; printf("  l invalid\n"); }
    if (good) return true;
    
    test.fail();
    printf("  %s", name);
    print("x", x);
    print("y", y);
    print("p", p);
    print("q", q);
    print("r", R);
    print("lhs", r);
    print("rhs", l);
    return false;
}

static void test_arithmetic() {
    decaf::SpongeRng rng(decaf::Block("test_arithmetic"));
    
    Test test("Arithmetic");
    Scalar x(0),y(0),z(0);
    arith_check(test,x,y,z,INT_MAX,(decaf_word_t)INT_MAX,"cast from max");
    arith_check(test,x,y,z,INT_MIN,-Scalar(1+(decaf_word_t)INT_MAX),"cast from min");
        
    for (int i=0; i<NTESTS*10 && test.passing_now; i++) {
        /* TODO: pathological cases */
        size_t sob = DECAF_255_SCALAR_BYTES + 8 - (i%16);
        Scalar x(rng.read(sob));
        Scalar y(rng.read(sob));
        Scalar z(rng.read(sob));
        

        arith_check(test,x,y,z,x+y,y+x,"commute add");
        arith_check(test,x,y,z,x,x+0,"ident add");
        arith_check(test,x,y,z,x,x-0,"ident sub");
        arith_check(test,x,y,z,x+(y+z),(x+y)+z,"assoc add");
        arith_check(test,x,y,z,x*(y+z),x*y + x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y-z),x*y - x*z,"distributive mul/add");
        arith_check(test,x,y,z,x*(y*z),(x*y)*z,"assoc mul");
        arith_check(test,x,y,z,x*y,y*x,"commute mul");
        arith_check(test,x,y,z,x,x*1,"ident mul");
        arith_check(test,x,y,z,0,x*0,"mul by 0");
        arith_check(test,x,y,z,-x,x*-1,"mul by -1");
        arith_check(test,x,y,z,x+x,x*2,"mul by 2");
        
        if (i%20) continue;
        if (y!=0) arith_check(test,x,y,z,x*y/y,x,"invert");
        arith_check(test,x,y,z,x/0,0,"invert0");
    }
}

static void test_elligator() {
    decaf::SpongeRng rng(decaf::Block("test_elligator"));
    Test test("Elligator");
    
    for (int i=0; i<32; i++) {
        decaf::SecureBuffer b1(Point::HASH_BYTES);
        Point p = Point::identity();
        for (int j=0; j<i/8; j++) p.debugging_torque_in_place();
        bool succ = p.invert_elligator(b1,i&7);
        Point q;
        unsigned char hint = q.set_to_hash(b1);
        
        if (succ != ((i&7) != 4) || (q != p) || (succ && (hint != (i&7)))) {
            test.fail();
            printf("Elligator test: t=%d, h=%d->%d, q%sp, %s %02x%02x\n",
                i/8, i&7, hint, (q==p)?"==":"!=",succ ? "SUCC" : "FAIL",
                b1[0], b1[1]);
        }
    }

    for (int i=0; i<NTESTS && (i<16 || test.passing_now); i++) {
        size_t len = (i % (2*Point::HASH_BYTES + 3));
        decaf::SecureBuffer b1(len), b2(len);
        rng.read(b1);
        if (i==1) b1[0] = 1; /* special case test */
        if (len > Point::HASH_BYTES)
            memcpy(&b2[Point::HASH_BYTES], &b1[Point::HASH_BYTES], len-Point::HASH_BYTES);
        Point s;
        unsigned char hint = s.set_to_hash(b1);
        for (int j=0; j<(i&3); j++) s.debugging_torque_in_place();
        bool succ = s.invert_elligator(b2,hint);
        if (!succ || memcmp(b1,b2,len)) {
            test.fail();
            printf("    Fail elligator inversion i=%d (claimed %s, hint=%d)\n",
                i, succ ? "success" : "failure", hint);
        }
        
        Point t(rng);
        point_check(test,t,t,t,0,0,t,Point::from_hash(t.steg_encode(rng)),"steg round-trip");
    }
}

static void test_ec() {
    decaf::SpongeRng rng(decaf::Block("test_ec"));
    
    Test test("EC");

    Point id = Point::identity(), base = Point::base();
    point_check(test,id,id,id,0,0,Point::from_hash(""),id,"fh0");
    //point_check(test,id,id,id,0,0,Point::from_hash("\x01"),id,"fh1"); FIXME
    
    for (int i=0; i<NTESTS && test.passing_now; i++) {
        /* TODO: pathological cases */
        Scalar x(rng);
        Scalar y(rng);
        Point p(rng);
        Point q(rng);
        
        decaf::SecureBuffer buffer(2*Point::HASH_BYTES);
        rng.read(buffer);
        Point r = Point::from_hash(buffer);
        
        point_check(test,p,q,r,0,0,p,Point((decaf::SecureBuffer)p),"round-trip");
        Point pp = p;
        (pp).debugging_torque_in_place();
        if (decaf::SecureBuffer(pp) != decaf::SecureBuffer(p)) {
            test.fail();
            printf("Fail torque seq test\n");
        }
        point_check(test,p,q,r,0,0,p,pp,"torque eq");
        point_check(test,p,q,r,0,0,p+q,q+p,"commute add");
        point_check(test,p,q,r,0,0,(p-q)+q,p,"correct sub");
        point_check(test,p,q,r,0,0,p+(q+r),(p+q)+r,"assoc add");
        point_check(test,p,q,r,0,0,p.times_two(),p+p,"dbl add");
        
        if (i%10) continue;
        point_check(test,p,q,r,x,0,x*(p+q),x*p+x*q,"distr mul");
        point_check(test,p,q,r,x,y,(x*y)*p,x*(y*p),"assoc mul");
        point_check(test,p,q,r,x,y,x*p+y*q,Point::double_scalarmul(x,p,y,q),"ds mul");
        point_check(test,base,q,r,x,y,x*base+y*q,q.non_secret_combo_with_base(y,x),"ds vt mul");
        point_check(test,p,q,r,x,0,Precomputed(p)*x,p*x,"precomp mul");
        point_check(test,p,q,r,0,0,r,
            Point::from_hash(buffer.slice(0,Point::HASH_BYTES))
            + Point::from_hash(buffer.slice(Point::HASH_BYTES,Point::HASH_BYTES)),
            "unih = hash+add"
        );
            

        point_check(test,p,q,r,x,0,Point(x.direct_scalarmul(decaf::SecureBuffer(p))),x*p,"direct mul");
    }
}

}; // template<decaf::GroupId GROUP>


static void test_decaf() {
    Test test("Sample crypto");
    decaf::SpongeRng rng(decaf::Block("test_decaf"));

    decaf_255_symmetric_key_t proto1,proto2;
    decaf_255_private_key_t s1,s2;
    decaf_255_public_key_t p1,p2;
    decaf_255_signature_t sig;
    unsigned char shared1[1234],shared2[1234];
    const char *message = "Hello, world!";

    for (int i=0; i<NTESTS && test.passing_now; i++) {
        rng.read(decaf::TmpBuffer(proto1,sizeof(proto1)));
        rng.read(decaf::TmpBuffer(proto2,sizeof(proto2)));
        decaf_255_derive_private_key(s1,proto1);
        decaf_255_private_to_public(p1,s1);
        decaf_255_derive_private_key(s2,proto2);
        decaf_255_private_to_public(p2,s2);
        if (!decaf_255_shared_secret (shared1,sizeof(shared1),s1,p2)) {
            test.fail(); printf("Fail ss12\n");
        }
        if (!decaf_255_shared_secret (shared2,sizeof(shared2),s2,p1)) {
            test.fail(); printf("Fail ss21\n");
        }
        if (memcmp(shared1,shared2,sizeof(shared1))) {
            test.fail(); printf("Fail ss21 == ss12\n");   
        }
        decaf_255_sign (sig,s1,(const unsigned char *)message,strlen(message));
        if (!decaf_255_verify (sig,p1,(const unsigned char *)message,strlen(message))) {
            test.fail(); printf("Fail sig ver\n");   
        }
    }
}

int main(int argc, char **argv) {
    (void) argc; (void) argv;
    
    Tests<decaf::Ed255>::test_arithmetic();
    Tests<decaf::Ed255>::test_elligator();
    Tests<decaf::Ed255>::test_ec();
    test_decaf();
    
    if (passing) printf("Passed all tests.\n");
    
    return passing ? 0 : 1;
}
