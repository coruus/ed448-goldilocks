#ifndef __GOLDILOCKS_TEST_H__
#define __GOLDILOCKS_TEST_H__ 1

#include "word.h"
#include "p448.h"

int
hexdecode (
    unsigned char *bytes,
    const char *hex,
    unsigned int nbytes
);

void
hexprint (
    const char *descr,
    const unsigned char *bytes,
    unsigned int nbytes
);
    
void p448_print (
    const char *descr,
    const struct p448_t *a
);
    
void scalar_print (
    const char *descr,
    const word_t *scalar,
    int nwords
);

void youfail();

int test_sha512_monte_carlo();

int test_linear_combo ();

int test_scalarmul_compatibility ();

int test_scalarmul_commutativity ();

int test_arithmetic ();

int test_goldilocks ();

int test_pointops ();

#endif // __GOLDILOCKS_TEST_H__
