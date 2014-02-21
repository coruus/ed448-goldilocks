/* Copyright (c) 2011 Stanford University.
 * Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/* A miniature version of the (as of yet incomplete) crandom project. */

#ifndef __GOLDI_CRANDOM_H__
#define __GOLDI_CRANDOM_H__ 1

#include <stdint.h>  /* for uint64_t */
#include <fcntl.h>   /* for open */
#include <errno.h>   /* for returning errors after open */
#include <stdlib.h>  /* for abort */
#include <string.h>  /* for memcpy */
#include <strings.h> /* for bzero */
#include <unistd.h>  /* for read */

struct crandom_state_t {
    unsigned char seed[32];
    unsigned char buffer[96];
    uint64_t ctr;
    uint64_t magic;
    unsigned int fill;
    int reseed_countdown;
    int reseed_interval;
    int reseeds_mandatory;
    int randomfd;
} __attribute__((aligned(16))) ;

#ifdef __cplusplus
extern "C" {
#endif

int
crandom_init_from_file(
    struct crandom_state_t *state,
    const char *filename,
    int reseed_interval,
    int reseeds_mandatory
) __attribute__((warn_unused_result));

void
crandom_init_from_buffer(
    struct crandom_state_t *state,
    const char initial_seed[32]
);

/* TODO : attribute warn for not checking return type? */
int
crandom_generate(
    struct crandom_state_t *state,
    unsigned char *output,
    unsigned long long length
);

void
crandom_destroy(
    struct crandom_state_t *state
);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __GOLDI_CRANDOM_H__ */
