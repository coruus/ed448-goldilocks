/**
 * @cond internal
 * @file shakesum.c
 * @copyright
 *   Copyright (c) 2015 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @brief SHA3 utility, to be combined with test vectors eventually...
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "shake.h"

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    keccak_sponge_t sponge;
    unsigned char buf[1024];
    
    unsigned int outlen = 512;
    shake256_init(sponge);

    /* Sloppy.  Real utility would parse --algo, --size ... */
    if (argc > 1) {
        if (!strcmp(argv[1], "shake256") || !strcmp(argv[1], "SHAKE256")) {
            outlen = 512;
            shake256_init(sponge);
        } else if (!strcmp(argv[1], "shake128") || !strcmp(argv[1], "SHAKE128")) {
            outlen = 512;
            shake128_init(sponge);
        } else if (!strcmp(argv[1], "sha3-224") || !strcmp(argv[1], "SHA3-224")) {
            outlen = 224/8;
            sha3_224_init(sponge);
        } else if (!strcmp(argv[1], "sha3-256") || !strcmp(argv[1], "SHA3-256")) {
            outlen = 256/8;
            sha3_256_init(sponge);
        } else if (!strcmp(argv[1], "sha3-384") || !strcmp(argv[1], "SHA3-384")) {
            outlen = 384/8;
            sha3_384_init(sponge);
        } else if (!strcmp(argv[1], "sha3-512") || !strcmp(argv[1], "SHA3-512")) {
            outlen = 512/8;
            sha3_512_init(sponge);
        }
    }

    ssize_t red;
    do {
        red = read(0, buf, sizeof(buf));
        if (red>0) sha3_update(sponge,buf,red);
    } while (red>0);

    sha3_output(sponge,buf,outlen);
    sponge_destroy(sponge);
    unsigned i;
    for (i=0; i<outlen; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    return 0;
}
