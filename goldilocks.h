/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#ifndef __GOLDILOCKS_H__
#define __GOLDILOCKS_H__ 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int
goldilocks_init();

int
goldilocks_keygen(
    uint8_t private[56],
    uint8_t public[56]
);

int
goldilocks_shared_secret(
    uint8_t shared[56],
    const uint8_t private[56],
    const uint8_t public[56]
);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __GOLDILOCKS_H__ */
