#ifndef GOLDI_HASH_H
#define GOLDI_HASH_H
#include "config.h"
#include "keccakc/keccak.h"

#define hash_ctx_t keccak_sponge
#if GOLDILOCKS_SHAKE == 128
#define hash_init shake128_init
#define hash_update shake128_update
#define hash_digest shake128_digest
#define HASH_NAME "SHAKE128"
#elif GOLDILOCKS_SHAKE == 256
#define hash_init shake256_init
#define hash_update shake256_update
#define hash_digest shake256_digest
#define HASH_NAME "SHAKE256"
#else
#error--
#endif

#endif  // GOLDI_HASH_H
