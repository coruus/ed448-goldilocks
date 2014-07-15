#ifndef KECCAK_UTILS_PRINT_IMPL_H
#define KECCAK_UTILS_PRINT_IMPL_H
// TODO(dlg): refactor to use fprintf everywhere

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ifnotmod(I, MODULUS, STATEMENT) \
  if ((I % MODULUS == 0) && (I != 0)) { \
    STATEMENT;                          \
  }

#define printbyte(byte)   \
  if (byte != 0) {        \
    printf("%02x", byte); \
  } else {                \
    printf("--", byte);   \
  }

static inline void _printbuf(const void* const buf, register const size_t buflen) {
  register const uint8_t* const bytes = (uint8_t*)buf;
  for (size_t i = 0; i < buflen; i++) {
    ifnotmod(i, 16, printf(" "));
    ifnotmod(i, 16 * 4, printf("\n"));
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

#define printbuf(BUF, BUFLEN)         \
  printf("%s (%u):\n", #BUF, BUFLEN); \
  _printbuf(BUF, BUFLEN);

static inline void _printstateLE(uint64_t a[25]) {
  uint8_t buf[25 * 8];
  memcpy(buf, a, 25 * 8);
  for (int i = 0; i < 200; i++) {
    ifnotmod(i, 8, printf(" ")) ifnotmod(i, 40, printf("\n")) printbyte(buf[i]);
  }
  printf("\n");
}

static inline void _printstateBE(uint64_t a[25]) {
  for (int i = 0; i < 25; i++) {
    ifnotmod(i, 5, printf("\n"));
    printf("%016llx ", a[i]);
  }
  printf("\n");
}

static inline void fprintbits_le(FILE* const restrict file,
                                 const uint8_t* const restrict in,
                                 const size_t inlen) {
  for (size_t i = 0; i < inlen; i++) {
    ifnotmod(i, 4, printf("\n"));
    for (int mask = 1; mask < 256; mask <<= 1) {
      fprintf(file, "%x", (in[i] & mask) && 1);
    }
    printf(" ");
  }
}

#define printbits(IN, INLEN) fprintbits_le(stdout, IN, INLEN)

#define _printstate _printstateLE
#define printstate(STATE)  \
  printf("%s:\n", #STATE); \
  _printstate(STATE);

static const size_t statelen = 25;

static inline void printinit_state(register const uint64_t* const restrict state,
                                   register const char* const restrict varname) {
  printf("static const uint64_t %s[25] = { ", varname);
  for (size_t i = 0; i < (statelen - 1); i++) {
    ifnotmod(i, 5, printf("\n"));
    printf("0x%016llxULL, ", state[i]);
  }
  printf("0x%016llxULL };\n", state[statelen - 1]);
}

static inline void printinit_buf(register const uint8_t* const restrict buf,
                                 register const size_t buflen,
                                 register const char* const restrict varname) {
  printf("static const uint8_t %s[%zu] = { ", varname, buflen);
  for (size_t i = 0; i < (buflen - 1); i++) {
    ifnotmod(i, 4, printf("\n"));
    printf("0x%02x, ", buf[i]);
  }
  printf("0x%02x };\n", buf[buflen - 1]);
}

#define printinit_bytes printinit_buf

#endif  // KECCAK_UTILS_PRINT_IMPL_H
