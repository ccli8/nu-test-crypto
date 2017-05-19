#ifndef UNTRIAGED_UTILS_H
#define UNTRIAGED_UTILS_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Convert hexadecimal string from big-endian to little-endian */
int hexstr_le2be(char *be, size_t be_maxsize, const char *le);

/* Trivial random number generator for RSA/ECP blinding */
int unsafe_rand(void *rng_state, unsigned char *output, size_t len);

/* Dump binary in C-array hexadecimal format */
void dump_bin(const unsigned char *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* UNTRIAGED_UTILS_H */
