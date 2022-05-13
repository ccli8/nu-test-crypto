#ifndef TESTVECTOR_GCM_H
#define TESTVECTOR_GCM_H

#include "mbedtls/gcm.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_GCM_C)

typedef struct {
    char            name[80];
    int             cipher;
    unsigned char   key[32];
    size_t          key_len;
    unsigned char   iv[16];
    size_t          iv_len;
    unsigned char   add[16];
    size_t          add_len;
    unsigned char   tag[16];
    size_t          tag_len;
    unsigned char   plaintext[500];
    unsigned char   ciphertext[500];
    size_t          text_len;
} testvector_gcm_t;

extern const testvector_gcm_t testvector_aes_gcm[];

#endif  /* MBEDTLS_GCM_C */

#ifdef __cplusplus
}
#endif


#endif /* TESTVECTOR_GCM_H */
