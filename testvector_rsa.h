#ifndef TESTVECTOR_RSA_H
#define TESTVECTOR_RSA_H

#include "mbedtls/rsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_RSA_C)

/**
 * \brief       Max RSA key size in hexadecimal string form
 *
 * \note        Extra 8 to fit Mbed TLS MPI's over-estimated buffer size,
 *              e.g. mbedtls_mpi_write_string().
 * \note        Not include ending NULL character.
 */
#define MYRSA_MAXKEY_CHAR   ((4096 / 4) + 8)

typedef struct {
    char        name[64 + 1];
    int         md_alg;
    char        salt[MYRSA_MAXKEY_CHAR + 1];
    char        msg[MYRSA_MAXKEY_CHAR + 1];
    char        sig[MYRSA_MAXKEY_CHAR + 1];
} testvector_rsa_signature_t;

typedef struct {
    char        name[64 + 1];
    int         padding;
    size_t      keybits;
    char        n[MYRSA_MAXKEY_CHAR + 1];
    char        e[MYRSA_MAXKEY_CHAR + 1];
    char        d[MYRSA_MAXKEY_CHAR + 1];
    testvector_rsa_signature_t  sig_arr[5];
} testvector_rsa_t;

extern const testvector_rsa_t testvector_rsa_v15_1024;
extern const testvector_rsa_t testvector_rsa_v15_1536;
extern const testvector_rsa_t testvector_rsa_v15_2048;
extern const testvector_rsa_t testvector_rsa_v15_3072;
extern const testvector_rsa_t testvector_rsa_v15_4096;

extern const testvector_rsa_t testvector_rsa_v21_1024;
extern const testvector_rsa_t testvector_rsa_v21_1536;
extern const testvector_rsa_t testvector_rsa_v21_2048;
extern const testvector_rsa_t testvector_rsa_v21_3072;
extern const testvector_rsa_t testvector_rsa_v21_4096;

#endif  /* MBEDTLS_RSA_C */

#ifdef __cplusplus
}
#endif


#endif /* TESTVECTOR_RSA_H */
