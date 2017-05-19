#ifndef TEST_CRYPTO_CM_H
#define TEST_CRYPTO_CM_H

#include "mbed.h"
#include "mbedtls/platform.h"
#include "crypto-misc.h"
#include "untriaged_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t test_buf1[1024];
extern uint8_t test_buf2[1024];
extern uint8_t test_buf3[1024];
#define MAXNUM_LOOP     1000

void test_hexstr_le2be(void);

#if defined(MBEDTLS_AES_C)
void test_aes(void);
#endif /* MBEDTLS_AES_C */
#if defined(MBEDTLS_GCM_C)
void test_aes_gcm(void);
#endif /* MBEDTLS_GCM_C */
#if defined(MBEDTLS_DES_C)
void test_des(void);
void test_des_cbc(void);
void test_des_perf(int ecb, uint32_t cbc_updatesize);
#endif /* MBEDTLS_DES_C */
#if defined(MBEDTLS_SHA1_C)
void test_sha1(void);
void test_sha1_nodata(void);
void test_sha1_random_updates(void);
void test_sha1_clone(uint32_t len1, uint32_t len2);
void test_sha1_perf(void);
#endif /* MBEDTLS_SHA1_C */
#if defined(MBEDTLS_SHA256_C)
void test_sha256(void);
void test_sha256_nodata(void);
void test_sha256_random_updates(void);
void test_sha256_clone(uint32_t len1, uint32_t len2);
void test_sha256_perf(int is224);
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
void test_sha512(void);
void test_sha512_nodata(void);
void test_sha512_random_updates(void);
void test_sha512_clone(uint32_t len1, uint32_t len2);
void test_sha512_perf(int is384);
#endif /* MBEDTLS_SHA512_C */

#if 1 && defined(MBEDTLS_ECP_C)
void test_ecp(void);

void test_ecp_secp192r1(void);
void test_ecp_secp384r1(void);
void test_ecp_secp521r1(void);

void test_ecp_curve25519(void);
void test_ecp_curve448(void);

#if 1 && defined(MBEDTLS_ECP_INTERNAL_ALT)
void test_ecp_internal_secp192r1(void);
void test_ecp_internal_secp384r1(void);
void test_ecp_internal_secp521r1(void);
#endif
#endif

#if 1 && defined(MBEDTLS_RSA_C)
void test_rsa(void);
void test_rsa_v15_1024(void);
void test_rsa_v15_1536(void);
void test_rsa_v15_2048(void);
void test_rsa_v15_3072(void);
void test_rsa_v15_4096(void);
void test_rsa_v21_1024(void);
void test_rsa_v21_1536(void);
void test_rsa_v21_2048(void);
void test_rsa_v21_3072(void);
void test_rsa_v21_4096(void);
#endif

#ifdef __cplusplus
}
#endif


#endif /* TEST_CRYPTO_CM_H */
