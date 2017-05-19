#include "mbed.h"
#include "mbedtls/aes.h"

#include "test_crypto_cm.h"

#if defined(MBEDTLS_AES_C)

void test_aes(void)
{
    if (mbedtls_aes_self_test(1)) {
        printf("mbedtls_aes_self_test failed\n\n");
    }
    else {
        printf("mbedtls_aes_self_test passed\n\n");
    }
}

#endif /* MBEDTLS_AES_C */
