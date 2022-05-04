/*
 *  Hello world example of using the authenticated encryption with mbed TLS
 *
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbed.h"

/*
#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls/platform.h"

#include <string.h>
*/
#include "test_crypto_cm.h"

uint8_t test_buf1[1024];
uint8_t test_buf2[1024];
uint8_t test_buf3[1024];

int main() {
    printf("nu-crypto ...\n\n");

#if 0 && defined(MBEDTLS_AES_C)
    test_aes();
#endif

#if 0 && defined(MBEDTLS_DES_C)
    test_des();
    test_des_cbc();
    test_des_perf(1, 0);
    test_des_perf(0, 8);
    test_des_perf(0, 8 * 10);
#endif

#if 0 && defined(MBEDTLS_SHA1_C)
    test_sha1();
    test_sha1_nodata();
    test_sha1_random_updates();

    test_sha1_clone(0, 0);
    test_sha1_clone(0, 63);
    test_sha1_clone(0, 64);
    test_sha1_clone(0, 65);
    test_sha1_clone(0, 128);

    test_sha1_clone(63, 0);
    test_sha1_clone(63, 63);
    test_sha1_clone(63, 64);
    test_sha1_clone(63, 65);
    test_sha1_clone(63, 128);

    test_sha1_clone(64, 0);
    test_sha1_clone(64, 63);
    test_sha1_clone(64, 64);
    test_sha1_clone(64, 65);
    test_sha1_clone(64, 128);

    test_sha1_clone(65, 0);
    test_sha1_clone(65, 63);
    test_sha1_clone(65, 64);
    test_sha1_clone(65, 65);
    test_sha1_clone(65, 128);

    test_sha1_clone(128, 0);
    test_sha1_clone(128, 63);
    test_sha1_clone(128, 64);
    test_sha1_clone(128, 65);
    test_sha1_clone(128, 128);

    test_sha1_perf();
#endif

#if 0 && defined(MBEDTLS_SHA256_C)
    test_sha256();
    test_sha256_nodata();
    test_sha256_random_updates();
    
    test_sha256_clone(0, 0);
    test_sha256_clone(0, 63);
    test_sha256_clone(0, 64);
    test_sha256_clone(0, 65);
    test_sha256_clone(0, 128);
    
    test_sha256_clone(63, 0);
    test_sha256_clone(63, 63);
    test_sha256_clone(63, 64);
    test_sha256_clone(63, 65);
    test_sha256_clone(63, 128);
    
    test_sha256_clone(64, 0);
    test_sha256_clone(64, 63);
    test_sha256_clone(64, 64);
    test_sha256_clone(64, 65);
    test_sha256_clone(64, 128);
    
    test_sha256_clone(65, 0);
    test_sha256_clone(65, 63);
    test_sha256_clone(65, 64);
    test_sha256_clone(65, 65);
    test_sha256_clone(65, 128);

    test_sha256_clone(128, 0);
    test_sha256_clone(128, 63);
    test_sha256_clone(128, 64);
    test_sha256_clone(128, 65);
    test_sha256_clone(128, 128);

    test_sha256_perf(0);
    test_sha256_perf(1);
#endif

#if 0 && defined(MBEDTLS_SHA512_C)
    test_sha512();
    test_sha512_nodata();
    test_sha512_random_updates();

    test_sha512_clone(0, 0);
    test_sha512_clone(0, 63);
    test_sha512_clone(0, 64);
    test_sha512_clone(0, 65);
    test_sha512_clone(0, 128);

    test_sha512_clone(63, 0);
    test_sha512_clone(63, 63);
    test_sha512_clone(63, 64);
    test_sha512_clone(63, 65);
    test_sha512_clone(63, 128);

    test_sha512_clone(64, 0);
    test_sha512_clone(64, 63);
    test_sha512_clone(64, 64);
    test_sha512_clone(64, 65);
    test_sha512_clone(64, 128);

    test_sha512_clone(65, 0);
    test_sha512_clone(65, 63);
    test_sha512_clone(65, 64);
    test_sha512_clone(65, 65);
    test_sha512_clone(65, 128);

    test_sha512_clone(128, 0);
    test_sha512_clone(128, 63);
    test_sha512_clone(128, 64);
    test_sha512_clone(128, 65);
    test_sha512_clone(128, 128);

    test_sha512_perf(0);
    test_sha512_perf(1);
#endif

#if 0 && defined(MBEDTLS_ECP_C)
    test_ecp();
    test_ecp_secp192r1();
    test_ecp_secp384r1();
    test_ecp_secp521r1();

#if 0 && defined(MBEDTLS_ECP_INTERNAL_ALT)
    /* Test add/double/mul with R = m*P + n*Q */
    test_ecp_internal_secp192r1();
    test_ecp_internal_secp384r1();
    test_ecp_internal_secp521r1();
#endif  /* MBEDTLS_ECP_INTERNAL_ALT */

#endif /* MBEDTLS_ECP_C */

#if 1 && defined(MBEDTLS_RSA_C)
    //test_rsa();
    test_rsa_v15_1024();
    //test_rsa_v15_1536();
    //test_rsa_v15_2048();
    //test_rsa_v15_3072();
    //test_rsa_v15_4096();
    //test_rsa_v21_1024();
    //test_rsa_v21_1536();
    //test_rsa_v21_2048();
    //test_rsa_v21_3072();
    //test_rsa_v21_4096();
#endif /* MBEDTLS_RSA_C */

    printf("nu-crypto ... END\n\n");
    
    while (1);
}
