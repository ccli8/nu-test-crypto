#include "mbed.h"
#include "mbedtls/des.h"

#include "test_crypto_cm.h"

#if defined(MBEDTLS_DES_C)

void test_des(void)
{
    if (mbedtls_des_self_test(1)) {
        printf("mbedtls_des_self_test failed\n\n");
    }
    else {
        printf("mbedtls_des_self_test passed\n\n");
    }
}



static const unsigned char des3_test_keys[24] =
{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
    0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
};

static const unsigned char des3_test_iv[8] =
{
    0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
};

void test_des_cbc(void)
{
#if defined(MBEDTLS_CIPHER_MODE_CBC)
#if defined(MBEDTLS_DES_ALT)
    
    mbedtls_des_context ctx;
    mbedtls_des3_context ctx3;
    mbedtls_des_sw_context ctx_sw;
    mbedtls_des3_sw_context ctx3_sw;
    unsigned char iv[8], iv_sw[8];

    mbedtls_des_init(&ctx);
    mbedtls_des3_init(&ctx3);
    mbedtls_des_sw_init(&ctx_sw);
    mbedtls_des3_sw_init(&ctx3_sw);
  
    unsigned i, j;
    
    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf3[j] = (j * j) & 0xFF;
    }
    for( i = 0; i < 6; i++ )
    {
        int des3 = i >> 1;
        int isenc = i & 1;
        
        switch (i)
        {
        case 0:
            mbedtls_des_setkey_dec(&ctx, des3_test_keys);
            mbedtls_des_sw_setkey_dec(&ctx_sw, des3_test_keys);
            break;

        case 1:
            mbedtls_des_setkey_enc(&ctx, des3_test_keys);
            mbedtls_des_sw_setkey_enc(&ctx_sw, des3_test_keys);
            break;

        case 2:
            mbedtls_des3_set2key_dec(&ctx3, des3_test_keys);
            mbedtls_des3_sw_set2key_dec(&ctx3_sw, des3_test_keys);
            break;

        case 3:
            mbedtls_des3_set2key_enc(&ctx3, des3_test_keys);
            mbedtls_des3_sw_set2key_enc(&ctx3_sw, des3_test_keys);
            break;

        case 4:
            mbedtls_des3_set3key_dec(&ctx3, des3_test_keys);
            mbedtls_des3_sw_set3key_dec(&ctx3_sw, des3_test_keys);
            break;

        case 5:
            mbedtls_des3_set3key_enc(&ctx3, des3_test_keys);
            mbedtls_des3_sw_set3key_enc(&ctx3_sw, des3_test_keys);
            break;
        }

        unsigned char *in_pos, *out1_pos, *out2_pos;
        memcpy( iv,  des3_test_iv,  8 );
        memcpy( iv_sw,  des3_test_iv,  8 );
                
        in_pos = test_buf3;
        out1_pos = test_buf1;
        out2_pos = test_buf2;
                
        uint16_t lengths[] = {8, 16, 40, 80, 240};
        if (! isenc)
        {
            if (! des3) {
                for (j = 0; j < sizeof (lengths) / sizeof (lengths[0]); j++) {
                    uint16_t len = lengths[j];
                    
                    mbedtls_des_crypt_cbc(&ctx, isenc, len, iv, in_pos, out1_pos);
                    mbedtls_des_sw_crypt_cbc(&ctx_sw, isenc, len, iv_sw, in_pos, out2_pos);
                    in_pos += len;
                    out1_pos += len;
                    out2_pos += len;
                }
            }
            else {
                for (j = 0; j < sizeof (lengths) / sizeof (lengths[0]); j++) {
                    uint16_t len = lengths[j];
                    
                    mbedtls_des3_crypt_cbc(&ctx3, isenc, len, iv, in_pos, out1_pos);
                    mbedtls_des3_sw_crypt_cbc(&ctx3_sw, isenc, len, iv_sw, in_pos, out2_pos);
                    in_pos += len;
                    out1_pos += len;
                    out2_pos += len;
                }
            }
        }
        else
        {
            if (! des3) {
                for (j = 0; j < sizeof (lengths) / sizeof (lengths[0]); j++) {
                    uint16_t len = lengths[j];
                    
                    mbedtls_des_crypt_cbc(&ctx, isenc, len, iv, in_pos, out1_pos);
                    mbedtls_des_sw_crypt_cbc(&ctx_sw, isenc, len, iv_sw, in_pos, out2_pos);
                    in_pos += len;
                    out1_pos += len;
                    out2_pos += len;
                }
            }
            else {
                for (j = 0; j < sizeof (lengths) / sizeof (lengths[0]); j++) {
                    uint16_t len = lengths[j];
                    
                    mbedtls_des3_crypt_cbc(&ctx3, isenc, len, iv, in_pos, out1_pos);
                    mbedtls_des3_sw_crypt_cbc(&ctx3_sw, isenc, len, iv_sw, in_pos, out2_pos);
                    in_pos += len;
                    out1_pos += len;
                    out2_pos += len;
                }
            }
        }

        int isok = memcmp(test_buf1, test_buf2, out1_pos - test_buf1) == 0 ? 1 : 0;
        
        printf("DES%c-CBC-%3d (%s): %s\n\n", des3 ? '3' : ' ', 56 + des3 * 56, isenc ? "enc" : "dec", 
                isok ? "passed" : "failed");
    }

    mbedtls_des_free(&ctx);
    mbedtls_des3_free(&ctx3);
    mbedtls_des_sw_free(&ctx_sw);
    mbedtls_des3_sw_free(&ctx3_sw);
#endif /* MBEDTLS_DES_ALT */
#endif /* MBEDTLS_CIPHER_MODE_CBC */
}

void test_des_perf(int ecb, uint32_t cbc_updatesize)
{
    mbedtls_des_context ctx;
    mbedtls_des3_context ctx3;
    
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    unsigned char iv[8];
#endif

    mbedtls_des_init(&ctx);
    mbedtls_des3_init(&ctx3);
    
    Timer t1;
    unsigned i, j;
    
    /* ECB mode */
    if (! ecb) {
        goto CBC;
    }
    for (i = 0; i < 6; i ++) {
        t1.reset();
        t1.start();
        
        int des3 = i >> 1;
        int isenc = i & 1;
        
        memset(test_buf1, 'a', 8);
        
        switch (i)
        {
        case 0:
            mbedtls_des_setkey_dec(&ctx, des3_test_keys);
            break;

        case 1:
            mbedtls_des_setkey_enc(&ctx, des3_test_keys);
            break;

        case 2:
            mbedtls_des3_set2key_dec(&ctx3, des3_test_keys);
            break;

        case 3:
            mbedtls_des3_set2key_enc(&ctx3, des3_test_keys);
            break;

        case 4:
            mbedtls_des3_set3key_dec(&ctx3, des3_test_keys);
            break;

        case 5:
            mbedtls_des3_set3key_enc(&ctx3, des3_test_keys);
            break;
        }
        
        for (j = 0; j < MAXNUM_LOOP; j ++)
        {
            if (! des3) {
                mbedtls_des_crypt_ecb(&ctx, test_buf1, test_buf2);
            }
            else {
                mbedtls_des3_crypt_ecb(&ctx3, test_buf1, test_buf2);
            }
        }
        
        t1.stop();
        
        printf("DES%c-ECB-%3d (%s)(upd-sz=8): %d (KB/s)\n\n", des3 ? '3' : ' ', 56 + des3 * 56, isenc ? "enc" : "dec", 
                8 * MAXNUM_LOOP / t1.read_ms());
    }
    
CBC:
    if (! cbc_updatesize) {
        goto END;
    }
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    /* CBC mode */
    MBED_ASSERT((cbc_updatesize % 8) == 0);
    
    for( i = 0; i < 6; i++ )
    {
        t1.reset();
        t1.start();
        
        int des3 = i >> 1;
        int isenc = i & 1;
        
        memset(test_buf1, 'a', cbc_updatesize);

        memcpy(iv,  des3_test_iv, 8);

        switch (i)
        {
        case 0:
            mbedtls_des_setkey_dec(&ctx, des3_test_keys);
            break;

        case 1:
            mbedtls_des_setkey_enc(&ctx, des3_test_keys);
            break;

        case 2:
            mbedtls_des3_set2key_dec(&ctx3, des3_test_keys);
            break;

        case 3:
            mbedtls_des3_set2key_enc(&ctx3, des3_test_keys);
            break;

        case 4:
            mbedtls_des3_set3key_dec(&ctx3, des3_test_keys);
            break;

        case 5:
            mbedtls_des3_set3key_enc(&ctx3, des3_test_keys);
            break;
        }

        if (! isenc)
        {
            for (j = 0; j < MAXNUM_LOOP; j++)
            {
                if (! des3) {
                    mbedtls_des_crypt_cbc(&ctx, isenc, cbc_updatesize, iv, test_buf1, test_buf2);
                }
                else {
                    mbedtls_des3_crypt_cbc(&ctx3, isenc, cbc_updatesize, iv, test_buf1, test_buf2);
                }
            }
        }
        else
        {
            for (j = 0; j < MAXNUM_LOOP; j++)
            {
                if (! des3) {
                    mbedtls_des_crypt_cbc(&ctx, isenc, cbc_updatesize, iv, test_buf1, test_buf2);
                }
                else {
                    mbedtls_des3_crypt_cbc(&ctx3, isenc, cbc_updatesize, iv, test_buf1, test_buf2);
                }
            }
        }

        t1.stop();
        
        printf("DES%c-CBC-%3d (%s)(upd-sz=%d): %d (KB/s)\n\n", des3 ? '3' : ' ', 56 + des3 * 56, isenc ? "enc" : "dec", 
                cbc_updatesize, cbc_updatesize * MAXNUM_LOOP / t1.read_ms());
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */

END:
    mbedtls_des_free(&ctx);
    mbedtls_des3_free(&ctx3);
}

#endif /* MBEDTLS_DES_C */
