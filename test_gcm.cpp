#include "mbed.h"
#include "mbedtls/gcm.h"

#if defined(MBEDTLS_GCM_C)

#include "mbedtls/error.h"
#include "test_crypto_cm.h"
#include "testvector_gcm.h"

static void print_bin(const unsigned char *data, size_t length);

void test_aes_gcm(void)
{
    Timer t;

    /* Intermediary buffers can be too large for stack to accommodate.
     * Change to static for safe, implying this function is non-reentrant. */
    static unsigned char    tag_act[sizeof(((testvector_gcm_t){0}).tag)];                   // Temp buffer to hold calculated tag
    static unsigned char    plaintext_act[sizeof(((testvector_gcm_t){0}).plaintext)];       // Temp buffer to hold decrypted plaintext
    static unsigned char    ciphertext_act[sizeof(((testvector_gcm_t){0}).ciphertext)];     // Temp buffer to hold encrypted ciphertext

    printf("Testing AES-GCM\n\n");

    /* Time measurement starts */
    t.start();

    mbedtls_gcm_context ctx;

    const testvector_gcm_t *tstgcm = testvector_aes_gcm;
    int tst_error = 0;

    while (1) {
        const char *tstgcm_name = tstgcm->name;

        /* Check whether or not end of test signature list */
        if (strlen(tstgcm_name) == 0) {
            break;
        }

        printf("  Testing %s ... \n", tstgcm_name);

        int ret = 0;

        /* Initialize GCM context */
        mbedtls_gcm_init(&ctx);

        /* Configure encryption key */
        if (ret == 0) {
            ret = mbedtls_gcm_setkey(&ctx,
                                     (mbedtls_cipher_id_t) tstgcm->cipher,
                                     tstgcm->key,
                                     tstgcm->key_len * 8);
            if (ret != 0) {
                printf("    mbedtls_gcm_setkey() encrypt key failed: -0x%08x\n", -ret);
            }
        }

        /* Encrypt */
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&ctx,
                                            MBEDTLS_GCM_ENCRYPT,
                                            tstgcm->text_len,
                                            tstgcm->iv, tstgcm->iv_len,
                                            tstgcm->add, tstgcm->add_len,
                                            tstgcm->plaintext,
                                            ciphertext_act,
                                            tstgcm->tag_len, tag_act);
            if (ret != 0) {
                printf("    mbedtls_gcm_crypt_and_tag() encrypt failed: -0x%08x\n", -ret);
            }
        }

        /* Verify encrypted ciphertext */
        if (ret == 0) {
            if (memcmp(ciphertext_act, tstgcm->ciphertext, tstgcm->text_len) != 0) {
                printf("    encrypted ciphertext error\n");
                ret = -1;
            }
        }

        /* Verify encrypted tag */
        if (ret == 0) {
            if (memcmp(tag_act, tstgcm->tag, tstgcm->tag_len) != 0) {
                printf("    encrypted tag error\n");
                ret = -1;
            }
        }

        /* Free GCM context */
        mbedtls_gcm_free(&ctx);

        /* Initialize GCM context */
        mbedtls_gcm_init(&ctx);

        /* Configure decryption key */
        if (ret == 0) {
            ret = mbedtls_gcm_setkey(&ctx,
                                     (mbedtls_cipher_id_t) tstgcm->cipher,
                                     tstgcm->key,
                                     tstgcm->key_len * 8);
            if (ret != 0) {
                printf("    mbedtls_gcm_setkey() decrypt key failed: -0x%08x\n", -ret);
            }
        }

        /* Decrypt */
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT,
                                            tstgcm->text_len,
                                            tstgcm->iv, tstgcm->iv_len,
                                            tstgcm->add, tstgcm->add_len,
                                            tstgcm->ciphertext,
                                            plaintext_act,
                                            tstgcm->tag_len, tag_act);
            if (ret != 0) {
                printf("    mbedtls_gcm_crypt_and_tag() decrypt failed: -0x%08x\n", -ret);
            }
        }

        /* Verify decrypted plaintext */
        if (ret == 0) {
            if (memcmp(plaintext_act, tstgcm->plaintext, tstgcm->text_len) != 0) {
                printf("    decrypted plaintext error\n");
                ret = -1;
            }
        }

        /* Verify decrypted tag */
        if (ret == 0) {
            if (memcmp(tag_act, tstgcm->tag, tstgcm->tag_len) != 0) {
                printf("    decrypted tag error\n");
                ret = -1;
            }
        }

        /* Free GCM context */
        mbedtls_gcm_free(&ctx);

        /* Accumulate error count */
        if (ret != 0) {
            tst_error ++;
        }

        printf("  Testing %s ... %s\n", tstgcm_name, ret == 0 ? "OK" : "Error");

        /* Next test */
        tstgcm ++;
    }

cleanup:

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting AES-GCM (%d ms) %s\n\n", ms, (tst_error ? "FAILED" : "OK"));
}

static void print_bin(const unsigned char *data, size_t length)
{
    size_t rmn = length;

    while (rmn >= 8) {
        printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
               data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
        data += 8;
        rmn -= 8;
    }

    if (rmn >= 4) {
        printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, ", data[0], data[1], data[2], data[3]);
        data += 4;
        rmn -= 4;
    }

    if (rmn >= 2) {
        printf("0x%02x, 0x%02x, ", data[0], data[1]);
        data += 2;
        rmn -= 2;
    }

    if (rmn) {
        printf("0x%02x, ", data[0]);
        data += 1;
        rmn -= 1;
    }

    printf("\n");
}

#endif /* MBEDTLS_GCM_C */
