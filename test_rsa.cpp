#include "mbed.h"
#include "mbedtls/rsa.h"

#if defined(MBEDTLS_RSA_C)

#include "mbedtls/error.h"
#include "test_crypto_cm.h"
#include "testvector_rsa.h"

static int myrand( void *rng_state, unsigned char *output, size_t len );
static void test_rsa_sub(const testvector_rsa_t *tstit);
                            
void test_rsa(void)
{
    if (mbedtls_rsa_self_test(1)) {
        printf("mbedtls_rsa_self_test failed\n\n");
    }
    else {
        printf("mbedtls_rsa_self_test passed\n\n");
    }
}

/* PKCS#1 V15 1024/1536/2048/3072/4096 */
void test_rsa_v15_1024(void)
{
    test_rsa_sub(&testvector_rsa_v15_1024);
}

void test_rsa_v15_1536(void)
{
    test_rsa_sub(&testvector_rsa_v15_1536);
}

void test_rsa_v15_2048(void)
{
    test_rsa_sub(&testvector_rsa_v15_2048);
}

void test_rsa_v15_3072(void)
{
    test_rsa_sub(&testvector_rsa_v15_3072);
}

void test_rsa_v15_4096(void)
{
    test_rsa_sub(&testvector_rsa_v15_4096);
}

/* PKCS#1 V21 1024/1536/2048/3072/4096 */
void test_rsa_v21_1024(void)
{
    test_rsa_sub(&testvector_rsa_v21_1024);
}

void test_rsa_v21_1536(void)
{
    test_rsa_sub(&testvector_rsa_v21_1536);
}

void test_rsa_v21_2048(void)
{
    test_rsa_sub(&testvector_rsa_v21_2048);
}

void test_rsa_v21_3072(void)
{
    test_rsa_sub(&testvector_rsa_v21_3072);
}

void test_rsa_v21_4096(void)
{
    test_rsa_sub(&testvector_rsa_v21_4096);
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

static void test_rsa_sub(const testvector_rsa_t *tstit)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    Timer t;

    /* Intermediary buffers can be too large for stack to accommodate.
     * Change to static for safe, implying this function is non-reentrant. */
    static unsigned char    msg_bin[MBEDTLS_MPI_MAX_SIZE];          // Temp buffer to hold message in binary form
    static size_t           msg_bin_len;
    static unsigned char    md_sum[64];                             // Temp buffer to hold message digest
    static unsigned char    sig_act_bin[MBEDTLS_MPI_MAX_SIZE];      // Temp buffer to hold calculated signature in binary form
    static unsigned char    sig_exp_bin[MBEDTLS_MPI_MAX_SIZE];      // Temp buffer to hold expected signature in binary form
    static char             sig_act_hexstr[MYRSA_MAXKEY_CHAR + 1];  // Temp buffer to hold calculated signature in hex string form
    static size_t           sig_act_hexstr_len;                     // Actual length of above, including NULL char
    static char             ctxkey_hexstr[MYRSA_MAXKEY_CHAR + 1];   // Temp buffer to hold context key in hex string form
    static size_t           ctxkey_hexstr_len;                      // Actual length of above, including NULL char

    printf("Testing %s\n", tstit->name);

    /* Time measurement starts */
    t.start();

    mbedtls_mpi K;
    mbedtls_rsa_context rsa;

    mbedtls_mpi_init( &K );
    mbedtls_rsa_init( &rsa, tstit->padding, 0 );

    const testvector_rsa_signature_t *tstsig;

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, tstit->n  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, &K, NULL, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, tstit->e  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, NULL, &K ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, tstit->d  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, &K, NULL ) );

    /* The key deduction can take long time. Skip elapsed time for it. */
    t.stop();
    MBEDTLS_MPI_CHK( mbedtls_rsa_complete( &rsa ) );
    t.start();

    MBEDTLS_MPI_CHK(tstit->keybits == (rsa.len * 8) ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);
    printf("N (modulus): %d bits (%d bytes)\n\n", rsa.len * 8, rsa.len);

    /* Dump key context */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&rsa.N, 16, ctxkey_hexstr, sizeof(ctxkey_hexstr), &ctxkey_hexstr_len));
    printf("N: \n%s\n", ctxkey_hexstr);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&rsa.E, 16, ctxkey_hexstr, sizeof(ctxkey_hexstr), &ctxkey_hexstr_len));
    printf("E: \n%s\n", ctxkey_hexstr);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&rsa.D, 16, ctxkey_hexstr, sizeof(ctxkey_hexstr), &ctxkey_hexstr_len));
    printf("D: \n%s\n", ctxkey_hexstr);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&rsa.P, 16, ctxkey_hexstr, sizeof(ctxkey_hexstr), &ctxkey_hexstr_len));
    printf("P: \n%s\n", ctxkey_hexstr);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&rsa.Q, 16, ctxkey_hexstr, sizeof(ctxkey_hexstr), &ctxkey_hexstr_len));
    printf("Q: \n%s\n", ctxkey_hexstr);

    printf("\n");

    tstsig = &(tstit->sig_arr[0]);

    while (1) {
        const char *tstsig_name = tstsig->name;

        /* Check whether or not end of test signature list */
        if (strlen(tstsig_name) == 0) {
            break;
        }

        printf("  Testing %s ... \n", tstsig_name);

        /* Change padding/hash_id */
        mbedtls_rsa_set_padding( &rsa, tstit->padding, tstsig->md_alg );

        /* Fetch mbedtls_md_info_t object */
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) tstsig->md_alg );
        MBEDTLS_MPI_CHK(md_info != NULL ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);

        /* Check whether or not temporary message digest buffer is large enough */
        unsigned char md_size = mbedtls_md_get_size( md_info );
        MBEDTLS_MPI_CHK(sizeof(md_sum) >= md_size ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);

        /* Hash the message */
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, tstsig->msg));
        msg_bin_len = mbedtls_mpi_size(&K);
        MBEDTLS_MPI_CHK(sizeof(msg_bin) >= msg_bin_len ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, msg_bin, msg_bin_len));
        MBEDTLS_MPI_CHK(mbedtls_md(md_info, msg_bin, msg_bin_len, md_sum));

        /* Create a signature */
        MBEDTLS_MPI_CHK(mbedtls_rsa_pkcs1_sign(&rsa,
                                               myrand,
                                               NULL,
                                               MBEDTLS_RSA_PRIVATE,
                                               (mbedtls_md_type_t) tstsig->md_alg,
                                               0,
                                               md_sum,
                                               sig_act_bin));

        /* Compare calculated signature with expected
         *
         * For V21 padding, hash_id and salt extra are needed to calculate
         * accurate signature to compare with expected one defined in test
         * vector (NIST CAVP). This needs hack into mbedtls_rsa_rsassa_pss_sign().
         * Skip it and just run with sign/verify test.
         */
        if (tstit->padding != MBEDTLS_RSA_PKCS_V21) {
#if 1
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&K, sig_act_bin, rsa.len));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&K, 16, sig_act_hexstr, sizeof(sig_act_hexstr), &sig_act_hexstr_len));
            printf("  Sig (EXP): \n%s\n", tstsig->sig);
            printf("  Sig (ACT): \n%s\n", sig_act_hexstr);
#endif
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&K, 16, tstsig->sig));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, sig_exp_bin, rsa.len));
            MBEDTLS_MPI_CHK(memcmp(sig_exp_bin, sig_act_bin, rsa.len) == 0 ? 0 : MBEDTLS_ERR_RSA_VERIFY_FAILED);
        }

        /* Verify the signature */
        MBEDTLS_MPI_CHK(mbedtls_rsa_pkcs1_verify(&rsa,
                                                 NULL,
                                                 NULL,
                                                 MBEDTLS_RSA_PUBLIC,
                                                 (mbedtls_md_type_t) tstsig->md_alg,
                                                 0,
                                                 md_sum,
                                                 sig_act_bin));

        printf("  Testing %s ... OK\n", tstsig_name);

        /* Next test signature */
        tstsig ++;
    }

cleanup:

    mbedtls_mpi_free( &K );
    mbedtls_rsa_free( &rsa );

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n\n", tstit->name, ms, ret ? "FAILED" : "OK");
}

#endif /* MBEDTLS_RSA_C */
