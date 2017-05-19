#include "mbed.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_ECP_C)

#include "test_crypto_cm.h"
#include "testvector_ecp.h"

extern "C" {
    int internal_ecp_normalize(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt);
}

static int myrand( void *rng_state, unsigned char *output, size_t len );
static void
test_ecp_secp_sub_mxG(mbedtls_ecp_group_id id, 
                      const testvector_ecp_point_t *test_point_G, 
                      const testvector_ecp_mxG_t *test_mxG_vector,
                      const char *test_name);
static void
test_ecp_secp_sub_mxP_plus_nxQ(mbedtls_ecp_group_id id,
                               const testvector_ecp_mxP_plus_nxQ_t *test_mxP_plus_nxQ_vector,
                               const char *test_name);
static void
test_ecp_secp_sub_ecdsa(mbedtls_ecp_group_id id,
                        const testvector_ecp_ecdsa_t *test_ecdsa_vector,
                        const char *test_name);

void test_ecp(void)
{
    if (mbedtls_ecp_self_test(1)) {
        printf("mbedtls_ecp_self_test failed\n\n");
    }
    else {
        printf("mbedtls_ecp_self_test passed\n\n");
    }
}

void test_ecp_secp192r1(void)
{
    test_ecp_secp_sub_mxG(MBEDTLS_ECP_DP_SECP192R1, 
                          &testvector_ecp_secp192r1_G, 
                          testvector_ecp_secp192r1_mxG,
                          "secp192r1: R=m*G");
    test_ecp_secp_sub_mxP_plus_nxQ(MBEDTLS_ECP_DP_SECP192R1,
                                   testvector_ecp_secp192r1_mxP_plus_nxQ,
                                   "secp192r1: R=m*P + n*Q");
    test_ecp_secp_sub_ecdsa(MBEDTLS_ECP_DP_SECP192R1,
                            testvector_ecp_secp192r1_ecdsa,
                            "secp192r1: ECDSA");
}

void test_ecp_secp384r1(void)
{
    test_ecp_secp_sub_mxG(MBEDTLS_ECP_DP_SECP384R1, 
                          &testvector_ecp_secp384r1_G, 
                          testvector_ecp_secp384r1_mxG,
                          "secp384r1: R=m*G");
    test_ecp_secp_sub_mxP_plus_nxQ(MBEDTLS_ECP_DP_SECP384R1,
                                   testvector_ecp_secp384r1_mxP_plus_nxQ,
                                   "secp384r1: R=m*P + n*Q");
    test_ecp_secp_sub_ecdsa(MBEDTLS_ECP_DP_SECP384R1,
                            testvector_ecp_secp384r1_ecdsa,
                            "secp384r1: ECDSA");
}

void test_ecp_secp521r1(void)
{
    test_ecp_secp_sub_mxG(MBEDTLS_ECP_DP_SECP521R1, 
                          &testvector_ecp_secp521r1_G, 
                          testvector_ecp_secp521r1_mxG,
                          "secp521r1: R=m*G");
    test_ecp_secp_sub_mxP_plus_nxQ(MBEDTLS_ECP_DP_SECP521R1,
                                   testvector_ecp_secp521r1_mxP_plus_nxQ,
                                   "secp521r1: R=m*P + n*Q");
    test_ecp_secp_sub_ecdsa(MBEDTLS_ECP_DP_SECP521R1,
                            testvector_ecp_secp521r1_ecdsa,
                            "secp521r1: ECDSA");
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

static void
test_ecp_secp_sub_mxG(mbedtls_ecp_group_id id,
                      const testvector_ecp_point_t *test_point_G, 
                      const testvector_ecp_mxG_t *test_mxG_vector,
                      const char *test_name)
{
    int ret;
    Timer t;

    printf("Testing %s\n", test_name);

    /* Time measurement starts */
    t.start();
    
    mbedtls_ecp_group grp;    
    mbedtls_ecp_group_init(&grp);
    
    mbedtls_ecp_point G;
    mbedtls_ecp_point_init(&G);
    
    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);
    
    mbedtls_ecp_point R_act;
    mbedtls_ecp_point_init(&R_act);
    
    mbedtls_mpi m;
    mbedtls_mpi_init(&m);
    
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));
    
    /* Import G */
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&G, 16, test_point_G->x, test_point_G->y));
       
    /* Test cases: R = m*G */
    {
        const testvector_ecp_mxG_t *test_mxG = test_mxG_vector;

        while (1) {
            /* End of test list? */
            if (strlen(test_mxG->name) == 0) {
                break;
            }

            printf("  Testing %s ... \n", test_mxG->name);

            /* Import R */
            if (strcmp(test_mxG->R.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&R));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&R, 16, test_mxG->R.x, test_mxG->R.y));
            }

            /* Import m */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&m, 10, test_mxG->m));

            /* Run R = m*G */
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &R_act, &m, &G, myrand, NULL));

            /* Verify the result */
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&R, &R_act));

            printf("  Testing %s ... OK\n", test_mxG->name);

            /* Next */
            test_mxG ++;
        }
    }    
    
cleanup:

    mbedtls_mpi_free(&m);
    mbedtls_ecp_point_free(&R_act);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&G);
    mbedtls_ecp_group_free(&grp);

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n", test_name, ms, ret ? "FAILED" : "OK");
    if (ret == MBEDTLS_ERR_ECP_INVALID_KEY) {
        printf("Meeting MBEDTLS_ERR_ECP_INVALID_KEY, "
               "see mbedtls_ecp_check_pubkey() for m "
               "as valid private key\n");
    }
    printf("\n");
}

static void
test_ecp_secp_sub_mxP_plus_nxQ(mbedtls_ecp_group_id id,
                               const testvector_ecp_mxP_plus_nxQ_t *test_mxP_plus_nxQ_vector,
                               const char *test_name)
{
    int ret;
    Timer t;

    printf("Testing %s\n", test_name);

    /* Time measurement starts */
    t.start();

    mbedtls_ecp_group grp;    
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);

    mbedtls_ecp_point R_act;
    mbedtls_ecp_point_init(&R_act);

    mbedtls_mpi m;
    mbedtls_mpi_init(&m);

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_mpi n;
    mbedtls_mpi_init(&n);

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));

    /* Test cases: R = m*P + n*Q */
    {
        const testvector_ecp_mxP_plus_nxQ_t *test_mxP_plus_nxQ = test_mxP_plus_nxQ_vector;

        while (1) {
            /* End of test list? */
            if (strlen(test_mxP_plus_nxQ->name) == 0) {
                break;
            }

            printf("  Testing %s ... \n", test_mxP_plus_nxQ->name);

            /* Import R */
            if (strcmp(test_mxP_plus_nxQ->R.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&R));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&R, 16, test_mxP_plus_nxQ->R.x, test_mxP_plus_nxQ->R.y));
            }

            /* Import m */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&m, 10, test_mxP_plus_nxQ->m));
            /* Import P */
            if (strcmp(test_mxP_plus_nxQ->P.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&P));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&P, 16, test_mxP_plus_nxQ->P.x, test_mxP_plus_nxQ->P.y));
            }

            /* Import n */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&n, 10, test_mxP_plus_nxQ->n));
            /* Import Q */
            if (strcmp(test_mxP_plus_nxQ->Q.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&Q));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&Q, 16, test_mxP_plus_nxQ->Q.x, test_mxP_plus_nxQ->Q.y));
            }

            /* Avoid MBEDTLS_ERR_ECP_INVALID_KEY for m/n as invalid private key
             *
             * mbedtls_ecp_muladd()/mbedtls_ecp_mul() will call mbedtls_ecp_check_privkey()
             * to check whether or not m/n are valid private keys. To avoid this error, skip
             * tests with m/n being zero or other invalid private keys.
             */
            if (!test_mxP_plus_nxQ->is_eccop ||
                test_mxP_plus_nxQ->eccop == ECCOP_POINT_ADD) {
                /* Run R = m*P + n*Q */
                MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, &R_act, &m, &P, &n, &Q));

                /* Verify the result */
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&R, &R_act));

                printf("  Testing %s ... OK\n", test_mxP_plus_nxQ->name);
            } else {
                printf("  Testing %s ... SKIPPED\n", test_mxP_plus_nxQ->name);
            }

            /* Next */
            test_mxP_plus_nxQ ++;
        }
    }    

cleanup:

    mbedtls_mpi_free(&m);
    mbedtls_mpi_free(&n);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&R_act);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_group_free(&grp);

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n", test_name, ms, ret ? "FAILED" : "OK");
    if (ret == MBEDTLS_ERR_ECP_INVALID_KEY) {
        printf("Meeting MBEDTLS_ERR_ECP_INVALID_KEY, "
               "see mbedtls_ecp_check_pubkey() for m/n "
               "as valid private key\n");
    }
    printf("\n");
}

static void
test_ecp_secp_sub_ecdsa(mbedtls_ecp_group_id id,
                        const testvector_ecp_ecdsa_t *test_ecdsa_vector,
                        const char *test_name)
{
    int ret;
    Timer t;

    /* Intermediary buffers can be too large for stack to accommodate.
     * Change to static for safe, implying this function is non-reentrant. */
    static unsigned char    msg_bin[MBEDTLS_MPI_MAX_SIZE];          // Temp buffer to hold message in binary form
    static size_t           msg_bin_len;
    static unsigned char    d_bin[MBEDTLS_MPI_MAX_SIZE];        // Temp buffer to hold d in binary form
    static size_t           d_bin_len;
    static char             d_hexstr[1024 + 8];                 // Temp buffer to hold d in hex string form
    static size_t           d_hexstr_len;                       // Actual length of above, including NULL char
    static char             r_act_hexstr[1024 + 8];             // Temp buffer to hold r_act in hex string form
    static size_t           r_act_hexstr_len;                   // Actual length of above, including NULL char
    static char             s_act_hexstr[1024 + 8];             // Temp buffer to hold s_act in hex string form
    static size_t           s_act_hexstr_len;                   // Actual length of above, including NULL char

    printf("Testing %s\n", test_name);

    /* Time measurement starts */
    t.start();

    mbedtls_ecp_group grp;    
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    mbedtls_mpi msg;
    mbedtls_mpi_init(&msg);

    mbedtls_mpi d;
    mbedtls_mpi_init(&d);

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_point dG;
    mbedtls_ecp_point_init(&dG);

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);

    mbedtls_mpi s;
    mbedtls_mpi_init(&s);

    mbedtls_mpi r_act;
    mbedtls_mpi_init(&r_act);

    mbedtls_mpi s_act;
    mbedtls_mpi_init(&s_act);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));

    /* Test cases: ECDSA # */
    {
        const testvector_ecp_ecdsa_t *test_ecdsa = test_ecdsa_vector;

        while (1) {
            /* End of test list? */
            if (strlen(test_ecdsa->name) == 0) {
                break;
            }

            printf("  Testing %s ... \n", test_ecdsa->name);

            /* Import msg */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&msg, 16, test_ecdsa->msg));
            msg_bin_len = mbedtls_mpi_size(&msg);
            MBEDTLS_MPI_CHK(sizeof(msg_bin) >= msg_bin_len ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&msg, msg_bin, msg_bin_len));

            /* Import d */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&d, 16, test_ecdsa->d));
            d_bin_len = mbedtls_mpi_size(&d);
            MBEDTLS_MPI_CHK(sizeof(d_bin) >= d_bin_len ? 0 : MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&d, d_bin, d_bin_len));
            MBEDTLS_MPI_CHK(mbedtls_ecp_read_key(id, &keypair, d_bin, d_bin_len));

            /* Import Q */
            if (strcmp(test_ecdsa->Q.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&Q));
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&keypair.Q));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&Q, 16, test_ecdsa->Q.x, test_ecdsa->Q.y));
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&keypair.Q, 16, test_ecdsa->Q.x, test_ecdsa->Q.y));
            }

            /* Import r */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&r, 16, test_ecdsa->r));

            /* Import s */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&s, 16, test_ecdsa->s));

            /* Confirm Q = d*G */
            /* Exclude the piece from performance measurement */
            t.stop();
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &dG, &d, &grp.G, myrand, NULL));
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&dG, &Q));
            t.start();

            /* Bind group and private key */
            MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&ctx, &keypair));

            /* Create a signature */
            MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&grp,
                                               &r_act, &s_act,
                                               &d,
                                               msg_bin, msg_bin_len,
                                               myrand, NULL));

            /* Compare calculated signature with expected
             *
             * Hash algorithm and random data are needed to calculate
             * accurate signature to compare with expected one defined
             * in test vector. This comparison is skipped because:
             * 1. Hash algorithm is unknown with this test vector.
             * 2. Random data needs hack into mbedtls_ecdsa_xxx().
             */
#if 0
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&r_act, 16, r_act_hexstr, sizeof(r_act_hexstr), &r_act_hexstr_len));
            printf("  Sig r part (EXP): \n%s\n", test_ecdsa->r);
            printf("  Sig r part (ACT): \n%s\n", r_act_hexstr);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&s_act, 16, s_act_hexstr, sizeof(s_act_hexstr), &s_act_hexstr_len));
            printf("  Sig s part (EXP): \n%s\n", test_ecdsa->s);
            printf("  Sig s part (ACT): \n%s\n", s_act_hexstr);
#endif
#if 0
            MBEDTLS_MPI_CHK(mbedtls_mpi_cmp_mpi(&r, &r_act));
            MBEDTLS_MPI_CHK(mbedtls_mpi_cmp_mpi(&s, &s_act));
#endif

            /* Verify the signature */
            MBEDTLS_MPI_CHK(mbedtls_ecdsa_verify(&grp,
                                                 msg_bin, msg_bin_len,
                                                 &Q,
                                                 &r_act, &s_act));

            printf("  Testing %s ... OK\n", test_ecdsa->name);

            /* Next */
            test_ecdsa ++;
        }
    }    

cleanup:

    mbedtls_mpi_free(&r_act);
    mbedtls_mpi_free(&s_act);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&dG);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&msg);
    mbedtls_ecdsa_free(&ctx);
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_group_free(&grp);

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n", test_name, ms, ret ? "FAILED" : "OK");
    if (ret == MBEDTLS_ERR_ECP_INVALID_KEY) {
        printf("Meeting MBEDTLS_ERR_ECP_INVALID_KEY, "
               "see mbedtls_ecp_check_pubkey() for m/n "
               "as valid private key\n");
    }
    printf("\n");
}

#endif /* MBEDTLS_ECP_C */
