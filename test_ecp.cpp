#include "mbed.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_ECP_C)

#include "test_crypto_cm.h"
#include "testvector_ecp.h"

#if defined(TARGET_M460)
#include "ecp_helper.h"
#endif

extern "C" {
    int internal_ecp_normalize(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt);
}

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

static void
test_ecp_montgomery_sub_mxP(mbedtls_ecp_group_id id, 
                            const testvector_ecp_montgomery_mxP_t *test_mxP_vector,
                            const char *test_name);

#if defined(TARGET_M460)
static void
test_ecp_montgomery_sub_deduce_y(mbedtls_ecp_group_id id, 
                                 const testvector_ecp_montgomery_deduce_y_t *test_deduce_y_vector,
                                 const char *test_name);
#endif

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

void test_ecp_curve25519(void)
{
    test_ecp_montgomery_sub_mxP(MBEDTLS_ECP_DP_CURVE25519,             
                                testvector_ecp_curve25519_mxP,
                                "Curve25519: R=m*P");
#if defined(TARGET_M460)
    test_ecp_montgomery_sub_deduce_y(MBEDTLS_ECP_DP_CURVE25519, 
                                     testvector_ecp_curve25519_deduce_y,
                                     "Curve25519: Deduce Y");
#endif
}

void test_ecp_curve448(void)
{
    test_ecp_montgomery_sub_mxP(MBEDTLS_ECP_DP_CURVE448,             
                                testvector_ecp_curve448_mxP,
                                "Curve448: R=m*P");
#if defined(TARGET_M460)
    test_ecp_montgomery_sub_deduce_y(MBEDTLS_ECP_DP_CURVE448, 
                                     testvector_ecp_curve448_deduce_y,
                                     "Curve448: Deduce Y");
#endif
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
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &R_act, &m, &G, unsafe_rand, NULL));

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
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &dG, &d, &grp.G, unsafe_rand, NULL));
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&dG, &Q));
            t.start();

            /* Bind group and private key */
            MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&ctx, &keypair));

            /* Create a signature */
            MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&grp,
                                               &r_act, &s_act,
                                               &d,
                                               msg_bin, msg_bin_len,
                                               unsafe_rand, NULL));

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

static void
test_ecp_montgomery_sub_mxP(mbedtls_ecp_group_id id, 
                            const testvector_ecp_montgomery_mxP_t *test_mxP_vector,
                            const char *test_name)
{
    int ret;
    Timer t;

    /* Intermediary buffers can be too large for stack to accommodate.
     * Change to static for safe, implying this function is non-reentrant. */
    static char             tmp_hexstr[sizeof(((testvector_ecp_montgomery_mxP_t *)0)->m_le)];    // Temp buffer to hold hex string
    static size_t           tmp_hexstr_len;                                                     // Actual length of above, including trailing '\0'
    static unsigned char    tmp_bin[sizeof(tmp_hexstr)/2];                                      // Temp buffer to hold bin
    static size_t           tmp_bin_len;                                                        // Actual length of above

    printf("Testing %s\n", test_name);

    /* Time measurement starts */
    t.start();

    mbedtls_ecp_group grp;    
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);

    mbedtls_ecp_point R_act;
    mbedtls_ecp_point_init(&R_act);

    mbedtls_ecp_keypair kp_m;
    mbedtls_ecp_keypair_init(&kp_m);

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_mpi tmp_mpi;
    mbedtls_mpi_init(&tmp_mpi);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));

    /* Test cases: R = m*P */
    {
        const testvector_ecp_montgomery_mxP_t *test_mxP = test_mxP_vector;

        while (1) {
            /* End of test list? */
            if (strlen(test_mxP->name) == 0) {
                break;
            }

            printf("  Testing %s ... \n", test_mxP->name);

            /* Import R */
            if (strcmp(test_mxP->R_le.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&R));
            } else {
                MBEDTLS_MPI_CHK(hexstr_le2be(tmp_hexstr, sizeof(tmp_hexstr), test_mxP->R_le.x));
                MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&tmp_mpi, 16, tmp_hexstr));
                tmp_bin_len = mbedtls_mpi_size(&grp.P); // Required by mbedtls_ecp_point_read_binary()
                MBEDTLS_MPI_CHK(tmp_bin_len <= sizeof(tmp_bin) ? 0 : -1);
                MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&tmp_mpi, tmp_bin, tmp_bin_len));
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &R, tmp_bin, tmp_bin_len));
            }

            /* Import m */
            MBEDTLS_MPI_CHK(hexstr_le2be(tmp_hexstr, sizeof(tmp_hexstr), test_mxP->m_le));
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&tmp_mpi, 16, tmp_hexstr));
            tmp_bin_len = mbedtls_mpi_size(&grp.P); // Required by mbedtls_ecp_read_key()
            MBEDTLS_MPI_CHK(tmp_bin_len <= sizeof(tmp_bin) ? 0 : -1);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&tmp_mpi, tmp_bin, tmp_bin_len));
            ret = mbedtls_ecp_read_key(grp.id, &kp_m, tmp_bin, tmp_bin_len);
            if (ret == MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE &&
                grp.id == MBEDTLS_ECP_DP_CURVE448) {
                MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&kp_m.d, tmp_bin, tmp_bin_len));

                /* Set the two least significant bits to 0 */
                MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&kp_m.d, 0, 0));
                MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&kp_m.d, 1, 0));

                /* Set the most significant bit to 1 */
                MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&kp_m.d, 447, 1));
            } else if (ret != 0) {
                goto cleanup;
            }

            /* Import P */
            if (strcmp(test_mxP->P_le.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&P));
            } else {
                MBEDTLS_MPI_CHK(hexstr_le2be(tmp_hexstr, sizeof(tmp_hexstr), test_mxP->P_le.x));
                MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&tmp_mpi, 16, tmp_hexstr));
                tmp_bin_len = mbedtls_mpi_size(&grp.P); // Required by mbedtls_ecp_point_read_binary()
                MBEDTLS_MPI_CHK(tmp_bin_len <= sizeof(tmp_bin) ? 0 : -1);
                MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&tmp_mpi, tmp_bin, tmp_bin_len));
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &P, tmp_bin, tmp_bin_len));
            }

            /* Run R = m*P */
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &R_act, &kp_m.d, &P, unsafe_rand, NULL));

#if 0
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&R.X, 16, tmp_hexstr, sizeof(tmp_hexstr), &tmp_hexstr_len));
            printf("  R.x (EXP): \n%s\n", tmp_hexstr);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(&R_act.X, 16, tmp_hexstr, sizeof(tmp_hexstr), &tmp_hexstr_len));
            printf("  R.x (ACT): \n%s\n", tmp_hexstr);
#endif

            /* Verify the result
             *
             * Only x-coord is significant for Montgomery curve.
             */
#if 1
            mbedtls_mpi_cmp_mpi(&R.X, &R_act.X);
#else
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&R, &R_act));
#endif

            printf("  Testing %s ... OK\n", test_mxP->name);

            /* Next */
            test_mxP ++;
        }
    }    

cleanup:

    mbedtls_mpi_free(&tmp_mpi);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_keypair_free(&kp_m);
    mbedtls_ecp_point_free(&R_act);
    mbedtls_ecp_point_free(&R);
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

#if defined(TARGET_M460)
static void
test_ecp_montgomery_sub_deduce_y(mbedtls_ecp_group_id id, 
                                 const testvector_ecp_montgomery_deduce_y_t *test_deduce_y_vector,
                                 const char *test_name)
{
    int ret;
    Timer t;

    /* Intermediary buffers can be too large for stack to accommodate.
     * Change to static for safe, implying this function is non-reentrant. */
    static char             tmp_hexstr[sizeof(((testvector_ecp_point_t *)0)->x) + 80];          // Temp buffer to hold hex string
    static size_t           tmp_hexstr_len;                                                     // Actual length of above, including trailing '\0'
    static unsigned char    tmp_bin[sizeof(tmp_hexstr)/2];                                      // Temp buffer to hold bin
    static size_t           tmp_bin_len;                                                        // Actual length of above

    printf("Testing %s\n", test_name);

    /* Time measurement starts */
    t.start();

    mbedtls_ecp_group grp;    
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_mpi y1_act;
    mbedtls_mpi_init(&y1_act);

    mbedtls_mpi y2_act;
    mbedtls_mpi_init(&y2_act);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));

    /* Test cases: Deduce Y from X for P on curves */
    {
        const testvector_ecp_montgomery_deduce_y_t *test_deduce_y = test_deduce_y_vector;

        while (1) {
            /* End of test list? */
            if (strlen(test_deduce_y->name) == 0) {
                break;
            }

            printf("  Testing %s ... \n", test_deduce_y->name);

            /* Import P */
            if (strcmp(test_deduce_y->P.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&P));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&P, 10, test_deduce_y->P.x, test_deduce_y->P.y));
            }

            /* Deduce Y1 from X */
            MBEDTLS_MPI_CHK(ecp_helper_deduce_y(&grp, &y1_act, &P.X));

            /* Y2 = P - Y1 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&y2_act, &grp.P, &y1_act));

            /* Compare the result */
            if (mbedtls_mpi_cmp_mpi(&y1_act, &P.Y) != 0 &&
                mbedtls_mpi_cmp_mpi(&y2_act, &P.Y) != 0) {
                ret = -1;
                goto cleanup;
            }

            printf("  Testing %s ... OK\n", test_deduce_y->name);

            /* Next */
            test_deduce_y ++;
        }
    }    

cleanup:

    mbedtls_mpi_free(&y2_act);
    mbedtls_mpi_free(&y1_act);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_group_free(&grp);

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n", test_name, ms, ret ? "FAILED" : "OK");
    printf("\n");
}
#endif

#endif /* MBEDTLS_ECP_C */
