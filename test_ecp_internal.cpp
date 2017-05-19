#include "mbed.h"
#include "mbedtls/ecp.h"

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_INTERNAL_ALT)

#include "test_crypto_cm.h"
#include "testvector_ecp.h"

extern "C" {
    unsigned char mbedtls_internal_ecp_grp_capable( const mbedtls_ecp_group *grp );
    int mbedtls_internal_ecp_init( const mbedtls_ecp_group *grp );
    void mbedtls_internal_ecp_free( const mbedtls_ecp_group *grp );
    int mbedtls_internal_ecp_mul(mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *R,
                            const mbedtls_mpi *m,
                            const mbedtls_ecp_point *P);                            
    int mbedtls_internal_ecp_normalize_jac( const mbedtls_ecp_group *grp,
        mbedtls_ecp_point *pt );

    int internal_ecp_normalize(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt);
    int internal_run_eccop(const mbedtls_ecp_group *grp,
                           mbedtls_ecp_point *R,
                           const mbedtls_mpi *m,
                           const mbedtls_ecp_point *P,
                           const mbedtls_mpi *n,
                           const mbedtls_ecp_point *Q,
                           uint32_t eccop);
}
               
/**
 * \brief           Point multiplication R = m*P, Jacobian coordinates.
 *
 * \param grp       Pointer to the group representing the curve.
 *
 * \param R         Pointer to a point structure to hold the result.
 *
 * \param m         Pointer to MPI by which to multiply P
 *
 * \param P         Pointer to the point that has to be multiplied by m, given with
 *                  Jacobian coordinates.
 *
 * \return          0 if successful.
 *
 * \note            Currently mbedTLS doesn't open R = m*P API like this.
 *                  It is expected because ECC accelerator can improve it by 30~40 times.
 */
int mbedtls_internal_ecp_mul_jac(mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *R,
                            const mbedtls_mpi *m,
                            const mbedtls_ecp_point *P)
{
    int ret;
    mbedtls_ecp_point P_;
    
    mbedtls_ecp_point_init(&P_);
    
    /* P_ = normalized P */
    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&P_, P));
    MBEDTLS_MPI_CHK(mbedtls_internal_ecp_normalize_jac(grp, &P_));
        
    /* Run ECC point multiplication: R = m*P */
    MBEDTLS_MPI_CHK(internal_run_eccop(grp, R, m, &P_, NULL, NULL, ECCOP_POINT_MUL));

cleanup:

    mbedtls_ecp_point_free(&P_);

    return ret;
}

static void test_ecp_internal_secp_sub(mbedtls_ecp_group_id id,
                            const testvector_ecp_mxP_plus_nxQ_t *test_mxP_plus_nxQ_vector,
                            const char *test_name);

void test_ecp_internal_secp192r1(void)
{
    test_ecp_internal_secp_sub(MBEDTLS_ECP_DP_SECP192R1, 
                            testvector_ecp_secp192r1_mxP_plus_nxQ,
                            __func__);
}

void test_ecp_internal_secp384r1(void)
{
    test_ecp_internal_secp_sub(MBEDTLS_ECP_DP_SECP384R1,
                            testvector_ecp_secp384r1_mxP_plus_nxQ,
                            __func__);
}

void test_ecp_internal_secp521r1(void)
{
    test_ecp_internal_secp_sub(MBEDTLS_ECP_DP_SECP521R1,
                            testvector_ecp_secp521r1_mxP_plus_nxQ,
                            __func__);
}

static void test_ecp_internal_secp_sub(mbedtls_ecp_group_id id,
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

    mbedtls_mpi m;
    mbedtls_mpi_init(&m);

    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    mbedtls_mpi n;
    mbedtls_mpi_init(&n);

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_point R_act;
    mbedtls_ecp_point_init(&R_act);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));

    MBEDTLS_MPI_CHK(mbedtls_internal_ecp_grp_capable(&grp) ? 0 : MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE);
    MBEDTLS_MPI_CHK(mbedtls_internal_ecp_init(&grp));

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

            if (test_mxP_plus_nxQ->is_eccop) {
                /* Run Crypto ECC H/W Mul/Add/Double operation */
                MBEDTLS_MPI_CHK(internal_run_eccop(&grp, &R_act, &m, &P, &n, &Q, test_mxP_plus_nxQ->eccop));

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

    mbedtls_internal_ecp_free(&grp);
    mbedtls_ecp_point_free(&R_act);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&n);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&m);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_group_free(&grp);
    
    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n\n", test_name, ms, ret ? "FAILED" : "OK");
}

#endif /* MBEDTLS_ECP_INTERNAL_ALT */
#endif /* MBEDTLS_ECP_C */
