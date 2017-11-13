#include "mbed.h"
#include "mbedtls/ecp.h"

#include "test_crypto_cm.h"

#if defined(MBEDTLS_ECP_C)

typedef struct {
    char    x[140];
    char    y[140];
    char    z[140];
} ecp_test_point;

/* R = m*G */
typedef struct {
    char            name[50];
    ecp_test_point  R;
    char            m[160];
} ecp_test_mxG;

static void test_ecp_secp_sub(mbedtls_ecp_group_id id, 
                            const ecp_test_point *test_point_G, 
                            const ecp_test_mxG *test_mxG_vector, 
                            size_t test_mxG_size,
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

const ecp_test_point secp192r1_G = {
    "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
    "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
    "1"
};

const ecp_test_point secp384r1_G = {
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    "1"
};

const ecp_test_point secp521r1_G = {
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    "1"
};

const ecp_test_mxG secp192r1_test_mxG_vector[] = {
    /* R = 1*G */
    {
        "R = 1*G",
        /* R = 1*G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* m = 1 */
        "1",
    },
    
    /* R = 2*G */
    {
        "R = 2*G",
        /* R = 2*G */
        {
            "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
            "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
            "1",
        },
        /* m = 2 */
        "2",
    },
    
    /* R = 3*G */
    {
        "R = 3*G",
        /* R = 3*G */
        {
            "76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
            "782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
            "1",
        },
        /* m = 3 */
        "3",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
            "229425F266C25F05B94D8443EBE4796FA6CCE505A3816C54",
            "1",
        },
        /* m = BigNum */
        "6277101735386680763835789423176059013767194773182842284079",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE",
            "1",
        },
        /* m = BigNum */
        "6277101735386680763835789423176059013767194773182842284080",
    },
    
};

const ecp_test_mxG secp384r1_test_mxG_vector[] = {
    /* R = 1*G */
    {
        "R = 1*G",
        /* R = 1*G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* m = 1 */
        "1",
    },
    
    /* R = 2*G */
    {
        "R = 2*G",
        /* R = 2*G */
        {
            "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
            "8E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80",
            "1",
        },
        /* m = 2 */
        "2",
    },
    
    /* R = 3*G */
    {
        "R = 3*G",
        /* R = 3*G */
        {
            "077A41D4606FFA1464793C7E5FDC7D98CB9D3910202DCD06BEA4F240D3566DA6B408BBAE5026580D02D7E5C70500C831",
            "C995F7CA0B0C42837D0BBE9602A9FC998520B41C85115AA5F7684C0EDC111EACC24ABD6BE4B5D298B65F28600A2F1DF1",
            "1",
        },
        /* m = 3 */
        "3",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
            "717F0E05A4E4C312484017200292458B4D8A278A43933BC16FB1AFA0DA954BD9A002BC15B2C61DD29EAFE190F56BF17F",
            "1",
        },
        /* m = BigNum */
        "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942641",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "C9E821B569D9D390A26167406D6D23D6070BE242D765EB831625CEEC4A0F473EF59F4E30E2817E6285BCE2846F15F1A0",
            "1",
        },
        /* m = BigNum */
        "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942642",
    },
};

const ecp_test_mxG secp521r1_test_mxG_vector[] = {
    /* R = 1*G */
    {
        "R = 1*G",
        /* R = 1*G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* m = 1 */
        "1",
    },
    
    /* R = 2*G */
    {
        "R = 2*G",
        /* R = 2*G */
        {
            "00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
            "00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02",
            "1",
        },
        /* m = 2 */
        "2",
    },
    
    /* R = 3*G */
    {
        "R = 3*G",
        /* R = 3*G */
        {
            "01A73D352443DE29195DD91D6A64B5959479B52A6E5B123D9AB9E5AD7A112D7A8DD1AD3F164A3A4832051DA6BD16B59FE21BAEB490862C32EA05A5919D2EDE37AD7D",
            "013E9B03B97DFA62DDD9979F86C6CAB814F2F1557FA82A9D0317D2F8AB1FA355CEEC2E2DD4CF8DC575B02D5ACED1DEC3C70CF105C9BC93A590425F588CA1EE86C0E5",
            "1",
        },
        /* m = 3 */
        "3",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
            "010B44733807924D98FF580C1311112C0F4A394AEF83B25688BF54DE5D66F93BD2444C1C882160DAE0946C6C805665CDB70B1503416A123F0B08E41CA9299E0BE4FD",
            "1",
        },
        /* m = BigNum */
        "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005447",
    },
    
    /* R = BigNum*G */
    {
        "R = BigNum*G",
        /* R = BigNum*G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "00E7C6D6958765C43FFBA375A04BD382E426670ABBB6A864BB97E85042E8D8C199D368118D66A10BD9BF3AAF46FEC052F89ECAC38F795D8D3DBF77416B89602E99AF",
            "1",
        },
        /* m = BigNum */
        "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005448",
    },
};

void test_ecp_secp192r1(void)
{
    test_ecp_secp_sub(MBEDTLS_ECP_DP_SECP192R1, 
                    &secp192r1_G, 
                    secp192r1_test_mxG_vector, 
                    sizeof (secp192r1_test_mxG_vector) / sizeof (secp192r1_test_mxG_vector[0]),
                    __func__);
}

void test_ecp_secp384r1(void)
{
    test_ecp_secp_sub(MBEDTLS_ECP_DP_SECP384R1, 
                    &secp384r1_G, 
                    secp384r1_test_mxG_vector, 
                    sizeof (secp384r1_test_mxG_vector) / sizeof (secp384r1_test_mxG_vector[0]),
                    __func__);
}

void test_ecp_secp521r1(void)
{
    test_ecp_secp_sub(MBEDTLS_ECP_DP_SECP521R1, 
                    &secp521r1_G, 
                    secp521r1_test_mxG_vector, 
                    sizeof (secp521r1_test_mxG_vector) / sizeof (secp521r1_test_mxG_vector[0]),
                    __func__);
}

static void test_ecp_secp_sub(mbedtls_ecp_group_id id,
                            const ecp_test_point *test_point_G, 
                            const ecp_test_mxG *test_mxG_vector, 
                            size_t test_mxG_size,
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
    
    mbedtls_ecp_point mP;
    mbedtls_ecp_point_init(&mP);
    
    mbedtls_mpi m;
    mbedtls_mpi_init(&m);
    
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));
    
    /* Import G */
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&G, 16, test_point_G->x, test_point_G->y));
       
    /* Test cases: R = m*G */
    {
        const ecp_test_mxG *mG = test_mxG_vector;
        const ecp_test_mxG *mG_end = test_mxG_vector + test_mxG_size;
        
        for (; mG != mG_end; mG ++) {
            printf("  Testing %s ... ", mG->name);
            
            /* Import R */
            if (strcmp(mG->R.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&R));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&R, 16, mG->R.x, mG->R.y));
            }
            
            /* Import m */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&m, 10, mG->m));
            
            /* Run R = m*G */
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &mP, &m, &G, NULL, NULL));
            
            /* Verify the result */
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&R, &mP));
            
            printf("OK\n");
        }
    }    
    
cleanup:

    mbedtls_mpi_free(&m);
    mbedtls_ecp_point_free(&mP);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&G);
    mbedtls_ecp_group_free(&grp);
    
    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();
    
    printf("\nTesting %s (%d ms) %s\n\n", test_name, ms, ret ? "FAILED" : "OK");
}

#endif /* MBEDTLS_ECP_C */
