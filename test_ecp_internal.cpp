#include "mbed.h"
#include "mbedtls/ecp.h"

#include "test_crypto_cm.h"

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_INTERNAL_ALT)

#define ECCOP_POINT_MUL     (0x0UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_MODULE        (0x1UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_ADD     (0x2UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_DOUBLE  (0x3UL << CRPT_ECC_CTL_ECCOP_Pos)

extern "C" {
    unsigned char mbedtls_internal_ecp_grp_capable( const mbedtls_ecp_group *grp );
    int mbedtls_internal_ecp_init( const mbedtls_ecp_group *grp );
    void mbedtls_internal_ecp_free( const mbedtls_ecp_group *grp );
    int mbedtls_internal_ecp_mul(mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *R,
                            const mbedtls_mpi *m,
                            const mbedtls_ecp_point *P);
    int mbedtls_internal_run_eccop(const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point *R,
                                const mbedtls_mpi *m,
                                const mbedtls_ecp_point *P,
                                const mbedtls_mpi *n,
                                const mbedtls_ecp_point *Q,
                                uint32_t eccop);
}
                
typedef struct {
    char    x[140];
    char    y[140];
    char    z[140];
} ecp_test_point;

/* R = m*P + n*Q */
typedef struct {
    char            name[50];
    ecp_test_point  R;
    char            m[160];
    ecp_test_point  P;
    char            n[160];
    ecp_test_point  Q;
    uint32_t        eccop;
} ecp_test_mxP_plus_nxQ;

static void test_ecp_secp_sub_internal(mbedtls_ecp_group_id id,
                            const ecp_test_mxP_plus_nxQ *test_mxP_plus_nxQ_vector, 
                            size_t test_mxP_plus_nxQ_size,
                            const char *test_name);

const ecp_test_mxP_plus_nxQ secp192r1_test_mxP_plus_nxQ_vector[] = {
    /* Add: 3G = 1G + 2G */
    {
        "Add: 3G = 1G + 2G",
        /* R = 3G */
        {
            "76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
            "782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 2G */
        {
            "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
            "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 10G = 3G + 7G */
    {
        "Add: 10G = 3G + 7G",
        /* R = 10G */
        {
            "AA7C4F9EF99E3E96D1AEDE2BD9238842859BB150D1FE9D85",
            "3212A36547EDC62901EE3658B2F4859460EB5EB2491397B0",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 3G */
        {
            "76E32A2557599E6EDCD283201FB2B9AADFD0D359CBB263DA",
            "782C37E372BA4520AA62E0FED121D49EF3B543660CFD05FD",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 7G */
        {
            "8DA75A1F75DDCD7660F923243060EDCE5DE37F007011FCFD",
            "57CB5FCF6860B35418240DB8FDB3C01DD4B702F96409FFB5",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 20G = 5G + 15G */
    {
        "Add: 20G = 5G + 15G",
        /* R = 20G */
        {
            "BB6F082321D34DBD786A1566915C6DD5EDF879AB0F5ADD67",
            "91E4DD8A77C4531C8B76DEF2E5339B5EB95D5D9479DF4C8D",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 5G */
        {
            "10BB8E9840049B183E078D9C300E1605590118EBDD7FF590",
            "31361008476F917BADC9F836E62762BE312B72543CCEAEA1",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 15G */
        {
            "8C9595E63B56B633BA3546B2B5414DE736DE4A9E7578B1E7",
            "266B762A934F00C17CF387993AA566B6AD7537CDD98FC7B1",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 0G = 1G + (order - 1)G */
    {
        "Add: 0G = 1G + (order - 1)G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = (order - 1)G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    
    /* Double: 2G = 2*1G */
    {
        "Double: 2G = 2*1G",
        /* R = 2G */
        {
            "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
            "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    /* Double: 18G = 2*9G */
    {
        "Double: 18G = 2*9G",
        /* R = 18G */
        {
            "C1B4DB0227210613A6CA15C428024E40B6513365D72591A3",
            "1E26B286BCA1D08F4FE8F801267DF9FD7782EC3EC3F47F53",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 9G */
        {
            "818A4D308B1CABB74E9E8F2BA8D27C9E1D9D375AB980388F",
            "01D1AA5E208D87CD7C292F7CBB457CDF30EA542176C8E739",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    
    /* Multiplication: 1G = 1*1G */
    {
        "Multiplication: 1G = 1*1G",
        /* R = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 12G = 3*4G */
    {
        "Multiplication: 12G = 3*4G",
        /* R = 12G */
        {
            "1061343F3D456D0ECA013877F8C9E7B28FCCDCDA67EEB8AB",
            "5A064CAA2EA6B03798FEF8E3E7A48648681EAC020B27293F",
            "1",
        },
        /* m = 3 */
        "3",
        /* P = 4G */
        {
            "35433907297CC378B0015703374729D7A4FE46647084E4BA",
            "A2649984F2135C301EA3ACB0776CD4F125389B311DB3BE32",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 20G = 20*1G */
    {
        "Multiplication: 20G = 20*1G",
        /* R = 20G */
        {
            "BB6F082321D34DBD786A1566915C6DD5EDF879AB0F5ADD67",
            "91E4DD8A77C4531C8B76DEF2E5339B5EB95D5D9479DF4C8D",
            "1",
        },
        /* m = 20 */
        "20",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: (order - 1)G = (order - 1)*1G */
    {
        "Multiplication: (order - 1)G = (order - 1)*1G",
        /* R = (order - 1)G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE",
            "1",
        },
        /* m = (order - 1) */
        "6277101735386680763835789423176059013767194773182842284080",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 0G = order*1G */
    {
        "Multiplication: 0G = order*1G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = order */
        "6277101735386680763835789423176059013767194773182842284081",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: -G = -1*1G */
    {
        "Multiplication: -G = -1*1G",
        /* R = -G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "F8E6D46A003725879CEFEE1294DB32298C06885EE186B7EE",
            "1",
        },
        /* m = -1 */
        "-1",
        /* P = 1G */
        {
            "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
            "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
};

const ecp_test_mxP_plus_nxQ secp384r1_test_mxP_plus_nxQ_vector[] = {
    /* Add: 3G = 1G + 2G */
    {
        "Add: 3G = 1G + 2G",
        /* R = 3G */
        {
            "077A41D4606FFA1464793C7E5FDC7D98CB9D3910202DCD06BEA4F240D3566DA6B408BBAE5026580D02D7E5C70500C831",
            "C995F7CA0B0C42837D0BBE9602A9FC998520B41C85115AA5F7684C0EDC111EACC24ABD6BE4B5D298B65F28600A2F1DF1",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 2G */
        {
            "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
            "8E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 10G = 3G + 7G */
    {
        "Add: 10G = 3G + 7G",
        /* R = 10G */
        {
            "A669C5563BD67EEC678D29D6EF4FDE864F372D90B79B9E88931D5C29291238CCED8E85AB507BF91AA9CB2D13186658FB",
            "A988B72AE7C1279F22D9083DB5F0ECDDF70119550C183C31C502DF78C3B705A8296D8195248288D997784F6AB73A21DD",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 3G */
        {
            "077A41D4606FFA1464793C7E5FDC7D98CB9D3910202DCD06BEA4F240D3566DA6B408BBAE5026580D02D7E5C70500C831",
            "C995F7CA0B0C42837D0BBE9602A9FC998520B41C85115AA5F7684C0EDC111EACC24ABD6BE4B5D298B65F28600A2F1DF1",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 7G */
        {
            "283C1D7365CE4788F29F8EBF234EDFFEAD6FE997FBEA5FFA2D58CC9DFA7B1C508B05526F55B9EBB2040F05B48FB6D0E1",
            "9475C99061E41B88BA52EFDB8C1690471A61D867ED799729D9C92CD01DBD225630D84EDE32A78F9E64664CDAC512EF8C",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 20G = 5G + 15G */
    {
        "Add: 20G = 5G + 15G",
        /* R = 20G */
        {
            "605508EC02C534BCEEE9484C86086D2139849E2B11C1A9CA1E2808DEC2EAF161AC8A105D70D4F85C50599BE5800A623F",
            "5158EE87962AC6B81F00A103B8543A07381B7639A3A65F1353AEF11B733106DDE92E99B78DE367B48E238C38DAD8EEDD",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 5G */
        {
            "11DE24A2C251C777573CAC5EA025E467F208E51DBFF98FC54F6661CBE56583B037882F4A1CA297E60ABCDBC3836D84BC",
            "8FA696C77440F92D0F5837E90A00E7C5284B447754D5DEE88C986533B6901AEB3177686D0AE8FB33184414ABE6C1713A",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 15G */
        {
            "B3D13FC8B32B01058CC15C11D813525522A94156FFF01C205B21F9F7DA7C4E9CA849557A10B6383B4B88701A9606860B",
            "152919E7DF9162A61B049B2536164B1BEEBAC4A11D749AF484D1114373DFBFD9838D24F8B284AF50985D588D33F7BD62",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 0G = 1G + (order - 1)G */
    {
        "Add: 0G = 1G + (order - 1)G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = (order - 1)G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "C9E821B569D9D390A26167406D6D23D6070BE242D765EB831625CEEC4A0F473EF59F4E30E2817E6285BCE2846F15F1A0",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    
    /* Double: 2G = 2*1G */
    {
        "Double: 2G = 2*1G",
        /* R = 2G */
        {
            "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
            "8E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    /* Double: 18G = 2*9G */
    {
        "Double: 18G = 2*9G",
        /* R = 18G */
        {
            "DFB1FE3A40F7AC9B64C41D39360A7423828B97CB088A4903315E402A7089FA0F8B6C2355169CC9C99DFB44692A9B93DD",
            "453ACA1243B5EC6B423A68A25587E1613A634C1C42D2EE7E6C57F449A1C91DC89168B7036EC0A7F37A366185233EC522",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 9G */
        {
            "8F0A39A4049BCB3EF1BF29B8B025B78F2216F7291E6FD3BAC6CB1EE285FB6E21C388528BFEE2B9535C55E4461079118B",
            "62C77E1438B601D6452C4A5322C3A9799A9B3D7CA3C400C6B7678854AED9B3029E743EFEDFD51B68262DA4F9AC664AF8",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    
    /* Multiplication: 1G = 1*1G */
    {
        "Multiplication: 1G = 1*1G",
        /* R = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 12G = 3*4G */
    {
        "Multiplication: 12G = 3*4G",
        /* R = 12G */
        {
            "952A7A349BD49289AB3AC421DCF683D08C2ED5E41F6D0E21648AF2691A481406DA4A5E22DA817CB466DA2EA77D2A7022",
            "A0320FAF84B5BC0563052DEAE6F66F2E09FB8036CE18A0EBB9028B096196B50D031AA64589743E229EF6BACCE21BD16E",
            "1",
        },
        /* m = 3 */
        "3",
        /* P = 4G */
        {
            "138251CD52AC9298C1C8AAD977321DEB97E709BD0B4CA0ACA55DC8AD51DCFC9D1589A1597E3A5120E1EFD631C63E1835",
            "CACAE29869A62E1631E8A28181AB56616DC45D918ABC09F3AB0E63CF792AA4DCED7387BE37BBA569549F1C02B270ED67",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 20G = 20*1G */
    {
        "Multiplication: 20G = 20*1G",
        /* R = 20G */
        {
            "605508EC02C534BCEEE9484C86086D2139849E2B11C1A9CA1E2808DEC2EAF161AC8A105D70D4F85C50599BE5800A623F",
            "5158EE87962AC6B81F00A103B8543A07381B7639A3A65F1353AEF11B733106DDE92E99B78DE367B48E238C38DAD8EEDD",
            "1",
        },
        /* m = 20 */
        "20",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: (order - 1)G = (order - 1)*1G */
    {
        "Multiplication: (order - 1)G = (order - 1)*1G",
        /* R = (order - 1)G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "C9E821B569D9D390A26167406D6D23D6070BE242D765EB831625CEEC4A0F473EF59F4E30E2817E6285BCE2846F15F1A0",
            "1",
        },
        /* m = (order - 1) */
        "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942642",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 0G = order*1G */
    {
        "Multiplication: 0G = order*1G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = order */
        "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: -G = -1*1G */
    {
        "Multiplication: -G = -1*1G",
        /* R = -G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "C9E821B569D9D390A26167406D6D23D6070BE242D765EB831625CEEC4A0F473EF59F4E30E2817E6285BCE2846F15F1A0",
            "1",
        },
        /* m = -1 */
        "-1",
        /* P = 1G */
        {
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
};

const ecp_test_mxP_plus_nxQ secp521r1_test_mxP_plus_nxQ_vector[] = {
    /* Add: 3G = 1G + 2G */
    {
        "Add: 3G = 1G + 2G",
        /* R = 3G */
        {
            "01A73D352443DE29195DD91D6A64B5959479B52A6E5B123D9AB9E5AD7A112D7A8DD1AD3F164A3A4832051DA6BD16B59FE21BAEB490862C32EA05A5919D2EDE37AD7D",
            "013E9B03B97DFA62DDD9979F86C6CAB814F2F1557FA82A9D0317D2F8AB1FA355CEEC2E2DD4CF8DC575B02D5ACED1DEC3C70CF105C9BC93A590425F588CA1EE86C0E5",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 2G */
        {
            "00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
            "00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 10G = 3G + 7G */
    {
        "Add: 10G = 3G + 7G",
        /* R = 10G */
        {
            "0190EB8F22BDA61F281DFCFE7BB6721EC4CD901D879AC09AC7C34A9246B11ADA8910A2C7C178FCC263299DAA4DA9842093F37C2E411F1A8E819A87FF09A04F2F3320",
            "01EB5D96B8491614BA9DBAEAB3B0CA2BA760C2EEB2144251B20BA97FD78A62EF62D2BF5349D44D9864BB536F6163DC57EBEFF3689639739FAA172954BC98135EC759",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 3G */
        {
            "01A73D352443DE29195DD91D6A64B5959479B52A6E5B123D9AB9E5AD7A112D7A8DD1AD3F164A3A4832051DA6BD16B59FE21BAEB490862C32EA05A5919D2EDE37AD7D",
            "013E9B03B97DFA62DDD9979F86C6CAB814F2F1557FA82A9D0317D2F8AB1FA355CEEC2E2DD4CF8DC575B02D5ACED1DEC3C70CF105C9BC93A590425F588CA1EE86C0E5",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 7G */
        {
            "0056D5D1D99D5B7F6346EEB65FDA0B073A0C5F22E0E8F5483228F018D2C2F7114C5D8C308D0ABFC698D8C9A6DF30DCE3BBC46F953F50FDC2619A01CEAD882816ECD4",
            "003D2D1B7D9BAAA2A110D1D8317A39D68478B5C582D02824F0DD71DBD98A26CBDE556BD0F293CDEC9E2B9523A34591CE1A5F9E76712A5DDEFC7B5C6B8BC90525251B",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 20G = 5G + 15G */
    {
        "Add: 20G = 5G + 15G",
        /* R = 20G */
        {
            "018BDD7F1B889598A4653DEEAE39CC6F8CC2BD767C2AB0D93FB12E968FBED342B51709506339CB1049CB11DD48B9BDB3CD5CAD792E43B74E16D8E2603BFB11B0344F",
            "00C5AADBE63F68CA5B6B6908296959BF0AF89EE7F52B410B9444546C550952D311204DA3BDDDC6D4EAE7EDFAEC1030DA8EF837CCB22EEE9CFC94DD3287FED0990F94",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 5G */
        {
            "00652BF3C52927A432C73DBC3391C04EB0BF7A596EFDB53F0D24CF03DAB8F177ACE4383C0C6D5E3014237112FEAF137E79A329D7E1E6D8931738D5AB5096EC8F3078",
            "015BE6EF1BDD6601D6EC8A2B73114A8112911CD8FE8E872E0051EDD817C9A0347087BB6897C9072CF374311540211CF5FF79D1F007257354F7F8173CC3E8DEB090CB",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = 15G */
        {
            "006B6AD89ABCB92465F041558FC546D4300FB8FBCC30B40A0852D697B532DF128E11B91CCE27DBD00FFE7875BD1C8FC0331D9B8D96981E3F92BDE9AFE337BCB8DB55",
            "01B468DA271571391D6A7CE64D2333EDBF63DF0496A9BAD20CBA4B62106997485ED57E9062C899470A802148E2232C96C99246FD90CC446ABDD956343480A1475465",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    /* Add: 0G = 1G + (order - 1)G */
    {
        "Add: 0G = 1G + (order - 1)G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 1 */
        "1",
        /* Q = (order - 1)G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "00E7C6D6958765C43FFBA375A04BD382E426670ABBB6A864BB97E85042E8D8C199D368118D66A10BD9BF3AAF46FEC052F89ECAC38F795D8D3DBF77416B89602E99AF",
            "1",
        },
        ECCOP_POINT_ADD
    },
    
    
    /* Double: 2G = 2*1G */
    {
        "Double: 2G = 2*1G",
        /* R = 2G */
        {
            "00433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
            "00F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    /* Double: 18G = 2*9G */
    {
        "Double: 18G = 2*9G",
        /* R = 18G */
        {
            "01BC33425E72A12779EACB2EDCC5B63D1281F7E86DBC7BF99A7ABD0CFE367DE4666D6EDBB8525BFFE5222F0702C3096DEC0884CE572F5A15C423FDF44D01DD99C61D",
            "010D06E999885B63535DE3E74D33D9E63D024FB07CE0D196F2552C8E4A00AC84C044234AEB201F7A9133915D1B4B45209B9DA79FE15B19F84FD135D841E2D8F9A86A",
            "1",
        },
        /* m = 2*/
        "2",
        /* P = 9G */
        {
            "01585389E359E1E21826A2F5BF157156D488ED34541B988746992C4AB145B8C6B6657429E1396134DA35F3C556DF725A318F4F50BABD85CD28661F45627967CBE207",
            "002A2E618C9A8AEDF39F0B55557A27AE938E3088A654EE1CEBB6C825BA263DDB446E0D69E5756057AC840FF56ECF4ABFD87D736C2AE928880F343AA0EA86B9AD2A4E",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_DOUBLE
    },
    
    
    /* Multiplication: 1G = 1*1G */
    {
        "Multiplication: 1G = 1*1G",
        /* R = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* m = 1*/
        "1",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 12G = 3*4G */
    {
        "Multiplication: 12G = 3*4G",
        /* R = 12G */
        {
            "01C0D9DCEC93F8221C5DE4FAE9749C7FDE1E81874157958457B6107CF7A5967713A644E90B7C3FB81B31477FEE9A60E938013774C75C530928B17BE69571BF842D8C",
            "014048B5946A4927C0FE3CE1D103A682CA4763FE65AB71494DA45E404ABF6A17C097D6D18843D86FCDB6CC10A6F951B9B630884BA72224F5AE6C79E7B1A3281B17F0",
            "1",
        },
        /* m = 3 */
        "3",
        /* P = 4G */
        {
            "0035B5DF64AE2AC204C354B483487C9070CDC61C891C5FF39AFC06C5D55541D3CEAC8659E24AFE3D0750E8B88E9F078AF066A1D5025B08E5A5E2FBC87412871902F3",
            "0082096F84261279D2B673E0178EB0B4ABB65521AEF6E6E32E1B5AE63FE2F19907F279F283E54BA385405224F750A95B85EEBB7FAEF04699D1D9E21F47FC346E4D0D",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 20G = 20*1G */
    {
        "Multiplication: 20G = 20*1G",
        /* R = 20G */
        {
            "018BDD7F1B889598A4653DEEAE39CC6F8CC2BD767C2AB0D93FB12E968FBED342B51709506339CB1049CB11DD48B9BDB3CD5CAD792E43B74E16D8E2603BFB11B0344F",
            "00C5AADBE63F68CA5B6B6908296959BF0AF89EE7F52B410B9444546C550952D311204DA3BDDDC6D4EAE7EDFAEC1030DA8EF837CCB22EEE9CFC94DD3287FED0990F94",
            "1",
        },
        /* m = 20 */
        "20",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: (order - 1)G = (order - 1)*1G */
    {
        "Multiplication: (order - 1)G = (order - 1)*1G",
        /* R = (order - 1)G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "00E7C6D6958765C43FFBA375A04BD382E426670ABBB6A864BB97E85042E8D8C199D368118D66A10BD9BF3AAF46FEC052F89ECAC38F795D8D3DBF77416B89602E99AF",
            "1",
        },
        /* m = (order - 1) */
        "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005448",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: 00G = order*1G */
    {
        "Multiplication: 0G = order*1G",
        /* R = 0G */
        {
            "0",
            "1",
            "0",
        },
        /* m = order */
        "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
    
    /* Multiplication: -G = -1*1G */
    {
        "Multiplication: -G = -1*1G",
        /* R = -G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "00E7C6D6958765C43FFBA375A04BD382E426670ABBB6A864BB97E85042E8D8C199D368118D66A10BD9BF3AAF46FEC052F89ECAC38F795D8D3DBF77416B89602E99AF",
            "1",
        },
        /* m = -1 */
        "-1",
        /* P = 1G */
        {
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            "1",
        },
        /* n = 0 */
        "0",
        /* Q = 0G */
        {
            "0",
            "1",
            "0",
        },
        ECCOP_POINT_MUL
    },
};

void test_ecp_secp192r1_internal(void)
{
    test_ecp_secp_sub_internal(MBEDTLS_ECP_DP_SECP192R1, 
                            secp192r1_test_mxP_plus_nxQ_vector, 
                            sizeof (secp192r1_test_mxP_plus_nxQ_vector) / sizeof (secp192r1_test_mxP_plus_nxQ_vector[0]),
                            __func__);
}

void test_ecp_secp384r1_internal(void)
{
    test_ecp_secp_sub_internal(MBEDTLS_ECP_DP_SECP384R1,
                            secp384r1_test_mxP_plus_nxQ_vector, 
                            sizeof (secp384r1_test_mxP_plus_nxQ_vector) / sizeof (secp384r1_test_mxP_plus_nxQ_vector[0]),
                            __func__);
}

void test_ecp_secp521r1_internal(void)
{
    test_ecp_secp_sub_internal(MBEDTLS_ECP_DP_SECP521R1,
                            secp521r1_test_mxP_plus_nxQ_vector, 
                            sizeof (secp521r1_test_mxP_plus_nxQ_vector) / sizeof (secp521r1_test_mxP_plus_nxQ_vector[0]),
                            __func__);
}

static void test_ecp_secp_sub_internal(mbedtls_ecp_group_id id,
                            const ecp_test_mxP_plus_nxQ *test_mxP_plus_nxQ_vector, 
                            size_t test_mxP_plus_nxQ_size,
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
    
    mbedtls_ecp_point mP_plus_nQ;
    mbedtls_ecp_point_init(&mP_plus_nQ);
    
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, id));
    
    MBEDTLS_MPI_CHK(mbedtls_internal_ecp_grp_capable(&grp) ? 0 : MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE);
    MBEDTLS_MPI_CHK(mbedtls_internal_ecp_init(&grp));

    /* Test cases: R = m*P + n*Q */
    {
        const ecp_test_mxP_plus_nxQ *mxP_plus_nxQ = test_mxP_plus_nxQ_vector;
        const ecp_test_mxP_plus_nxQ *mxP_plus_nxQ_end = test_mxP_plus_nxQ_vector + test_mxP_plus_nxQ_size;
        
        for (; mxP_plus_nxQ != mxP_plus_nxQ_end; mxP_plus_nxQ ++) {
            printf("  Testing %s ... ", mxP_plus_nxQ->name);
            
            /* Import R */
            if (strcmp(mxP_plus_nxQ->R.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&R));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&R, 16, mxP_plus_nxQ->R.x, mxP_plus_nxQ->R.y));
            }
            
            /* Import m */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&m, 10, mxP_plus_nxQ->m));
            /* Import P */
            if (strcmp(mxP_plus_nxQ->P.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&P));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&P, 16, mxP_plus_nxQ->P.x, mxP_plus_nxQ->P.y));
            }
            
            /* Import n */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&n, 10, mxP_plus_nxQ->n));
            /* Import Q */
            if (strcmp(mxP_plus_nxQ->Q.z, "0") == 0) {
                MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(&Q));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_string(&Q, 16, mxP_plus_nxQ->Q.x, mxP_plus_nxQ->Q.y));
            }
            
            /* Run R = m*P + n*Q */
            if (mxP_plus_nxQ->eccop == ECCOP_POINT_MUL && mbedtls_mpi_cmp_int(&m, 0) < 0) {
                MBEDTLS_MPI_CHK(mbedtls_internal_ecp_mul(&grp, &mP_plus_nQ, &m, &P));
            } else {
                MBEDTLS_MPI_CHK(mbedtls_internal_run_eccop(&grp, &mP_plus_nQ, &m, &P, &n, &Q, mxP_plus_nxQ->eccop));
            }
            
            /* Verify the result */
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_cmp(&R, &mP_plus_nQ));
            
            printf("OK\n");
        }
    }    
    
cleanup:

    mbedtls_internal_ecp_free(&grp);
    mbedtls_ecp_point_free(&mP_plus_nQ);
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
