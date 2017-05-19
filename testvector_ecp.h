#ifndef TESTVECTOR_ECP_H
#define TESTVECTOR_ECP_H

#include "mbed.h"
#include "mbedtls/ecp.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_ECP_C)

#define ECCOP_POINT_MUL     (0x0UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_MODULE        (0x1UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_ADD     (0x2UL << CRPT_ECC_CTL_ECCOP_Pos)
#define ECCOP_POINT_DOUBLE  (0x3UL << CRPT_ECC_CTL_ECCOP_Pos)

typedef struct {
    char    x[160];
    char    y[160];
    char    z[160];
} testvector_ecp_point_t;

/* R = m*G */
typedef struct {
    char                    name[50];
    testvector_ecp_point_t  R;
    char                    m[160];
} testvector_ecp_mxG_t;

/* R = m*P for Montgomery curve */
typedef struct {
    char                    name[80];
    testvector_ecp_point_t  R_le;
    char                    m_le[160];
    testvector_ecp_point_t  P_le;
} testvector_ecp_montgomery_mxP_t;

/* Deduce y-coord from x-coord on Montgomery curve */
typedef struct {
    char                    name[80];
    testvector_ecp_point_t  P;
} testvector_ecp_montgomery_deduce_y_t;

/* R = m*P + n*Q */
typedef struct {
    char                    name[80];
    testvector_ecp_point_t  R;
    char                    m[160];
    testvector_ecp_point_t  P;
    char                    n[160];
    testvector_ecp_point_t  Q;
    bool                    is_eccop;   // add/double/mul or muladd (R = m*P + n*Q)
                                        // Crypto ECC H/W doesn't support muladd directly.
    uint32_t                eccop;
} testvector_ecp_mxP_plus_nxQ_t;

/* ECDSA */
typedef struct {
    char                    name[80];
    char                    msg[520];
    char                    d[160];     // Private key
    testvector_ecp_point_t  Q;          // Public key
    char                    k[160];     // The random value used in calculating signature (r, s)
    char                    r[160];
    char                    s[160];
} testvector_ecp_ecdsa_t;

extern const testvector_ecp_point_t testvector_ecp_secp192r1_G;
extern const testvector_ecp_point_t testvector_ecp_secp384r1_G;
extern const testvector_ecp_point_t testvector_ecp_secp521r1_G;

extern const testvector_ecp_mxG_t testvector_ecp_secp192r1_mxG[];
extern const testvector_ecp_mxG_t testvector_ecp_secp384r1_mxG[];
extern const testvector_ecp_mxG_t testvector_ecp_secp521r1_mxG[];

extern const testvector_ecp_mxP_plus_nxQ_t testvector_ecp_secp192r1_mxP_plus_nxQ[];
extern const testvector_ecp_mxP_plus_nxQ_t testvector_ecp_secp384r1_mxP_plus_nxQ[];
extern const testvector_ecp_mxP_plus_nxQ_t testvector_ecp_secp521r1_mxP_plus_nxQ[];

extern const testvector_ecp_ecdsa_t testvector_ecp_secp192r1_ecdsa[];
extern const testvector_ecp_ecdsa_t testvector_ecp_secp384r1_ecdsa[];
extern const testvector_ecp_ecdsa_t testvector_ecp_secp521r1_ecdsa[];

extern const testvector_ecp_montgomery_mxP_t testvector_ecp_curve25519_mxP[];
extern const testvector_ecp_montgomery_mxP_t testvector_ecp_curve448_mxP[];

extern const testvector_ecp_montgomery_deduce_y_t testvector_ecp_curve25519_deduce_y[];
extern const testvector_ecp_montgomery_deduce_y_t testvector_ecp_curve448_deduce_y[];

#endif  /* MBEDTLS_ECP_C */

#ifdef __cplusplus
}
#endif


#endif /* TESTVECTOR_ECP_H */
