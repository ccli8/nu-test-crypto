#if !defined(TARGET_M480)

/*
 *  FIPS-180-2 compliant SHA-384/512 implementation
 *
 *  Copyright The Mbed TLS Contributors
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
/*
 *  The SHA-512 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include "common.h"

#if defined(MBEDTLS_SHA512_C)

#include "sha512_alt_sw.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(_MSC_VER) || defined(__WATCOMC__)
  #define UL64(x) x##ui64
#else
  #define UL64(x) x##ULL
#endif

#include <string.h>

#define SHA512_VALIDATE_RET(cond)                           \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_SHA512_BAD_INPUT_DATA )
#define SHA512_VALIDATE(cond)  MBEDTLS_INTERNAL_VALIDATE( cond )

#if defined(MBEDTLS_SHA512_ALT)

/*
 * 64-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )       \
        | ( (uint64_t) (b)[(i) + 1] << 48 )       \
        | ( (uint64_t) (b)[(i) + 2] << 40 )       \
        | ( (uint64_t) (b)[(i) + 3] << 32 )       \
        | ( (uint64_t) (b)[(i) + 4] << 24 )       \
        | ( (uint64_t) (b)[(i) + 5] << 16 )       \
        | ( (uint64_t) (b)[(i) + 6] <<  8 )       \
        | ( (uint64_t) (b)[(i) + 7]       );      \
}
#endif /* GET_UINT64_BE */

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 7] = (unsigned char) ( (n)       );       \
}
#endif /* PUT_UINT64_BE */

#if defined(MBEDTLS_SHA512_SMALLER)
static void sha512_put_uint64_be( uint64_t n, unsigned char *b, uint8_t i )
{
    PUT_UINT64_BE(n, b, i);
}
#else
#define sha512_put_uint64_be    PUT_UINT64_BE
#endif /* MBEDTLS_SHA512_SMALLER */

void mbedtls_sha512_sw_init( mbedtls_sha512_sw_context *ctx )
{
    SHA512_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_sha512_sw_context ) );
}

void mbedtls_sha512_sw_free( mbedtls_sha512_sw_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha512_sw_context ) );
}

void mbedtls_sha512_sw_clone( mbedtls_sha512_sw_context *dst,
                           const mbedtls_sha512_sw_context *src )
{
    SHA512_VALIDATE( dst != NULL );
    SHA512_VALIDATE( src != NULL );

    *dst = *src;
}

/*
 * SHA-512 context setup
 */
int mbedtls_sha512_sw_starts_ret( mbedtls_sha512_sw_context *ctx, int is384 )
{
    SHA512_VALIDATE_RET( ctx != NULL );
#if !defined(MBEDTLS_SHA512_NO_SHA384)
    SHA512_VALIDATE_RET( is384 == 0 || is384 == 1 );
#else
    SHA512_VALIDATE_RET( is384 == 0 );
#endif

    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if( is384 == 0 )
    {
        /* SHA-512 */
        ctx->state[0] = UL64(0x6A09E667F3BCC908);
        ctx->state[1] = UL64(0xBB67AE8584CAA73B);
        ctx->state[2] = UL64(0x3C6EF372FE94F82B);
        ctx->state[3] = UL64(0xA54FF53A5F1D36F1);
        ctx->state[4] = UL64(0x510E527FADE682D1);
        ctx->state[5] = UL64(0x9B05688C2B3E6C1F);
        ctx->state[6] = UL64(0x1F83D9ABFB41BD6B);
        ctx->state[7] = UL64(0x5BE0CD19137E2179);
    }
    else
    {
#if defined(MBEDTLS_SHA512_NO_SHA384)
        return( MBEDTLS_ERR_SHA512_BAD_INPUT_DATA );
#else
        /* SHA-384 */
        ctx->state[0] = UL64(0xCBBB9D5DC1059ED8);
        ctx->state[1] = UL64(0x629A292A367CD507);
        ctx->state[2] = UL64(0x9159015A3070DD17);
        ctx->state[3] = UL64(0x152FECD8F70E5939);
        ctx->state[4] = UL64(0x67332667FFC00B31);
        ctx->state[5] = UL64(0x8EB44A8768581511);
        ctx->state[6] = UL64(0xDB0C2E0D64F98FA7);
        ctx->state[7] = UL64(0x47B5481DBEFA4FA4);
#endif /* MBEDTLS_SHA512_NO_SHA384 */
    }

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    ctx->is384 = is384;
#endif

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_sw_starts( mbedtls_sha512_sw_context *ctx,
                            int is384 )
{
    mbedtls_sha512_sw_starts_ret( ctx, is384 );
}
#endif

#if !defined(MBEDTLS_SHA512_PROCESS_ALT)

/*
 * Round constants
 */
static const uint64_t K[80] =
{
    UL64(0x428A2F98D728AE22),  UL64(0x7137449123EF65CD),
    UL64(0xB5C0FBCFEC4D3B2F),  UL64(0xE9B5DBA58189DBBC),
    UL64(0x3956C25BF348B538),  UL64(0x59F111F1B605D019),
    UL64(0x923F82A4AF194F9B),  UL64(0xAB1C5ED5DA6D8118),
    UL64(0xD807AA98A3030242),  UL64(0x12835B0145706FBE),
    UL64(0x243185BE4EE4B28C),  UL64(0x550C7DC3D5FFB4E2),
    UL64(0x72BE5D74F27B896F),  UL64(0x80DEB1FE3B1696B1),
    UL64(0x9BDC06A725C71235),  UL64(0xC19BF174CF692694),
    UL64(0xE49B69C19EF14AD2),  UL64(0xEFBE4786384F25E3),
    UL64(0x0FC19DC68B8CD5B5),  UL64(0x240CA1CC77AC9C65),
    UL64(0x2DE92C6F592B0275),  UL64(0x4A7484AA6EA6E483),
    UL64(0x5CB0A9DCBD41FBD4),  UL64(0x76F988DA831153B5),
    UL64(0x983E5152EE66DFAB),  UL64(0xA831C66D2DB43210),
    UL64(0xB00327C898FB213F),  UL64(0xBF597FC7BEEF0EE4),
    UL64(0xC6E00BF33DA88FC2),  UL64(0xD5A79147930AA725),
    UL64(0x06CA6351E003826F),  UL64(0x142929670A0E6E70),
    UL64(0x27B70A8546D22FFC),  UL64(0x2E1B21385C26C926),
    UL64(0x4D2C6DFC5AC42AED),  UL64(0x53380D139D95B3DF),
    UL64(0x650A73548BAF63DE),  UL64(0x766A0ABB3C77B2A8),
    UL64(0x81C2C92E47EDAEE6),  UL64(0x92722C851482353B),
    UL64(0xA2BFE8A14CF10364),  UL64(0xA81A664BBC423001),
    UL64(0xC24B8B70D0F89791),  UL64(0xC76C51A30654BE30),
    UL64(0xD192E819D6EF5218),  UL64(0xD69906245565A910),
    UL64(0xF40E35855771202A),  UL64(0x106AA07032BBD1B8),
    UL64(0x19A4C116B8D2D0C8),  UL64(0x1E376C085141AB53),
    UL64(0x2748774CDF8EEB99),  UL64(0x34B0BCB5E19B48A8),
    UL64(0x391C0CB3C5C95A63),  UL64(0x4ED8AA4AE3418ACB),
    UL64(0x5B9CCA4F7763E373),  UL64(0x682E6FF3D6B2B8A3),
    UL64(0x748F82EE5DEFB2FC),  UL64(0x78A5636F43172F60),
    UL64(0x84C87814A1F0AB72),  UL64(0x8CC702081A6439EC),
    UL64(0x90BEFFFA23631E28),  UL64(0xA4506CEBDE82BDE9),
    UL64(0xBEF9A3F7B2C67915),  UL64(0xC67178F2E372532B),
    UL64(0xCA273ECEEA26619C),  UL64(0xD186B8C721C0C207),
    UL64(0xEADA7DD6CDE0EB1E),  UL64(0xF57D4F7FEE6ED178),
    UL64(0x06F067AA72176FBA),  UL64(0x0A637DC5A2C898A6),
    UL64(0x113F9804BEF90DAE),  UL64(0x1B710B35131C471B),
    UL64(0x28DB77F523047D84),  UL64(0x32CAAB7B40C72493),
    UL64(0x3C9EBE0A15C9BEBC),  UL64(0x431D67C49C100D4C),
    UL64(0x4CC5D4BECB3E42B6),  UL64(0x597F299CFC657E2A),
    UL64(0x5FCB6FAB3AD6FAEC),  UL64(0x6C44198C4A475817)
};

int mbedtls_internal_sha512_sw_process( mbedtls_sha512_sw_context *ctx,
                                     const unsigned char data[128] )
{
    int i;
    struct
    {
        uint64_t temp1, temp2, W[80];
        uint64_t A[8];
    } local;

    SHA512_VALIDATE_RET( ctx != NULL );
    SHA512_VALIDATE_RET( (const unsigned char *)data != NULL );

#define  SHR(x,n) ((x) >> (n))
#define ROTR(x,n) (SHR((x),(n)) | ((x) << (64 - (n))))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^  SHR(x, 7))
#define S1(x) (ROTR(x,19) ^ ROTR(x,61) ^  SHR(x, 6))

#define S2(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define S3(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))

#define F0(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

#define P(a,b,c,d,e,f,g,h,x,K)                                      \
    do                                                              \
    {                                                               \
        local.temp1 = (h) + S3(e) + F1((e),(f),(g)) + (K) + (x);    \
        local.temp2 = S2(a) + F0((a),(b),(c));                      \
        (d) += local.temp1; (h) = local.temp1 + local.temp2;        \
    } while( 0 )

    for( i = 0; i < 8; i++ )
        local.A[i] = ctx->state[i];

#if defined(MBEDTLS_SHA512_SMALLER)
    for( i = 0; i < 80; i++ )
    {
        if( i < 16 )
        {
            GET_UINT64_BE( local.W[i], data, i << 3 );
        }
        else
        {
            local.W[i] = S1(local.W[i -  2]) + local.W[i -  7] +
                   S0(local.W[i - 15]) + local.W[i - 16];
        }

        P( local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
           local.A[5], local.A[6], local.A[7], local.W[i], K[i] );

        local.temp1 = local.A[7]; local.A[7] = local.A[6];
        local.A[6] = local.A[5]; local.A[5] = local.A[4];
        local.A[4] = local.A[3]; local.A[3] = local.A[2];
        local.A[2] = local.A[1]; local.A[1] = local.A[0];
        local.A[0] = local.temp1;
    }
#else /* MBEDTLS_SHA512_SMALLER */
    for( i = 0; i < 16; i++ )
    {
        GET_UINT64_BE( local.W[i], data, i << 3 );
    }

    for( ; i < 80; i++ )
    {
        local.W[i] = S1(local.W[i -  2]) + local.W[i -  7] +
               S0(local.W[i - 15]) + local.W[i - 16];
    }

    i = 0;
    do
    {
        P( local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
           local.A[5], local.A[6], local.A[7], local.W[i], K[i] ); i++;
        P( local.A[7], local.A[0], local.A[1], local.A[2], local.A[3],
           local.A[4], local.A[5], local.A[6], local.W[i], K[i] ); i++;
        P( local.A[6], local.A[7], local.A[0], local.A[1], local.A[2],
           local.A[3], local.A[4], local.A[5], local.W[i], K[i] ); i++;
        P( local.A[5], local.A[6], local.A[7], local.A[0], local.A[1],
           local.A[2], local.A[3], local.A[4], local.W[i], K[i] ); i++;
        P( local.A[4], local.A[5], local.A[6], local.A[7], local.A[0],
           local.A[1], local.A[2], local.A[3], local.W[i], K[i] ); i++;
        P( local.A[3], local.A[4], local.A[5], local.A[6], local.A[7],
           local.A[0], local.A[1], local.A[2], local.W[i], K[i] ); i++;
        P( local.A[2], local.A[3], local.A[4], local.A[5], local.A[6],
           local.A[7], local.A[0], local.A[1], local.W[i], K[i] ); i++;
        P( local.A[1], local.A[2], local.A[3], local.A[4], local.A[5],
           local.A[6], local.A[7], local.A[0], local.W[i], K[i] ); i++;
    }
    while( i < 80 );
#endif /* MBEDTLS_SHA512_SMALLER */

    for( i = 0; i < 8; i++ )
        ctx->state[i] += local.A[i];

    /* Zeroise buffers and variables to clear sensitive data from memory. */
    mbedtls_platform_zeroize( &local, sizeof( local ) );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_sw_process( mbedtls_sha512_sw_context *ctx,
                             const unsigned char data[128] )
{
    mbedtls_internal_sha512_sw_process( ctx, data );
}
#endif
#endif /* !MBEDTLS_SHA512_PROCESS_ALT */

/*
 * SHA-512 process buffer
 */
int mbedtls_sha512_sw_update_ret( mbedtls_sha512_sw_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t fill;
    unsigned int left;

    SHA512_VALIDATE_RET( ctx != NULL );
    SHA512_VALIDATE_RET( ilen == 0 || input != NULL );

    if( ilen == 0 )
        return( 0 );

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = 128 - left;

    ctx->total[0] += (uint64_t) ilen;

    if( ctx->total[0] < (uint64_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );

        if( ( ret = mbedtls_internal_sha512_sw_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 128 )
    {
        if( ( ret = mbedtls_internal_sha512_sw_process( ctx, input ) ) != 0 )
            return( ret );

        input += 128;
        ilen  -= 128;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_sw_update( mbedtls_sha512_sw_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    mbedtls_sha512_sw_update_ret( ctx, input, ilen );
}
#endif

/*
 * SHA-512 final digest
 */
int mbedtls_sha512_sw_finish_ret( mbedtls_sha512_sw_context *ctx,
                               unsigned char output[64] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned used;
    uint64_t high, low;

    SHA512_VALIDATE_RET( ctx != NULL );
    SHA512_VALIDATE_RET( (unsigned char *)output != NULL );

    /*
     * Add padding: 0x80 then 0x00 until 16 bytes remain for the length
     */
    used = ctx->total[0] & 0x7F;

    ctx->buffer[used++] = 0x80;

    if( used <= 112 )
    {
        /* Enough room for padding + length in current block */
        memset( ctx->buffer + used, 0, 112 - used );
    }
    else
    {
        /* We'll need an extra block */
        memset( ctx->buffer + used, 0, 128 - used );

        if( ( ret = mbedtls_internal_sha512_sw_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        memset( ctx->buffer, 0, 112 );
    }

    /*
     * Add message length
     */
    high = ( ctx->total[0] >> 61 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    sha512_put_uint64_be( high, ctx->buffer, 112 );
    sha512_put_uint64_be( low,  ctx->buffer, 120 );

    if( ( ret = mbedtls_internal_sha512_sw_process( ctx, ctx->buffer ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    sha512_put_uint64_be( ctx->state[0], output,  0 );
    sha512_put_uint64_be( ctx->state[1], output,  8 );
    sha512_put_uint64_be( ctx->state[2], output, 16 );
    sha512_put_uint64_be( ctx->state[3], output, 24 );
    sha512_put_uint64_be( ctx->state[4], output, 32 );
    sha512_put_uint64_be( ctx->state[5], output, 40 );

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    if( ctx->is384 == 0 )
#endif
    {
        sha512_put_uint64_be( ctx->state[6], output, 48 );
        sha512_put_uint64_be( ctx->state[7], output, 56 );
    }

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_sw_finish( mbedtls_sha512_sw_context *ctx,
                            unsigned char output[64] )
{
    mbedtls_sha512_sw_finish_ret( ctx, output );
}
#endif

#endif /* MBEDTLS_SHA512_ALT */

/*
 * output = SHA-512( input buffer )
 */
int mbedtls_sha512_sw_ret( const unsigned char *input,
                    size_t ilen,
                    unsigned char output[64],
                    int is384 )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sha512_sw_context ctx;

#if !defined(MBEDTLS_SHA512_NO_SHA384)
    SHA512_VALIDATE_RET( is384 == 0 || is384 == 1 );
#else
    SHA512_VALIDATE_RET( is384 == 0 );
#endif
    SHA512_VALIDATE_RET( ilen == 0 || input != NULL );
    SHA512_VALIDATE_RET( (unsigned char *)output != NULL );

    mbedtls_sha512_sw_init( &ctx );

    if( ( ret = mbedtls_sha512_sw_starts_ret( &ctx, is384 ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sha512_sw_update_ret( &ctx, input, ilen ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sha512_sw_finish_ret( &ctx, output ) ) != 0 )
        goto exit;

exit:
    mbedtls_sha512_sw_free( &ctx );

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha512_sw( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[64],
                     int is384 )
{
    mbedtls_sha512_sw_ret( input, ilen, output, is384 );
}
#endif

#endif /* MBEDTLS_SHA512_C */

#endif /* !defined(TARGET_M480) */
