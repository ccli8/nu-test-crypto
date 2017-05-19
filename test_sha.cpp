#include "mbed.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "sha1_alt_sw.h"
#include "sha256_alt_sw.h"
#include "sha512_alt_sw.h"

#include "test_crypto_cm.h"

#if defined(MBEDTLS_SHA1_C)

void test_sha1(void)
{
    if (mbedtls_sha1_self_test(1)) {
        printf("mbedtls_sha1_self_test failed\n\n");
    }
    else {
        printf("mbedtls_sha1_self_test passed\n\n");
    }
}

void test_sha1_nodata(void)
{
    /* Test SHA-1 no data */
    printf("SHA-1 no data ...\n");
    
    unsigned char shasum1[20], shasum2[20];
    mbedtls_sha1_context ctx1;
    mbedtls_sha1_sw_context ctx2;
    
    mbedtls_sha1_init(&ctx1);
    mbedtls_sha1_sw_init(&ctx2);
    
    mbedtls_sha1_starts(&ctx1);
    mbedtls_sha1_finish(&ctx1, shasum1);
    mbedtls_sha1_sw_starts(&ctx2);
    mbedtls_sha1_sw_finish(&ctx2, shasum2);
    
    mbedtls_sha1_free(&ctx1);
    mbedtls_sha1_sw_free(&ctx2);
    
    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-1 no data FAILED\n");
    }
    else {
        printf("SHA-1 no data OK\n");
    }
}

void test_sha1_random_updates(void)
{
    /* Test SHA-1 random updates */
    printf("SHA-1 random updates ...\n");
    
    unsigned char shasum1[20], shasum2[20];
    mbedtls_sha1_context ctx1;
    mbedtls_sha1_sw_context ctx2;
    unsigned i, j;
    size_t update_sizes[] = {64, 128, 1, 3, 4, 53, 1, 63, 2, 61, 64, 128, 255};

    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha1_init(&ctx1);
    mbedtls_sha1_sw_init(&ctx2);
    
    mbedtls_sha1_starts(&ctx1);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha1_update(&ctx1, test_buf1, update_sizes[i]);
    }
    mbedtls_sha1_finish(&ctx1, shasum1);
    
    mbedtls_sha1_sw_starts(&ctx2);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha1_sw_update(&ctx2, test_buf1, update_sizes[i]);
    }
    mbedtls_sha1_sw_finish(&ctx2, shasum2);
    
    mbedtls_sha1_free(&ctx1);
    mbedtls_sha1_sw_free(&ctx2);
    
    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-1 random updates FAILED\n");
    }
    else {
        printf("SHA-1 random updates OK\n");
    }
}

void test_sha1_clone(uint32_t len1, uint32_t len2)
{
    /* Test SHA-1 clone */
    printf("SHA-1 clone ...\n");
    
    unsigned char shasum1[20], shasum11[20], shasum2[20];
    mbedtls_sha1_context ctx1, ctx11;
    mbedtls_sha1_sw_context ctx2;
    unsigned j;
    
    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha1_init(&ctx1);
    mbedtls_sha1_sw_init(&ctx2);

    mbedtls_sha1_starts(&ctx1);
    mbedtls_sha1_sw_starts(&ctx2);

    // Update ctx1/ctx2
    mbedtls_sha1_update(&ctx1, test_buf1, len1);
    mbedtls_sha1_sw_update(&ctx2, test_buf1, len1);

    // Clone ctx11
    mbedtls_sha1_init(&ctx11);
    mbedtls_sha1_clone(&ctx11, &ctx1);

    // Update ctx1/ctx11/ctx2
    mbedtls_sha1_update(&ctx1, test_buf1, len2);
    mbedtls_sha1_update(&ctx11, test_buf1, len2);
    mbedtls_sha1_sw_update(&ctx2, test_buf1, len2);

    // Finish ctx1/ctx11/ctx2
    mbedtls_sha1_finish(&ctx1, shasum1);
    mbedtls_sha1_finish(&ctx11, shasum11);
    mbedtls_sha1_sw_finish(&ctx2, shasum2);

    // Free ctx1/ctx11/ctx2
    mbedtls_sha1_free(&ctx1);
    mbedtls_sha1_free(&ctx11);
    mbedtls_sha1_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof(shasum2)) ||
        memcmp(shasum11, shasum2, sizeof(shasum2))) {
        printf("SHA-1 clone (len1=%d, len2=%d) FAILED\n", len1, len2);
    }
    else {
        printf("SHA-1 clone (len1=%d, len2=%d) OK\n", len1, len2);
    }
}

void test_sha1_perf(void)
{
    /* Test SHA-1 performance */
    printf("SHA-1 performance ...\n");
    
    unsigned char shasum1[20], shasum2[20];
    mbedtls_sha1_context ctx1;
    mbedtls_sha1_sw_context ctx2;
    Timer t1, t2;
    unsigned i;

    memset(test_buf1, 'a', sizeof (test_buf1));
    memset(test_buf2, 'a', sizeof (test_buf2));
    
    mbedtls_sha1_init(&ctx1);
    mbedtls_sha1_sw_init(&ctx2);
    
    t1.start();
    mbedtls_sha1_starts(&ctx1);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha1_update(&ctx1, test_buf1, sizeof (test_buf1));
    }
    mbedtls_sha1_finish(&ctx1, shasum1);
    t1.stop();

    t2.start();
    mbedtls_sha1_sw_starts(&ctx2);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha1_sw_update(&ctx2, test_buf2, sizeof (test_buf2));
    }
    mbedtls_sha1_sw_finish(&ctx2, shasum2);
    t2.stop();

    mbedtls_sha1_free(&ctx1);
    mbedtls_sha1_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-1 performance FAILED\n");
    }
    else {
        printf("SHA-1 CTX1: %d (KB/s)\n", sizeof (test_buf1) * MAXNUM_LOOP / t1.read_ms());
        printf("SHA-1 CTX2: %d (KB/s)\n", sizeof (test_buf2) * MAXNUM_LOOP / t2.read_ms());
    }

    printf("\n");
}

#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)

void test_sha256(void)
{
    if (mbedtls_sha256_self_test(1)) {
        printf("mbedtls_sha256_self_test failed\n\n");
    }
    else {
        printf("mbedtls_sha256_self_test passed\n\n");
    }
}

void test_sha256_nodata(void)
{
    /* Test SHA-256 no data */
    printf("SHA-256 no data ...\n");
    
    unsigned char shasum1[32], shasum2[32];
    mbedtls_sha256_context ctx1;
    mbedtls_sha256_sw_context ctx2;
    
    mbedtls_sha256_init(&ctx1);
    mbedtls_sha256_sw_init(&ctx2);
    
    mbedtls_sha256_starts(&ctx1, 0);
    mbedtls_sha256_finish(&ctx1, shasum1);
    mbedtls_sha256_sw_starts(&ctx2, 0);
    mbedtls_sha256_sw_finish(&ctx2, shasum2);

    mbedtls_sha256_free(&ctx1);
    mbedtls_sha256_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-256 no data FAILED\n");
    }
    else {
        printf("SHA-256 no data OK\n");
    }
}

void test_sha256_random_updates(void)
{
    /* Test SHA-256 random updates */
    printf("SHA-256 random updates ...\n");
    
    unsigned char shasum1[32], shasum2[32];
    mbedtls_sha256_context ctx1;
    mbedtls_sha256_sw_context ctx2;
    unsigned i, j;
    size_t update_sizes[] = {64, 128, 1, 3, 4, 53, 1, 63, 2, 61, 64, 128, 255};

    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha256_init(&ctx1);
    mbedtls_sha256_sw_init(&ctx2);
    
    mbedtls_sha256_starts(&ctx1, 0);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha256_update(&ctx1, test_buf1, update_sizes[i]);
    }
    mbedtls_sha256_finish(&ctx1, shasum1);
    
    mbedtls_sha256_sw_starts(&ctx2, 0);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha256_sw_update(&ctx2, test_buf1, update_sizes[i]);
    }
    mbedtls_sha256_sw_finish(&ctx2, shasum2);
    
    mbedtls_sha256_free(&ctx1);
    mbedtls_sha256_sw_free(&ctx2);
    
    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-256 random updates FAILED\n");
    }
    else {
        printf("SHA-256 random updates OK\n");
    }
}

void test_sha256_clone(uint32_t len1, uint32_t len2)
{
    /* Test SHA-256 clone */
    printf("SHA-256 clone ...\n");
    
    unsigned char shasum1[32], shasum11[32], shasum2[32];
    mbedtls_sha256_context ctx1, ctx11;
    mbedtls_sha256_sw_context ctx2;
    unsigned j;

    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha256_init(&ctx1);
    mbedtls_sha256_sw_init(&ctx2);

    mbedtls_sha256_starts(&ctx1, 0);
    mbedtls_sha256_sw_starts(&ctx2, 0);

    // Update ctx1/ctx2
    mbedtls_sha256_update(&ctx1, test_buf1, len1);
    mbedtls_sha256_sw_update(&ctx2, test_buf1, len1);

    // Clone ctx11
    mbedtls_sha256_init(&ctx11);
    mbedtls_sha256_clone(&ctx11, &ctx1);

    // Update ctx1/ctx11/ctx2
    mbedtls_sha256_update(&ctx1, test_buf1, len2);
    mbedtls_sha256_update(&ctx11, test_buf1, len2);
    mbedtls_sha256_sw_update(&ctx2, test_buf1, len2);

    // Finish ctx1/ctx11/ctx2
    mbedtls_sha256_finish(&ctx1, shasum1);
    mbedtls_sha256_finish(&ctx11, shasum11);
    mbedtls_sha256_sw_finish(&ctx2, shasum2);

    // Free ctx1/ctx11/ctx2
    mbedtls_sha256_free(&ctx1);
    mbedtls_sha256_free(&ctx11);
    mbedtls_sha256_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof(shasum2)) ||
        memcmp(shasum11, shasum2, sizeof(shasum2))) {
        printf("SHA-256 clone (len1=%d, len2=%d) FAILED\n", len1, len2);
    }
    else {
        printf("SHA-256 clone (len1=%d, len2=%d) OK\n", len1, len2);
    }
}

void test_sha256_perf(int is224)
{
    /* Test SHA-2 performance */
    printf("SHA-%s performance ...\n", is224 ? "224" : "256");
    
    unsigned char shasum1[32], shasum2[32];
    mbedtls_sha256_context ctx1;
    mbedtls_sha256_sw_context ctx2;
    Timer t1, t2;
    unsigned i;

    memset(test_buf1, 'a', sizeof (test_buf1));
    memset(test_buf2, 'a', sizeof (test_buf2));
    
    mbedtls_sha256_init(&ctx1);
    mbedtls_sha256_sw_init(&ctx2);
    
    t1.start();
    mbedtls_sha256_starts(&ctx1, is224);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha256_update(&ctx1, test_buf1, sizeof (test_buf1));
    }
    mbedtls_sha256_finish(&ctx1, shasum1);
    t1.stop();

    t2.start();
    mbedtls_sha256_sw_starts(&ctx2, is224);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha256_sw_update(&ctx2, test_buf2, sizeof (test_buf2));
    }
    mbedtls_sha256_sw_finish(&ctx2, shasum2);
    t2.stop();

    mbedtls_sha256_free(&ctx1);
    mbedtls_sha256_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-256 performance FAILED\n");
    }
    else {
        printf("SHA-%s CTX1: %d (KB/s)\n", is224 ? "224" : "256", sizeof (test_buf1) * MAXNUM_LOOP / t1.read_ms());
        printf("SHA-%s CTX2: %d (KB/s)\n", is224 ? "224" : "256", sizeof (test_buf2) * MAXNUM_LOOP / t2.read_ms());
    }

    printf("\n");
}

#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)

void test_sha512(void)
{
    if (mbedtls_sha512_self_test(1)) {
        printf("mbedtls_sha512_self_test failed\n\n");
    }
    else {
        printf("mbedtls_sha512_self_test passed\n\n");
    }
}


void test_sha512_nodata(void)
{
    /* Test SHA-512 no data */
    printf("SHA-512 no data ...\n");
    
    unsigned char shasum1[64], shasum2[64];
    mbedtls_sha512_context ctx1;
    mbedtls_sha512_sw_context ctx2;
    
    mbedtls_sha512_init(&ctx1);
    mbedtls_sha512_sw_init(&ctx2);
    
    mbedtls_sha512_starts(&ctx1, 0);
    mbedtls_sha512_finish(&ctx1, shasum1);
    mbedtls_sha512_sw_starts(&ctx2, 0);
    mbedtls_sha512_sw_finish(&ctx2, shasum2);
    
    mbedtls_sha512_free(&ctx1);
    mbedtls_sha512_sw_free(&ctx2);
    
    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-512 no data FAILED\n");
    }
    else {
        printf("SHA-512 no data OK\n");
    }
}


void test_sha512_random_updates(void)
{
    /* Test SHA-512 random updates */
    printf("SHA-512 random updates ...\n");
    
    unsigned char shasum1[64], shasum2[64];
    mbedtls_sha512_context ctx1;
    mbedtls_sha512_sw_context ctx2;
    unsigned i, j;
    size_t update_sizes[] = {64, 128, 1, 3, 4, 53, 1, 63, 2, 61, 64, 128, 255};

    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha512_init(&ctx1);
    mbedtls_sha512_sw_init(&ctx2);
    
    mbedtls_sha512_starts(&ctx1, 0);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha512_update(&ctx1, test_buf1, update_sizes[i]);
    }
    mbedtls_sha512_finish(&ctx1, shasum1);
    
    mbedtls_sha512_sw_starts(&ctx2, 0);
    for (i = 0; i < sizeof (update_sizes) / sizeof (update_sizes[0]); i ++) {
        mbedtls_sha512_sw_update(&ctx2, test_buf1, update_sizes[i]);
    }
    mbedtls_sha512_sw_finish(&ctx2, shasum2);
    
    mbedtls_sha512_free(&ctx1);
    mbedtls_sha512_sw_free(&ctx2);
    
    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-512 random updates FAILED\n");
    }
    else {
        printf("SHA-512 random updates OK\n");
    }
}


void test_sha512_clone(uint32_t len1, uint32_t len2)
{
    /* Test SHA-512 clone */
    printf("SHA-512 clone ...\n");

    unsigned char shasum1[64], shasum11[64], shasum2[64];
    mbedtls_sha512_context ctx1, ctx11;
    mbedtls_sha512_sw_context ctx2;
    unsigned j;

    for (j = 0; j < sizeof (test_buf1); j ++) {
        test_buf1[j] = (j * j) & 0xFF;
    }
    
    mbedtls_sha512_init(&ctx1);
    mbedtls_sha512_sw_init(&ctx2);

    mbedtls_sha512_starts(&ctx1, 0);
    mbedtls_sha512_sw_starts(&ctx2, 0);

    // Update ctx1/ctx2
    mbedtls_sha512_update(&ctx1, test_buf1, len1);
    mbedtls_sha512_sw_update(&ctx2, test_buf1, len1);

    // Clone ctx11
    mbedtls_sha512_init(&ctx11);
    mbedtls_sha512_clone(&ctx11, &ctx1);

    // Update ctx1/ctx11/ctx2
    mbedtls_sha512_update(&ctx1, test_buf1, len2);
    mbedtls_sha512_update(&ctx11, test_buf1, len2);
    mbedtls_sha512_sw_update(&ctx2, test_buf1, len2);

    // Finish ctx1/ctx11/ctx2
    mbedtls_sha512_finish(&ctx1, shasum1);
    mbedtls_sha512_finish(&ctx11, shasum11);
    mbedtls_sha512_sw_finish(&ctx2, shasum2);

    // Free ctx1/ctx11/ctx2
    mbedtls_sha512_free(&ctx1);
    mbedtls_sha512_free(&ctx11);
    mbedtls_sha512_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof(shasum2)) ||
        memcmp(shasum11, shasum2, sizeof(shasum2))) {
        printf("SHA-512 clone (len1=%d, len2=%d) FAILED\n", len1, len2);
    }
    else {
        printf("SHA-512 clone (len1=%d, len2=%d) OK\n", len1, len2);
    }
}

void test_sha512_perf(int is384)
{
    /* Test SHA-2 performance */
    printf("SHA-%s performance ...\n", is384 ? "384" : "512");
    
    unsigned char shasum1[64], shasum2[64];
    mbedtls_sha512_context ctx1;
    mbedtls_sha512_sw_context ctx2;
    Timer t1, t2;
    unsigned i;

    memset(test_buf1, 'a', sizeof (test_buf1));
    memset(test_buf2, 'a', sizeof (test_buf2));
    
    mbedtls_sha512_init(&ctx1);
    mbedtls_sha512_sw_init(&ctx2);
    
    t1.start();
    mbedtls_sha512_starts(&ctx1, is384);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha512_update(&ctx1, test_buf1, sizeof (test_buf1));
    }
    mbedtls_sha512_finish(&ctx1, shasum1);
    t1.stop();
    
    t2.start();
    mbedtls_sha512_sw_starts(&ctx2, is384);
    i = MAXNUM_LOOP;
    while (i --) {
        mbedtls_sha512_sw_update(&ctx2, test_buf2, sizeof (test_buf2));
    }
    mbedtls_sha512_sw_finish(&ctx2, shasum2);
    t2.stop();

    mbedtls_sha512_free(&ctx1);
    mbedtls_sha512_sw_free(&ctx2);

    if (memcmp(shasum1, shasum2, sizeof (shasum1))) {
        printf("SHA-512 performance FAILED\n");
    }
    else {
        printf("SHA-%s CTX1: %d (KB/s)\n", is384 ? "384" : "512", sizeof (test_buf1) * MAXNUM_LOOP / t1.read_ms());
        printf("SHA-%s CTX2: %d (KB/s)\n", is384 ? "384" : "512", sizeof (test_buf2) * MAXNUM_LOOP / t2.read_ms());
    }

    printf("\n");
}

#endif /* MBEDTLS_SHA512_C */
