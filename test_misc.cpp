#include "mbed.h"
#include "test_crypto_cm.h"

void test_hexstr_le2be(void)
{
    int err_cnt = 0;
    Timer t;

    printf("Testing %s\n", "hexstr le2be");

    /* Time measurement starts */
    t.start();

    static const char *testvector_le[] = {
        "", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"
    };
    static const char *testvector_be[] = {
        "", "a", "ab", "cab", "cdab", "ecdab", "efcdab", "gefcdab"
    };

    static char be_act[64];

    const char **le = testvector_le;
    const char **le_end = testvector_le + sizeof(testvector_le) / sizeof(testvector_le[0]);
    const char **be = testvector_be;
    
    for (; le < le_end; le ++, be ++) {
        bool is_error = false;

        printf("  Testing \"%s\" --> \"%s\" ... \n", *le, *be);

        if (!is_error && hexstr_le2be(be_act, sizeof(be_act), *le) != 0) {
            is_error = true;
            err_cnt ++;
        }

        if (!is_error && strcmp(*be, be_act) != 0) {
            printf("    Exp \"%s\", but Act \"%s\"\n", *be, be_act);
            is_error = true;
            err_cnt ++;
        }

        printf("  Testing \"%s\" --> \"%s\" ... %s\n", *le, *be, is_error ? "Error" : "OK");
    }

    /* Time measurement starts */
    t.stop();
    uint32_t ms = t.read_ms();

    printf("\nTesting %s (%d ms) %s\n", "hexstr le2be", ms, err_cnt ? "FAILED" : "OK");
    printf("\n");
}
