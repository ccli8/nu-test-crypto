#include "mbed.h"
#include "untriaged_utils.h"

int hexstr_le2be(char *be, size_t be_maxsize, const char *le)
{
    size_t len = strlen(le);

    /* Buffer size enough? */
    if (be_maxsize < (len + 1)) {
        return -1;
    }

    /* Trailing NULL for all cases below */
    be[len] = '\0';

    /* Empty string */
    if (len == 0) {
        return 0;
    }

    /* Special handling for odd length */
    if (len & 1) {
        be[0] = le[len - 1];
        be ++;
        len --;

        /* Empty string */
        if (len == 0) {
            return 0;
        }
    }

    MBED_ASSERT(len >= 2 && (len & 1) == 0);
    size_t swap_index_sum_even = len - 2;
    size_t swap_index_sum_odd = len;

    size_t i;
    for (i = 0; i < len; i ++) {
        if (i & 1) {
            be[i] = le[swap_index_sum_odd - i];
        } else {
            be[i] = le[swap_index_sum_even - i];
        }
    }

    return 0;
}

int unsafe_rand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

void dump_bin(const unsigned char *data, size_t length)
{
    size_t rmn = length;

    while (rmn >= 8) {
        printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
               data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
        data += 8;
        rmn -= 8;
    }

    if (rmn >= 4) {
        printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, ", data[0], data[1], data[2], data[3]);
        data += 4;
        rmn -= 4;
    }

    if (rmn >= 2) {
        printf("0x%02x, 0x%02x, ", data[0], data[1]);
        data += 2;
        rmn -= 2;
    }

    if (rmn) {
        printf("0x%02x, ", data[0]);
        data += 1;
        rmn -= 1;
    }

    printf("\n");
}
