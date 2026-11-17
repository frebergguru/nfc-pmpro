#include "hidraw.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
    unsigned char dst[PMPRO_REPORT_LEN];

    /* short payload: padded with zeros, returns len */
    unsigned char a[3] = {0xDE, 0xAD, 0xBE};
    memset(dst, 0xFF, sizeof dst);
    size_t n = pmpro_fill_report(dst, a, sizeof a);
    assert(n == 3);
    assert(dst[0] == 0xDE && dst[1] == 0xAD && dst[2] == 0xBE);
    for (int i = 3; i < PMPRO_REPORT_LEN; i++)
        assert(dst[i] == 0x00);

    /* oversized payload: truncated at 64, returns 64 */
    unsigned char big[100];
    memset(big, 0x5A, sizeof big);
    n = pmpro_fill_report(dst, big, sizeof big);
    assert(n == PMPRO_REPORT_LEN);
    for (int i = 0; i < PMPRO_REPORT_LEN; i++)
        assert(dst[i] == 0x5A);

    /* empty payload: all zeros, returns 0 */
    n = pmpro_fill_report(dst, NULL, 0);
    assert(n == 0);
    for (int i = 0; i < PMPRO_REPORT_LEN; i++)
        assert(dst[i] == 0x00);

    printf("test_hidraw_common: OK\n");
    return 0;
}
