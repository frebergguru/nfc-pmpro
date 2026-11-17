#include "hidraw.h"
#include <string.h>

size_t pmpro_fill_report(unsigned char dst[64], const unsigned char *src, size_t len)
{
    memset(dst, 0, PMPRO_REPORT_LEN);
    if (len > PMPRO_REPORT_LEN)
        len = PMPRO_REPORT_LEN;
    if (len && src)
        memcpy(dst, src, len);
    return len;
}
