/* probe.c — command-line RE helper (built as `pmprobe`).
 *
 *   pmprobe listen            listen-only; logs frames (present a card / press
 *                             the device button). Sends nothing.
 *   pmprobe send <hex...>     send one report, print responses.
 *   pmprobe scan [lo] [hi]    send single-byte commands lo..hi (hex), log replies
 */
#include "hidraw.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void show(const char *dir, const unsigned char *d, int n)
{
    char hex[200], asc[80];
    pmpro_hex(d, (size_t)n, hex, sizeof hex);
    pmpro_ascii(d, (size_t)n, asc, sizeof asc);
    int nz = n;
    while (nz > 0 && d[nz - 1] == 0) nz--;
    printf("%s [%2d] %s  |%s|\n", dir, nz, hex, asc);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* line-buffered so captures survive timeout */
    const char *mode = argc > 1 ? argv[1] : "listen";
    pmpro_dev dev;
    if (!pmpro_open(&dev, NULL)) {
        fprintf(stderr, "ERROR: %s\n", dev.err);
        return 1;
    }
    printf("opened %s\n", dev.path);

    unsigned char buf[PMPRO_REPORT_LEN];

    if (strcmp(mode, "listen") == 0) {
        printf(">>> listening. Present a card / press the device button. Ctrl-C to stop.\n");
        for (;;) {
            int n = pmpro_read(&dev, buf, 1000);
            if (n > 0) show("IN ", buf, n);
        }
    } else if (strcmp(mode, "send") == 0) {
        unsigned char out[PMPRO_REPORT_LEN];
        char joined[512] = {0};
        for (int i = 2; i < argc; ++i) {
            strncat(joined, argv[i], sizeof joined - strlen(joined) - 1);
            strncat(joined, " ", sizeof joined - strlen(joined) - 1);
        }
        int n = pmpro_parse_hex(joined, out, sizeof out);
        if (n < 0) { fprintf(stderr, "bad hex\n"); return 2; }
        show("OUT", out, PMPRO_REPORT_LEN);
        pmpro_write(&dev, out, (size_t)n);
        int got = 0;
        for (;;) {
            int r = pmpro_read(&dev, buf, 800);
            if (r <= 0) break;
            show("IN ", buf, r);
            got = 1;
        }
        if (!got) printf("(no response)\n");
    } else if (strcmp(mode, "scan") == 0) {
        int lo = argc > 2 ? (int)strtol(argv[2], NULL, 16) : 0x00;
        int hi = argc > 3 ? (int)strtol(argv[3], NULL, 16) : 0x1f;
        printf(">>> scan 0x%02x..0x%02x\n", lo, hi);
        for (int cmd = lo; cmd <= hi; ++cmd) {
            unsigned char one = (unsigned char)cmd;
            /* flush stale input */
            while (pmpro_read(&dev, buf, 0) > 0) {}
            printf("--- cmd 0x%02x\n", cmd);
            pmpro_write(&dev, &one, 1);
            int got = 0;
            for (int k = 0; k < 6; ++k) {
                int r = pmpro_read(&dev, buf, 120);
                if (r <= 0) break;
                show("IN ", buf, r);
                got = 1;
            }
            if (!got) printf("    (no response)\n");
        }
    } else {
        fprintf(stderr, "usage: pmprobe [listen|send <hex>|scan [lo] [hi]]\n");
    }
    pmpro_close(&dev);
    return 0;
}
