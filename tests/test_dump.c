/* test_dump.c — unit tests for the non-crypto logic: dump round-trip,
 * value-block detection, card-type mapping, access-condition decode. */
#include "dump.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("ok   - %s\n", msg); } \
    else      { printf("FAIL - %s\n", msg); fails++; } } while (0)

int main(void)
{
    /* ---- value block detection ---- */
    unsigned char vb[16] = {0x0a,0,0,0, 0xf5,0xff,0xff,0xff, 0x0a,0,0,0, 0x05,0xfa,0x05,0xfa};
    int32_t val = 0; uint8_t addr = 0;
    CHECK(pmpro_value_block(vb, &val, &addr) && val == 10 && addr == 5,
          "value block decoded (value=10, addr=5)");
    unsigned char nvb[16] = {0}; nvb[0] = 1;          /* not a value block */
    CHECK(!pmpro_value_block(nvb, NULL, NULL), "non-value block rejected");
    unsigned char zero[16] = {0};
    CHECK(!pmpro_value_block(zero, NULL, NULL), "all-zero block is not a value block");

    /* ---- card type ---- */
    int sec = -1;
    CHECK(strstr(pmpro_card_type(0x08, 0x0004, 4, &sec), "1K") && sec == 16, "SAK 08 -> 1K/16");
    CHECK(strstr(pmpro_card_type(0x18, 0x0002, 4, &sec), "4K") && sec == 40, "SAK 18 -> 4K/40");
    CHECK(strstr(pmpro_card_type(0x00, 0x0044, 7, NULL), "Ultralight"), "SAK 00 -> Ultralight");

    /* ---- access-condition decode (transport FF 07 80) ---- */
    unsigned char tr[16] = {0xff,0xff,0xff,0xff,0xff,0xff, 0xff,0x07,0x80,0x69,
                            0xff,0xff,0xff,0xff,0xff,0xff};
    char acs[256];
    pmpro_decode_acs(tr, acs, sizeof acs);
    CHECK(strstr(acs, "blk0 rd A|B wr A|B") != NULL, "transport data blocks rd/wr A|B");
    CHECK(strstr(acs, "trailer transport") != NULL, "transport trailer decoded");

    /* ---- dump text round-trip (one 64-byte sector: 3 data + trailer) ---- */
    pmpro_dump d; pmpro_dump_init(&d);
    snprintf(d.uid, sizeof d.uid, "73 9e 70 62");
    pmpro_dump_add_block(&d,
        "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff "
        "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
        "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f "
        "a0 a1 a2 a3 a4 a5 ff 07 80 69 b0 b1 b2 b3 b4 b5");
    char err[128];
    CHECK(pmpro_dump_save(&d, "/tmp/_pmpro_test.pmdump", err, sizeof err), "save .pmdump");
    pmpro_dump d2;
    CHECK(pmpro_dump_load(&d2, "/tmp/_pmpro_test.pmdump", err, sizeof err) &&
          d2.n_blocks == 1 && strcmp(d2.blocks[0], d.blocks[0]) == 0,
          "load .pmdump round-trips the sector");

    /* ---- .mfd (raw) round-trip ---- */
    unsigned char raw[1024];
    for (int i = 0; i < 1024; i++) raw[i] = (unsigned char)i;
    FILE *f = fopen("/tmp/_pmpro_test.mfd", "wb"); fwrite(raw, 1, 1024, f); fclose(f);
    pmpro_dump dm;
    CHECK(pmpro_dump_load(&dm, "/tmp/_pmpro_test.mfd", err, sizeof err) && dm.n_blocks == 16,
          "load 1K .mfd -> 16 sectors");
    CHECK(pmpro_dump_save_mfd(&dm, "/tmp/_pmpro_test2.mfd", err, sizeof err), "export .mfd");
    FILE *g = fopen("/tmp/_pmpro_test2.mfd", "rb");
    unsigned char back[1024]; size_t rd = fread(back, 1, sizeof back, g); fclose(g);
    CHECK(rd == 1024 && memcmp(raw, back, 1024) == 0, ".mfd export is byte-identical");

    /* ---- .keys export (keyA a0a1a2a3a4a5 + keyB b0b1b2b3b4b5) ---- */
    int nk = pmpro_dump_save_keys(&d, "/tmp/_pmpro_test.keys", err, sizeof err);
    CHECK(nk == 2, ".keys export wrote 2 unique keys (keyA + keyB)");

    printf("\n%s\n", fails ? "*** DUMP TESTS FAILED ***" : "*** DUMP TESTS PASS ***");
    return fails ? 1 : 0;
}
