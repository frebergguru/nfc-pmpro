#include "hardnested_glue.h"
#include "session.h"
#include "furui.h"
#include "hardnested/hn_compat.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* mfnestedhard() from the vendored solver (cmdhfmfhard.h pulls GTK-free headers,
 * so declare just what we need here). */
extern int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key,
                        uint8_t trgBlockNo, uint8_t trgKeyType, int hard_low_memory);

/* shared with the collection hook (single-threaded use) */
static pmpro_dev *hn_dev;
static uint32_t hn_uid;
static int hn_first = 1;

/* device key-type byte: solver uses MC_AUTH_A(0x60)/MC_AUTH_B(0x61); the device
 * wants 0=A,1=B. */
static uint8_t dev_type(uint8_t solver_type) { return solver_type == MC_AUTH_B ? 1 : 0; }

/* Collect a batch of encrypted nonces via cmd 0x30 and feed them to the solver.
 * Returns the number fed; sets *cuid_out to the card UID. */
static int pmpro_collect(uint8_t blockNo, uint8_t keyType, const uint8_t *key,
                         uint8_t trgBlockNo, uint8_t trgKeyType,
                         hn_feed_fn feed, uint32_t *cuid_out)
{
    *cuid_out = hn_uid;

    uint8_t p[18];
    p[0] = 0x30;
    p[1] = blockNo;
    p[2] = dev_type(keyType);
    memcpy(p + 3, key, 6);
    p[9]  = trgBlockNo;
    p[10] = dev_type(trgKeyType);
    p[11] = 200;                 /* Attcount: nonces to collect this batch */
    p[12] = hn_first ? 1 : 0;    /* isFirst */
    p[13] = 0; p[14] = 0; p[15] = 0; p[16] = 0;  /* DeviceRandom */
    hn_first = 0;

    uint8_t resp[FURUI_MAXMSG];
    size_t r = furui_exec(hn_dev, p, 17, resp, sizeof resp, 12000);
    if (r < 6 || resp[2] != 1)
        return 0;
    const uint8_t *data = resp + 3;          /* payload after [len][code] */
    size_t dlen = r - 5;                     /* minus [len(2)][code(1)][crc(2)] */

    if (getenv("PMPRO_HN_DEBUG")) {
        fprintf(stderr, "[hn] cmd30 payload %zu bytes:", dlen);
        for (size_t i = 0; i < dlen && i < 64; i++) fprintf(stderr, " %02x", data[i]);
        fprintf(stderr, "\n");
    }

    /* Best-effort record parse: a small header then N records of
     * [nonce_enc(4 LE)][par_enc(1)]. Adjust offsets once validated on a real
     * vulnerable card (use PMPRO_HN_DEBUG=1). */
    int fed = 0;
    size_t hdr = 4;                          /* assume 4-byte header (count/uid) */
    for (size_t off = hdr; off + 5 <= dlen; off += 5) {
        uint32_t nt = (uint32_t)data[off] | (uint32_t)data[off+1] << 8 |
                      (uint32_t)data[off+2] << 16 | (uint32_t)data[off+3] << 24;
        uint8_t par = data[off+4];
        feed(nt, par);
        fed++;
    }
    return fed;
}

int furui_hardnested(pmpro_dev *dev, uint8_t knownBlock, uint8_t knownType,
                     const uint8_t knownKey[6], uint8_t trgBlock, uint8_t trgType,
                     uint8_t found[6], char *log, size_t lcap)
{
    if (!furui_connect(dev)) { snprintf(log, lcap, "connect failed"); return 0; }

    /* get the UID for the solver (cuid) */
    furui_hf_card card;
    if (!furui_read_hf(dev, &card) || card.uid_len < 4) {
        snprintf(log, lcap, "no card on reader");
        return 0;
    }
    hn_uid = (uint32_t)card.uid[0] << 24 | (uint32_t)card.uid[1] << 16 |
             (uint32_t)card.uid[2] << 8 | card.uid[3];

    hn_dev = dev;
    hn_first = 1;
    hardnested_recovered = 0;
    hardnested_recovered_key = 0;
    hardnested_pmpro_collect = pmpro_collect;

    uint8_t kt = knownType ? MC_AUTH_B : MC_AUTH_A;
    uint8_t tt = trgType ? MC_AUTH_B : MC_AUTH_A;
    uint8_t k[6]; memcpy(k, knownKey, 6);

    int rc = mfnestedhard(knownBlock, kt, k, trgBlock, tt, 0);
    (void)rc;

    if (hardnested_recovered) {
        uint64_t key = hardnested_recovered_key;
        for (int i = 0; i < 6; i++) found[i] = (uint8_t)(key >> ((5 - i) * 8));
        snprintf(log, lcap, "hardnested recovered the key");
        return 1;
    }
    snprintf(log, lcap, "hardnested did not recover a key (no nonces collected, "
             "card not vulnerable, or record layout needs tuning — see PMPRO_HN_DEBUG)");
    return 0;
}
