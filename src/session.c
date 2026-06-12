#include "session.h"
#include "furui.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>

size_t furui_exec(pmpro_dev *dev, const uint8_t *payload, size_t len,
                  uint8_t *resp, size_t cap, int timeout_ms)
{
    uint8_t tx[FURUI_MAXMSG];
    size_t txlen = furui_pack(payload, len, tx);
    for (size_t off = 0; off < txlen; off += 64)
        if (!pmpro_write(dev, tx + off, 64))
            return 0;

    /* read first report, learn the length, then read the rest */
    uint8_t rx[FURUI_MAXMSG];
    int n = pmpro_read(dev, rx, timeout_ms);
    if (n <= 0)
        return 0;

    uint8_t probe[64];
    memcpy(probe, rx, 64);
    uint16_t flen = furui_decrypt_report(probe);   /* decrypt copy for length */
    if (flen < 4 || flen > FURUI_MAXMSG)
        flen = 64;
    size_t need = ((flen + 63) / 64) * 64;
    size_t have = 64;
    while (have < need && have + 64 <= sizeof rx) {
        n = pmpro_read(dev, rx + have, timeout_ms);
        if (n <= 0)
            break;
        have += 64;
    }
    furui_unpack(rx, have);                          /* decrypt whole stream */
    uint16_t total = (uint16_t)(rx[0] | (rx[1] << 8));
    if (total < 3)
        return 0;
    /* copy the FULL decrypted buffer (incl. RC4 padding past the framed length)
     * so callers like the nested collector can read records that overrun into
     * the still-valid padding; the framed length is the return value. Clamp the
     * returned length to what we actually copied: a truncated/oversized device
     * reply must never make a caller read past the valid bytes. */
    size_t out = have < cap ? have : cap;
    memcpy(resp, rx, out);
    return total < out ? total : out;
}

static int ack(const uint8_t *resp, size_t len)
{
    return len >= 3 && resp[2] == 1;
}

static const uint8_t KEY_FF[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const uint8_t KEY_00[6] = {0,0,0,0,0,0};

int furui_connect(pmpro_dev *dev)
{
    uint8_t resp[FURUI_MAXMSG];

    /* cmd 06 — identify */
    uint8_t c06[1] = {0x06};
    size_t r = furui_exec(dev, c06, sizeof c06, resp, sizeof resp, 1500);
    if (!ack(resp, r))
        return 0;

    /* cmd 01 — handshake step 1: ver=01, packsize=5120(LE), 0F 04, pcRandom=5264(LE) */
    uint8_t c01a[10] = {0x01, 0x01, 0x00, 0x14, 0x0F, 0x04, 0x90, 0x14, 0x00, 0x00};
    r = furui_exec(dev, c01a, sizeof c01a, resp, sizeof resp, 1500);
    if (!ack(resp, r))
        return 0;
    if (r < 16)   /* need the pcRandom echo (8..11) + device random (12..15) */
        return 0;
    uint32_t pcecho = resp[8] | (resp[9] << 8) | (resp[10] << 16) | (resp[11] << 24);
    if (pcecho != 5264)
        return 0;
    /* device random (little-endian) -> echo back in step 2 */
    uint8_t c01b[5] = {0x01, resp[12], resp[13], resp[14], resp[15]};
    r = furui_exec(dev, c01b, sizeof c01b, resp, sizeof resp, 1500);
    if (!ack(resp, r))
        return 0;

    /* cmd 06 again, as the official FindDevice does */
    r = furui_exec(dev, c06, sizeof c06, resp, sizeof resp, 1500);
    return ack(resp, r);
}

int furui_beep(pmpro_dev *dev, uint8_t type, uint8_t count)
{
    uint8_t resp[FURUI_MAXMSG];
    uint8_t c09[3] = {0x09, type, count};
    size_t r = furui_exec(dev, c09, sizeof c09, resp, sizeof resp, 1500);
    return ack(resp, r);
}

int furui_openfind(pmpro_dev *dev)
{
    uint8_t resp[FURUI_MAXMSG], c[1] = {0x0F};
    size_t r = furui_exec(dev, c, 1, resp, sizeof resp, 1500);
    return ack(resp, r);
}

size_t furui_read_hid(pmpro_dev *dev, uint8_t *out, size_t cap)
{
    uint8_t resp[FURUI_MAXMSG], c[1] = {0x29};
    size_t r = furui_exec(dev, c, 1, resp, sizeof resp, 3000);
    if (!ack(resp, r))
        return 0;
    size_t dlen = r > 5 ? r - 5 : 0;
    if (dlen > cap) dlen = cap;
    memcpy(out, resp + 3, dlen);
    return dlen;
}

int furui_write_hid(pmpro_dev *dev, const uint8_t cardid[12])
{
    uint8_t resp[FURUI_MAXMSG], p[13];
    p[0] = 0x2E;
    memcpy(p + 1, cardid, 12);
    size_t r = furui_exec(dev, p, sizeof p, resp, sizeof resp, 3000);
    return ack(resp, r);
}

int furui_format_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                        const uint8_t keyA[6], const uint8_t keyB[6])
{
    uint8_t resp[FURUI_MAXMSG], p[15];
    p[0] = 0x16; p[1] = sector; p[2] = flag;
    memcpy(p + 3, keyA ? keyA : (const uint8_t[6]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, 6);
    memcpy(p + 9, keyB ? keyB : (const uint8_t[6]){0,0,0,0,0,0}, 6);
    furui_activate(dev);
    size_t r = furui_exec(dev, p, sizeof p, resp, sizeof resp, 3000);
    return ack(resp, r);
}

int furui_read_hf(pmpro_dev *dev, furui_hf_card *card)
{
    memset(card, 0, sizeof *card);
    uint8_t cmd[1] = {0x21}, resp[FURUI_MAXMSG];
    size_t r = furui_exec(dev, cmd, 1, resp, sizeof resp, 3000);
    if (!ack(resp, r))
        return 0;
    /* response: [len(2)][01][card data...][crc(2)]; data = UID(4|7|10) + tail */
    size_t dlen = r > 5 ? r - 5 : 0;          /* strip len+code+crc */
    const uint8_t *d = resp + 3;
    /* The tail is normally ATQA(2)+SAK(1) = 3 bytes, so the UID is dlen-3 when
     * that lands on a valid ISO14443A UID length (4/7/10). Fall back to a size
     * bucket otherwise. */
    int uidlen;
    int t = (int)dlen - 3;
    if (t == 4 || t == 7 || t == 10)
        uidlen = t;
    else if (dlen >= 10)
        uidlen = 7;
    else if (dlen >= 7)
        uidlen = 4;
    else
        uidlen = (int)dlen;
    if (uidlen > 10) uidlen = 10;
    memcpy(card->uid, d, uidlen);
    card->uid_len = uidlen;
    int tl = (int)dlen - uidlen;
    if (tl < 0) tl = 0;
    if (tl > 8) tl = 8;
    memcpy(card->tail, d + uidlen, tl);
    card->tail_len = tl;
    card->present = 1;
    return 1;
}

int furui_activate(pmpro_dev *dev)
{
    uint8_t resp[FURUI_MAXMSG], c10[1] = {0x10};
    size_t r = furui_exec(dev, c10, 1, resp, sizeof resp, 2000);
    return ack(resp, r);
}

/* Is there a gen1a/UID0 magic card present? cmd 1D is the gen1a backdoor block
 * read (no auth): a normal card rejects it, a UID-changeable magic answers. The
 * backdoor is flaky — the device's read only succeeds intermittently — so retry
 * a handful of times (the OEM app retries too) before giving up. */
static int furui_is_gen1a_magic(pmpro_dev *dev)
{
    uint8_t resp[FURUI_MAXMSG], p[2] = {0x1D, 0x00};   /* read block 0 */
    furui_activate(dev);
    for (int i = 0; i < 10; i++) {
        size_t r = furui_exec(dev, p, sizeof p, resp, sizeof resp, 2000);
        if (ack(resp, r))
            return 1;
    }
    return 0;
}

furui_tag_kind furui_identify(pmpro_dev *dev, furui_tag_id *out)
{
    memset(out, 0, sizeof *out);

    /* 1) HF (13.56 MHz, ISO14443A) — cmd 21 returns UID + ATQA (+ a trailing
     * byte that is NOT the SAK). */
    if (furui_read_hf(dev, &out->hf)) {
        out->kind = FURUI_TAG_HF;
        out->atqa = out->hf.tail_len >= 2
                  ? (out->hf.tail[0] | (uint16_t)out->hf.tail[1] << 8) : 0;
        /* The real SAK lives in block 0 byte 5, not in the cmd 21 reply, so
         * recover it with an authenticated read using the default key (this is
         * also how the OEM app types a card). Falls back to ATQA-only typing
         * (sak 0xFF) when sector 0 is key-protected. */
        out->sak = 0xFF;
        uint8_t blk[64];
        furui_activate(dev);
        if (furui_read_sector(dev, 0, 1, KEY_FF, NULL, blk, sizeof blk) >= 16)
            out->sak = blk[5];
        out->type = pmpro_card_type(out->sak, out->atqa, out->hf.uid_len,
                                    &out->sectors);
        out->magic_gen1a = furui_is_gen1a_magic(dev);
        return out->kind;
    }

    /* 2) LF (125 kHz, EM4100/EM4200) — cmd 28, Auto=1 Freq=0 (5 s like the OEM). */
    uint8_t resp[FURUI_MAXMSG], lf[3] = {0x28, 0x01, 0x00};
    size_t r = furui_exec(dev, lf, sizeof lf, resp, sizeof resp, 5000);
    if (ack(resp, r)) {
        size_t dlen = r > 5 ? r - 5 : 0;
        if (dlen > sizeof out->data) dlen = sizeof out->data;
        memcpy(out->data, resp + 3, dlen);
        out->data_len = dlen;
        out->kind = FURUI_TAG_LF;
        out->type = "EM4100 / 125 kHz ID";
        return out->kind;
    }

    /* 3) HID prox — cmd 29. Also catches a T5577 emulating HID (the LF read
     * above only sees EM-family IDs). */
    size_t n = furui_read_hid(dev, out->data, sizeof out->data);
    if (n) {
        out->data_len = n;
        out->kind = FURUI_TAG_HID;
        out->type = "HID Prox";
        return out->kind;
    }

    return FURUI_TAG_NONE;
}

furui_magic_kind furui_magic_test(pmpro_dev *dev, char *detail, size_t cap)
{
    furui_hf_card card;
    if (!furui_read_hf(dev, &card)) {
        if (detail) snprintf(detail, cap, "no HF card on the reader");
        return FURUI_MAGIC_NOCARD;
    }

    /* gen1a: the cmd 1D backdoor block read works without authentication. */
    if (furui_is_gen1a_magic(dev)) {
        if (detail) snprintf(detail, cap, "answers the gen1a backdoor (cmd 1D) — UID-changeable");
        return FURUI_MAGIC_GEN1A;
    }

    /* gen2/CUID: a normal card's block 0 is read-only; a CUID accepts a block-0
     * write. Read sector 0, flip one manufacturer byte, write, read back. */
    uint8_t sec0[64];
    furui_activate(dev);
    if (furui_read_sector(dev, 0, 1, KEY_FF, NULL, sec0, sizeof sec0) < 16) {
        if (detail) snprintf(detail, cap,
            "sector 0 not readable with the default key — load its key to run the gen2 probe");
        return FURUI_MAGIC_UNKNOWN;
    }
    /* Preserve the trailer: the read masks keyA to 00, so restore it to the key
     * we authenticated with; access bits + keyB read back intact. */
    memcpy(sec0 + 48, KEY_FF, 6);
    uint8_t orig = sec0[8];                 /* byte 8 = first manufacturer byte (after UID/BCC/SAK/ATQA) */

    uint8_t buf[64];
    memcpy(buf, sec0, sizeof buf);
    buf[8] = (uint8_t)(orig ^ 0xFF);
    furui_activate(dev);
    furui_write_sector(dev, 0, 1, KEY_FF, NULL, buf, sizeof buf);  /* device ACKs regardless; verify by read-back */

    uint8_t back[64];
    int changed = 0;
    furui_activate(dev);
    if (furui_read_sector(dev, 0, 1, KEY_FF, NULL, back, sizeof back) >= 16)
        changed = (back[8] == (uint8_t)(orig ^ 0xFF));

    /* Always restore the original block 0 (a genuine card rejects this anyway). */
    furui_activate(dev);
    furui_write_sector(dev, 0, 1, KEY_FF, NULL, sec0, sizeof sec0);

    if (changed) {
        if (detail) snprintf(detail, cap, "block 0 is writable (gen2/CUID) — UID-changeable magic");
        return FURUI_MAGIC_GEN2;
    }
    if (detail) snprintf(detail, cap, "block 0 is read-only — genuine (non-magic) card");
    return FURUI_MAGIC_NONE;
}

size_t furui_read_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                         const uint8_t keyA[6], const uint8_t keyB[6],
                         uint8_t *out, size_t cap)
{
    uint8_t p[15], resp[FURUI_MAXMSG];
    p[0] = 0x17; p[1] = sector; p[2] = flag;
    memcpy(p + 3, keyA ? keyA : KEY_FF, 6);
    memcpy(p + 9, keyB ? keyB : KEY_00, 6);
    size_t r = furui_exec(dev, p, sizeof p, resp, sizeof resp, 3000);
    if (!ack(resp, r) || r < 6)
        return 0;
    /* resp = [len(2)][code(1)][status(1)][pad(1)][64 sector bytes]...
     * status byte (resp[3]) is 0x0f on auth success, 0x00 on auth fail. */
    if (resp[3] == 0x00)
        return 0;
    size_t dlen = r > 7 ? r - 7 : 0;
    if (dlen > 256) dlen = 256;        /* a sector is 4 blocks (1K) or 16 (4K) */
    if (dlen > cap) dlen = cap;
    memcpy(out, resp + 5, dlen);
    return dlen;
}

int furui_write_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                       const uint8_t keyA[6], const uint8_t keyB[6],
                       const uint8_t *data, size_t datalen)
{
    uint8_t p[3 + 12 + 64], resp[FURUI_MAXMSG];
    if (datalen > 64) datalen = 64;
    p[0] = 0x18; p[1] = sector; p[2] = flag;
    memcpy(p + 3, keyA ? keyA : KEY_FF, 6);
    memcpy(p + 9, keyB ? keyB : KEY_00, 6);
    memcpy(p + 15, data, datalen);
    size_t r = furui_exec(dev, p, 15 + datalen, resp, sizeof resp, 3000);
    return ack(resp, r);
}

int furui_clone(pmpro_dev *dev, int sectors, const uint8_t srcKeyA[6],
                const uint8_t dstKeyA[6], int *done,
                void (*progress)(int sector, int ok, void *u), void *u)
{
    int ok_all = 1, n = 0;
    const uint8_t *dk = dstKeyA ? dstKeyA : KEY_FF;
    for (int s = 0; s < sectors; s++) {
        uint8_t blk[64];
        furui_activate(dev);
        size_t bl = furui_read_sector(dev, (uint8_t)s, 1, srcKeyA, NULL, blk, sizeof blk);
        int ok = 0;
        if (bl >= 64) {
            /* the trailer's keyA reads back as 00 — restore the dst key so the
             * cloned sector stays accessible, keep access bits + keyB. */
            memcpy(blk + 48, dk, 6);
            furui_activate(dev);
            ok = furui_write_sector(dev, (uint8_t)s, 1, dstKeyA, NULL, blk, 64);
        }
        if (ok) n++; else ok_all = 0;
        if (progress) progress(s, ok, u);
    }
    if (done) *done = n;
    return ok_all;
}
