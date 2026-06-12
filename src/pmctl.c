/* pmctl.c — CLI to drive the PM-Pro over the reversed protocol.
 *   pmctl connect        identify + handshake
 *   pmctl identify       auto-detect the tag on the reader (HF/LF/HID) + type
 *   pmctl magic          test if the HF card is gen1a/gen2-CUID magic (writes block 0)
 *   pmctl beep [t] [c]   beep the device
 *   pmctl raw <hex>      send one command payload, print decrypted response
 */
#include "hidraw.h"
#include "furui.h"
#include "session.h"
#include "crack.h"
#include "hardnested_glue.h"
#include "nested.h"
#include "protocol.h"
#include "dump.h"
#include "ndef.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show(const char *tag, const uint8_t *d, size_t n)
{
    printf("%s [%zu]:", tag, n);
    for (size_t i = 0; i < n; i++) printf(" %02x", d[i]);
    printf("\n");
}

static void cli_prog(const char *msg, void *u) { (void)u; printf("  %s\n", msg); fflush(stdout); }

static const char *NDEF_USAGE =
    "ndef type: text <lang> <text> | uri <uri> | sp <uri> <title> | geo <lat,lon> |\n"
    "           social <platform> <handle> | service <name> <id|url> | aar <pkg> |\n"
    "           vcard <name> [phone] [email] [org] [url] |\n"
    "           mime <type> <data> | ext <domain:type> <data>";

/* Build an NDEF message from argv starting at argv[base] (the record type). */
static int build_ndef(int argc, char **argv, int base, ndef_message *m)
{
    ndef_msg_init(m);
    if (base >= argc) return -1;
    const char *t = argv[base];
    int a = base + 1;
    if (!strcmp(t, "text") && a + 1 < argc) return ndef_add_text(m, argv[a], argv[a + 1]);
    if (!strcmp(t, "uri")  && a < argc)     return ndef_add_uri(m, argv[a]);
    if (!strcmp(t, "geo")  && a < argc)     return ndef_add_geo(m, argv[a]);
    if (!strcmp(t, "aar")  && a < argc)     return ndef_add_aar(m, argv[a]);
    if (!strcmp(t, "sp")   && a + 1 < argc) return ndef_add_smartposter(m, argv[a], argv[a + 1], "en");
    if (!strcmp(t, "social") && a + 1 < argc) return ndef_add_social(m, argv[a], argv[a + 1]);
    if (!strcmp(t, "service") && a + 1 < argc) return ndef_add_service(m, argv[a], argv[a + 1]);
    if (!strcmp(t, "mime") && a + 1 < argc)
        return ndef_add_mime(m, argv[a], (const uint8_t *)argv[a + 1], strlen(argv[a + 1]));
    if (!strcmp(t, "ext")  && a + 1 < argc)
        return ndef_add_external(m, argv[a], (const uint8_t *)argv[a + 1], strlen(argv[a + 1]));
    if (!strcmp(t, "vcard") && a < argc) {
        ndef_vcard vc = {0};
        vc.name = argv[a];
        if (a + 1 < argc) vc.phone = argv[a + 1];
        if (a + 2 < argc) vc.email = argv[a + 2];
        if (a + 3 < argc) vc.org   = argv[a + 3];
        if (a + 4 < argc) vc.url   = argv[a + 4];
        return ndef_add_vcard(m, &vc);
    }
    return -1;
}

static void ndef_print(const ndef_message *m, int nl)
{
    printf("NDEF: %d record(s), %d bytes\n", m->n, nl);
    for (int i = 0; i < m->n; i++) {
        char d[NDEF_MAX_PAYLOAD + 128];
        ndef_record_describe(&m->rec[i], d, sizeof d);
        printf("  [%d] %s\n", i, d);
    }
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "connect";

    /* offline .pmdump tools — no device needed, handle before opening hidraw */
    if (!strcmp(cmd, "dumpdiff") && argc > 3) {
        static pmpro_dump da, db; char e[128];
        if (!pmpro_dump_load(&da, argv[2], e, sizeof e)) { printf("%s\n", e); return 2; }
        if (!pmpro_dump_load(&db, argv[3], e, sizeof e)) { printf("%s\n", e); return 2; }
        static char buf[16384];
        int n = pmpro_dump_diff(&da, &db, buf, sizeof buf);
        printf("%s%d difference(s)\n", buf, n);
        return 0;
    }
    if (!strcmp(cmd, "dumpset") && argc > 4) {
        static pmpro_dump d; char e[128];
        if (!pmpro_dump_load(&d, argv[2], e, sizeof e)) { printf("%s\n", e); return 2; }
        int idx = atoi(argv[3]);
        if (!pmpro_dump_set_block(&d, idx, argv[4])) { printf("set failed (bad index %d or hex)\n", idx); return 2; }
        if (!pmpro_dump_save_auto(&d, argv[2], e, sizeof e)) { printf("%s\n", e); return 2; }
        printf("block %d set; saved %s\n", idx, argv[2]);
        return 0;
    }
    if (!strcmp(cmd, "dumpconv") && argc > 3) {
        /* convert between formats by extension: <in> <out>  (.mfd <-> .pmdump) */
        static pmpro_dump d; char e[128];
        if (!pmpro_dump_load(&d, argv[2], e, sizeof e)) { printf("%s\n", e); return 2; }
        if (!pmpro_dump_save_auto(&d, argv[3], e, sizeof e)) { printf("%s\n", e); return 2; }
        printf("converted %s -> %s (%d sectors)\n", argv[2], argv[3], d.n_blocks);
        return 0;
    }

    if (!strcmp(cmd, "ndefencode") && argc > 2) {
        /* offline: build a message, print the NDEF bytes + the Mifare layout */
        ndef_message m;
        if (build_ndef(argc, argv, 2, &m) != 0) { printf("%s\n", NDEF_USAGE); return 2; }
        uint8_t ndef[NDEF_MAX_MESSAGE];
        int nl = ndef_encode(&m, ndef, sizeof ndef);
        if (nl < 0) { printf("encode overflow\n"); return 2; }
        ndef_print(&m, nl);
        printf("bytes:"); for (int i = 0; i < nl; i++) printf(" %02x", ndef[i]); printf("\n");
        uint8_t image[16][64]; memset(image, 0, sizeof image);
        int used = 0;
        if (ndef_to_mifare(ndef, (size_t)nl, NULL, 16, image, &used) == 0)
            printf("Mifare 1K layout: sector 0 (MAD) + data sectors 1..%d\n", used);
        else
            printf("too large for a 1K NDEF tag (max ~720 bytes)\n");
        return 0;
    }

    pmpro_dev dev;
    if (!pmpro_open(&dev, NULL)) { printf("open: %s\n", dev.err); return 1; }

    if (!strcmp(cmd, "connect")) {
        int ok = furui_connect(&dev);
        printf("connect: %s\n", ok ? "OK (identified + handshake complete)" : "FAILED");
        if (ok) furui_beep(&dev, 0x01, 0x02);
    } else if (!strcmp(cmd, "beep")) {
        uint8_t t = argc > 2 ? (uint8_t)strtol(argv[2], 0, 16) : 0x01;
        uint8_t c = argc > 3 ? (uint8_t)strtol(argv[3], 0, 16) : 0x02;
        furui_connect(&dev);
        printf("beep: %s\n", furui_beep(&dev, t, c) ? "OK" : "FAILED");
    } else if (!strcmp(cmd, "readic")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t p[1] = {0x21}; uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&dev, p, 1, resp, sizeof resp, 3000);
        printf("HF read ack=%d\n", r >= 3 && resp[2] == 1);
        if (r) show("resp(dec)", resp, r < 64 ? r : 64);
    } else if (!strcmp(cmd, "readid")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t p[3] = {0x28, 0x01, 0x00}; uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&dev, p, 3, resp, sizeof resp, 3000);
        printf("LF read ack=%d\n", r >= 3 && resp[2] == 1);
        if (r) show("resp(dec)", resp, r < 64 ? r : 64);
    } else if (!strcmp(cmd, "identify")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        furui_tag_id t;
        switch (furui_identify(&dev, &t)) {
        case FURUI_TAG_HF: {
            char uid[40], tail[32];
            pmpro_hex(t.hf.uid, t.hf.uid_len, uid, sizeof uid);
            pmpro_hex(t.hf.tail, t.hf.tail_len, tail, sizeof tail);
            printf("HF 13.56 MHz: %s\n", t.type);
            printf("  UID %s (%d-byte)  ATQA %04X  SAK %02X  [tail %s]%s\n",
                   uid, t.hf.uid_len, t.atqa, t.sak, tail,
                   t.magic_gen1a ? "  gen1a magic (UID-changeable)" : "");
            break;
        }
        case FURUI_TAG_LF: {
            char h[200]; pmpro_hex(t.data, t.data_len, h, sizeof h);
            printf("LF 125 kHz: %s  data %s\n", t.type, h);
            em4100_info em;
            if (pmpro_decode_em4100(t.data, t.data_len, &em))
                printf("  EM4100 id %s customer %u card %u fob %s\n",
                       em.hex, em.customer, em.card_number, em.fob_text);
            break;
        }
        case FURUI_TAG_HID: {
            char h[200]; pmpro_hex(t.data, t.data_len, h, sizeof h);
            printf("HID prox (%zu bytes): %s\n", t.data_len, h);
            break;
        }
        default:
            printf("no tag detected (tried HF 13.56 MHz, LF 125 kHz, HID prox)\n");
        }
    } else if (!strcmp(cmd, "magic")) {
        /* WRITES to block 0 (restored afterwards) to detect a gen2/CUID card. */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        char d[160];
        furui_magic_kind k = furui_magic_test(&dev, d, sizeof d);
        const char *label =
            k == FURUI_MAGIC_GEN1A   ? "GEN1A MAGIC" :
            k == FURUI_MAGIC_GEN2    ? "GEN2/CUID MAGIC" :
            k == FURUI_MAGIC_NONE    ? "not magic (genuine)" :
            k == FURUI_MAGIC_NOCARD  ? "no card" : "unknown";
        printf("magic test: %s — %s\n", label, d);
    } else if (!strcmp(cmd, "dumphf")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t resp[FURUI_MAXMSG];
        uint8_t a10[1] = {0x10};                       /* activate card */
        size_t r = furui_exec(&dev, a10, 1, resp, sizeof resp, 2000);
        printf("activate ack=%d\n", r >= 3 && resp[2] == 1);
        for (int sec = 0; sec < 16; sec++) {
            uint8_t p[15] = {0x17, (uint8_t)sec, 0x01,
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0,0,0,0,0,0};
            r = furui_exec(&dev, p, sizeof p, resp, sizeof resp, 3000);
            int ok = r >= 3 && resp[2] == 1;
            printf("sector %2d (keyA=FFFFFFFFFFFF) ack=%d", sec, ok);
            if (r) { printf("  resp[%zu]:", r); for (size_t i = 0; i < r && i < 64; i++) printf(" %02x", resp[i]); }
            printf("\n");
        }
    } else if (!strcmp(cmd, "readkey")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t key[6];
        if (argc > 2 && pmpro_parse_hex(argv[2], key, sizeof key) == 6) ;
        else memset(key, 0xFF, 6);
        char kh[20]; pmpro_hex(key, 6, kh, sizeof kh);
        printf("reading 16 sectors with key A = %s\n", kh);
        int open = 0;
        for (int s = 0; s < 16; s++) {
            furui_activate(&dev);
            uint8_t blk[64];
            size_t bl = furui_read_sector(&dev, (uint8_t)s, 1, key, NULL, blk, sizeof blk);
            int nz = 0; for (size_t i = 0; i < bl; i++) if (blk[i]) { nz = 1; break; }
            if (bl && nz) { open++; printf("  sector %2d:", s); for (size_t i=0;i<bl&&i<48;i++) printf(" %02x", blk[i]); printf("\n"); }
        }
        printf("%d/16 sectors readable with this key\n", open);
    } else if (!strcmp(cmd, "writesector") && argc > 4) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int sec = atoi(argv[2]);
        uint8_t key[6]; if (pmpro_parse_hex(argv[3], key, 6) != 6) { printf("key must be 6 bytes\n"); return 2; }
        uint8_t data[64]; int dl = pmpro_parse_hex(argv[4], data, sizeof data);
        if (dl <= 0) { printf("bad data hex\n"); return 2; }
        furui_activate(&dev);
        int ok = furui_write_sector(&dev, (uint8_t)sec, 1, key, NULL, data, dl);
        printf("write sector %d (%d bytes): %s\n", sec, dl, ok ? "OK" : "FAILED");
    } else if (!strcmp(cmd, "clone") && argc > 3) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t sk[6], dk[6];
        if (pmpro_parse_hex(argv[2], sk, 6) != 6 || pmpro_parse_hex(argv[3], dk, 6) != 6) {
            printf("usage: clone <srcKeyA(6)> <dstKeyA(6)>\n"); return 2; }
        printf("NOTE: place SOURCE card, press enter conceptually — here we read then expect TARGET swap.\n");
        int done = 0;
        furui_clone(&dev, 16, sk, dk, &done, NULL, NULL);
        printf("cloned %d/16 sectors\n", done);
    } else if (!strcmp(cmd, "rawcmd") && argc > 2) {
        /* activate then send one command payload; dump FULL decrypted response */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t pl[80]; int n = pmpro_parse_hex(argv[2], pl, sizeof pl);
        if (n <= 0) { printf("bad hex\n"); return 2; }
        uint8_t resp[FURUI_MAXMSG];
        uint8_t a10[1] = {0x10};
        furui_exec(&dev, a10, 1, resp, sizeof resp, 2000);
        size_t r = furui_exec(&dev, pl, n, resp, sizeof resp, 4000);
        printf("resp len=%zu:", r);
        for (size_t i = 0; i < r && i < 80; i++) printf(" %02x", resp[i]);
        printf("\n");
    } else if (!strcmp(cmd, "csec") && argc > 3) {
        /* clone one sector to another (verifies read->write data path) */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int src = atoi(argv[2]), dst = atoi(argv[3]);
        uint8_t key[6]; memset(key, 0xFF, 6);
        uint8_t blk[64];
        furui_activate(&dev);
        size_t bl = furui_read_sector(&dev, (uint8_t)src, 1, key, NULL, blk, sizeof blk);
        printf("read src sector %d (%zu bytes):", src, bl);
        for (size_t i=0;i<bl;i++) printf(" %02x", blk[i]);
        printf("\n");
        if (bl >= 64) {
            memcpy(blk + 48, key, 6);              /* restore trailer keyA = FF */
            furui_activate(&dev);
            int w = furui_write_sector(&dev, (uint8_t)dst, 1, key, NULL, blk, 64);
            printf("write -> dst sector %d: %s\n", dst, w ? "OK" : "FAILED");
            furui_activate(&dev);
            uint8_t v[64];
            size_t vl = furui_read_sector(&dev, (uint8_t)dst, 1, key, NULL, v, sizeof v);
            printf("read back dst sector %d (%zu bytes):", dst, vl);
            for (size_t i=0;i<vl;i++) printf(" %02x", v[i]);
            printf("\n%s\n", (vl>=48 && memcmp(blk, v, 48)==0) ? "*** CLONE DATA MATCHES ***" : "(data differs)");
        }
    } else if (!strcmp(cmd, "rt")) {
        /* round-trip on a magic card: read sector raw, write pattern, read again */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int sec = argc > 2 ? atoi(argv[2]) : 1;
        uint8_t key[6]; memset(key, 0xFF, 6);
        uint8_t buf[64];
        furui_activate(&dev);
        size_t r1 = furui_read_sector(&dev, (uint8_t)sec, 1, key, NULL, buf, sizeof buf);
        printf("BEFORE read sector %d (%zu bytes):", sec, r1);
        for (size_t i = 0; i < r1; i++) printf(" %02x", buf[i]);
        printf("\n");
        /* full 64-byte sector: 3 data blocks (pattern) + default transport trailer */
        uint8_t sd[64];
        for (int i = 0; i < 48; i++) sd[i] = (uint8_t)(0xa0 + (i & 0x0f));
        uint8_t trailer[16] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0x07,0x80,0x69,
                               0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        memcpy(sd + 48, trailer, 16);
        furui_activate(&dev);
        int w = furui_write_sector(&dev, (uint8_t)sec, 1, key, NULL, sd, 64);
        printf("WRITE full 64-byte sector: %s\n", w ? "OK" : "FAILED");
        furui_activate(&dev);
        size_t r2 = furui_read_sector(&dev, (uint8_t)sec, 1, key, NULL, buf, sizeof buf);
        printf("AFTER  read sector %d (%zu bytes):", sec, r2);
        for (size_t i = 0; i < r2; i++) printf(" %02x", buf[i]);
        printf("\n");
    } else if (!strcmp(cmd, "format") && argc > 2) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int sec = atoi(argv[2]);
        uint8_t key[6]; if (argc < 4 || pmpro_parse_hex(argv[3], key, 6) != 6) memset(key, 0xFF, 6);
        printf("format sector %d: %s\n", sec,
               furui_format_sector(&dev, (uint8_t)sec, 1, key, NULL) ? "OK" : "FAILED");
    } else if (!strcmp(cmd, "readhid")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t buf[64]; size_t n = furui_read_hid(&dev, buf, sizeof buf);
        printf("HID read (%zu bytes):", n);
        for (size_t i = 0; i < n; i++) printf(" %02x", buf[i]);
        printf("\n");
    } else if (!strcmp(cmd, "writehid") && argc > 2) {
        /* writehid <12-byte card id hex> — write an HID prox card (cmd 2E) */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t id[12];
        if (pmpro_parse_hex(argv[2], id, sizeof id) != 12) { printf("card id must be 12 bytes\n"); return 2; }
        printf("write HID: %s\n", furui_write_hid(&dev, id) ? "OK" : "FAILED");
    } else if (!strcmp(cmd, "openfind")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        printf("openfind: %s\n", furui_openfind(&dev) ? "OK" : "FAILED");
    } else if (!strcmp(cmd, "hardnested") && argc > 4) {
        /* hardnested <knownBlock> <knownKeyHex> <trgBlock> [knownType] [trgType] */
        int kb = atoi(argv[2]);
        uint8_t kk[6]; if (pmpro_parse_hex(argv[3], kk, 6) != 6) { printf("known key must be 6 bytes\n"); return 2; }
        int tb = atoi(argv[4]);
        int ktype = argc > 5 ? atoi(argv[5]) : 0;
        int ttype = argc > 6 ? atoi(argv[6]) : 0;
        uint8_t found[6]; char log[256];
        int ok = furui_hardnested(&dev, (uint8_t)kb, (uint8_t)ktype, kk, (uint8_t)tb, (uint8_t)ttype, found, log, sizeof log);
        printf("hardnested: %s\n", log);
        if (ok) printf("KEY block %d (key %c): %02x%02x%02x%02x%02x%02x\n", tb, ttype?'B':'A',
                       found[0],found[1],found[2],found[3],found[4],found[5]);
    } else if (!strcmp(cmd, "autopwn")) {
        /* autopwn [outfile.mfd] [keysfile.keys] */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        const char *path = argc > 2 ? argv[2] : "card.mfd";
        if (argc > 3) {
            char e[128]; int n = furui_keys_load(argv[3], e, sizeof e);
            if (n < 0) printf("%s\n", e);
            else printf("loaded %d keys from %s (%d in dictionary)\n", n, argv[3], furui_keys_count());
        }
        char log[256];
        int ok = furui_autopwn(&dev, path, cli_prog, NULL, log, sizeof log);
        printf("autopwn: %s\n", log);
        (void)ok;
    } else if (!strcmp(cmd, "nested") && argc > 4) {
        /* nested <footholdBlock> <footholdKeyHex> <trgBlock> [fType] [tType] */
        int fb = atoi(argv[2]);
        uint8_t fk[6]; if (pmpro_parse_hex(argv[3], fk, 6) != 6) { printf("foothold key must be 6 bytes\n"); return 2; }
        int tb = atoi(argv[4]);
        int ftype = argc > 5 ? atoi(argv[5]) : 0;
        int ttype = argc > 6 ? atoi(argv[6]) : 0;
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t found[6]; char log[256];
        int ok = furui_nested(&dev, (uint8_t)fb, (uint8_t)ftype, fk, (uint8_t)tb, (uint8_t)ttype, found, log, sizeof log);
        printf("nested: %s\n", log);
        if (ok) printf("KEY block %d (key %c): %02x%02x%02x%02x%02x%02x\n", tb, ttype?'B':'A',
                       found[0],found[1],found[2],found[3],found[4],found[5]);
    } else if (!strcmp(cmd, "dict")) {
        /* dict <block> <type> [keysfile.keys] */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int block = argc > 2 ? atoi(argv[2]) : 4;
        int type  = argc > 3 ? atoi(argv[3]) : 0;
        if (argc > 4) {
            char e[128]; int n = furui_keys_load(argv[4], e, sizeof e);
            if (n < 0) printf("%s\n", e);
            else printf("loaded %d keys from %s (%d in dictionary)\n", n, argv[4], furui_keys_count());
        }
        uint8_t found[6];
        if (furui_dict_attack(&dev, (uint8_t)block, (uint8_t)type, found)) {
            printf("KEY FOUND for block %d (key %c): %02x%02x%02x%02x%02x%02x\n",
                   block, type ? 'B' : 'A', found[0],found[1],found[2],found[3],found[4],found[5]);
        } else printf("no dictionary key works for block %d\n", block);
    } else if (!strcmp(cmd, "crack")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int block = argc > 2 ? atoi(argv[2]) : 4;
        int type  = argc > 3 ? atoi(argv[3]) : 0;
        uint8_t found[6]; char st[256];
        int ok = furui_darkside(&dev, (uint8_t)block, (uint8_t)type, found, st, sizeof st);
        printf("darkside: %s\n", st);
        if (ok) printf("KEY: %02x%02x%02x%02x%02x%02x\n",
                       found[0],found[1],found[2],found[3],found[4],found[5]);
    } else if (!strcmp(cmd, "checkkeys")) {
        /* cmd 13: test a dictionary of keys against a block; dump raw response */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int block = argc > 2 ? atoi(argv[2]) : 4;
        int type  = argc > 3 ? atoi(argv[3]) : 0;
        static const uint8_t dict[][6] = {
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5},
            {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7}, {0x00,0x00,0x00,0x00,0x00,0x00},
            {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5}, {0x4D,0x3A,0x99,0xC3,0x51,0xDD},
        };
        int nk = (int)(sizeof dict / 6);
        uint8_t p[3 + 6*16]; p[0] = 0x13; p[1] = (uint8_t)block; p[2] = (uint8_t)type;
        p[3] = (uint8_t)nk;
        for (int i = 0; i < nk; i++) memcpy(p + 4 + i*6, dict[i], 6);
        furui_activate(&dev);
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&dev, p, 4 + nk*6, resp, sizeof resp, 5000);
        printf("cmd13 block=%d type=%d keys=%d -> resp len=%zu:", block, type, nk, r);
        for (size_t i = 0; i < r && i < 60; i++) printf(" %02x", resp[i]);
        printf("\n");
    } else if (!strcmp(cmd, "ds")) {
        /* darkside collection: activate (10) then GetAllDecode (15 <block> <type>) */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        int block = argc > 2 ? atoi(argv[2]) : 0;
        int type  = argc > 3 ? atoi(argv[3]) : 0;   /* 0=keyA,1=keyB */
        uint8_t resp[FURUI_MAXMSG];
        uint8_t a10[1] = {0x10};
        furui_exec(&dev, a10, 1, resp, sizeof resp, 2000);
        uint8_t p[3] = {0x15, (uint8_t)block, (uint8_t)type};
        size_t r = furui_exec(&dev, p, 3, resp, sizeof resp, 8000);
        printf("cmd15 block=%d type=%d ack=%d len=%zu\n", block, type, r>=3&&resp[2]==1, r);
        if (r) { printf("resp(dec):"); for (size_t i=0;i<r && i<200;i++) printf(" %02x", resp[i]); printf("\n"); }
    } else if (!strcmp(cmd, "ndefwrite") && argc > 2) {
        /* Write an NDEF message to a Mifare Classic card. Tries the NDEF/MAD keys
         * then the default key per sector, verifies by read-back, and keeps an
         * already-present MAD (so an already-formatted genuine card works; a fresh
         * magic card gets a new MAD). The GUI additionally recovers unknown keys. */
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        ndef_message m;
        if (build_ndef(argc, argv, 2, &m) != 0) { printf("%s\n", NDEF_USAGE); return 2; }
        uint8_t ndef[NDEF_MAX_MESSAGE];
        int nl = ndef_encode(&m, ndef, sizeof ndef);
        if (nl < 0) { printf("encode overflow\n"); return 2; }
        uint8_t ff[6]; memset(ff, 0xFF, 6);

        /* read sector 0 (MAD key, else default) to preserve block 0 + see the MAD */
        uint8_t s0[64], block0[16]; memset(block0, 0, 16);
        int have_s0 = 0;
        furui_activate(&dev);
        if (furui_read_sector(&dev, 0, 1, NDEF_MAD_KEY, NULL, s0, sizeof s0) >= 16) have_s0 = 1;
        else { furui_activate(&dev);
               if (furui_read_sector(&dev, 0, 1, ff, NULL, s0, sizeof s0) >= 16) have_s0 = 1; }
        if (have_s0) memcpy(block0, s0, 16);

        uint8_t image[16][64]; memset(image, 0, sizeof image);
        int used = 0;
        if (ndef_to_mifare(ndef, (size_t)nl, block0, 16, image, &used) != 0) {
            printf("message too large for a 1K NDEF tag\n"); return 2; }

        int mad_ok = have_s0;
        for (int s = 1; s <= used && mad_ok; s++)
            if (s0[16 + 2 * s] != 0x03 || s0[16 + 2 * s + 1] != 0xE1) mad_ok = 0;

        ndef_print(&m, nl);
        printf(mad_ok ? "writing data sectors 1..%d (MAD already present)…\n"
                      : "writing sector 0 (MAD) + data sectors 1..%d…\n", used);
        int wrote = 0;
        for (int s = 0; s <= used; s++) {
            if (s == 0 && mad_ok) { printf("  sector 0: MAD already present — kept\n"); wrote++; continue; }
            const uint8_t *ka = (s == 0) ? NDEF_MAD_KEY : NDEF_DATA_KEY;
            furui_activate(&dev);
            if (!furui_write_sector(&dev, (uint8_t)s, 1, ka, NULL, image[s], 64)) {
                furui_activate(&dev);
                furui_write_sector(&dev, (uint8_t)s, 1, ff, NULL, image[s], 64);
            }
            /* verify by reading the data blocks back (block 0 of sector 0 is kept) */
            uint8_t rb[64]; int v = 0, st = (s == 0) ? 16 : 0;
            furui_activate(&dev);
            if (furui_read_sector(&dev, (uint8_t)s, 1, ka, NULL, rb, sizeof rb) >= 64
                || furui_read_sector(&dev, (uint8_t)s, 1, ff, NULL, rb, sizeof rb) >= 64)
                v = memcmp(rb + st, image[s] + st, 48 - st) == 0;
            printf("  sector %d: %s\n", s, v ? "written" : "FAILED");
            if (v) wrote++;
        }
        printf("wrote %d/%d sectors\n", wrote, used + 1);
    } else if (!strcmp(cmd, "ndefread")) {
        if (!furui_connect(&dev)) { printf("connect failed\n"); return 3; }
        uint8_t image[16][64]; memset(image, 0, sizeof image);
        uint8_t ff[6]; memset(ff, 0xFF, 6);
        for (int s = 0; s < 16; s++) {
            const uint8_t *k = (s == 0) ? NDEF_MAD_KEY : NDEF_DATA_KEY;
            furui_activate(&dev);
            if (furui_read_sector(&dev, (uint8_t)s, 1, k, NULL, image[s], 64) < 16) {
                furui_activate(&dev);                       /* fall back to default key */
                furui_read_sector(&dev, (uint8_t)s, 1, ff, NULL, image[s], 64);
            }
        }
        uint8_t ndef[NDEF_MAX_MESSAGE];
        int nl = mifare_to_ndef((const uint8_t *)image, 16, ndef, sizeof ndef);
        if (nl < 0) { printf("no NDEF message found (is the card NDEF-formatted?)\n"); return 1; }
        ndef_message m;
        if (ndef_decode(ndef, (size_t)nl, &m) < 0) { printf("NDEF parse error\n"); return 1; }
        ndef_print(&m, nl);
    } else if (!strcmp(cmd, "raw") && argc > 2) {
        unsigned char payload[64];
        int n = pmpro_parse_hex(argv[2], payload, sizeof payload);
        if (n < 0) { printf("bad hex\n"); return 2; }
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&dev, payload, n, resp, sizeof resp, 1500);
        if (r) show("resp(dec)", resp, r < 64 ? r : 64);
        else printf("no/blank response\n");
    } else {
        printf("usage: pmctl [connect|identify|magic|beep [t] [c]|raw <hex>]\n"
               "       pmctl [ndefencode|ndefwrite] <type> <args…>   pmctl ndefread\n"
               "       %s\n", NDEF_USAGE);
    }
    pmpro_close(&dev);
    return 0;
}
