#include "protocol.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

char *pmpro_hex(const unsigned char *data, size_t len, char *out, size_t n)
{
    size_t pos = 0;
    out[0] = '\0';
    for (size_t i = 0; i < len && pos + 3 < n; ++i)
        pos += (size_t)snprintf(out + pos, n - pos, i ? " %02x" : "%02x",
                                data[i]);
    return out;
}

char *pmpro_ascii(const unsigned char *data, size_t len, char *out, size_t n)
{
    size_t i = 0;
    for (; i < len && i + 1 < n; ++i) {
        unsigned char b = data[i];
        out[i] = (b >= 32 && b < 127) ? (char)b : '.';
    }
    out[i] = '\0';
    return out;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int pmpro_parse_hex(const char *text, unsigned char *buf, size_t n)
{
    size_t count = 0;
    const char *p = text;
    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ',' ||
                      (*p == '0' && (p[1] == 'x' || p[1] == 'X'))))
            p += (*p == '0' && (p[1] == 'x' || p[1] == 'X')) ? 2 : 1;
        if (!*p)
            break;
        int hi = hexval(*p++);
        if (hi < 0)
            return -1;
        int lo = hexval(*p);
        if (lo < 0) {
            /* single hex digit token -> treat as low nibble */
            if (count >= n) return -1;
            buf[count++] = (unsigned char)hi;
            continue;
        }
        p++;
        if (count >= n)
            return -1;
        buf[count++] = (unsigned char)((hi << 4) | lo);
    }
    return (int)count;
}

bool pmpro_decode_em4100(const unsigned char *id_bytes, size_t len,
                         em4100_info *out)
{
    if (len < 5)
        return false;
    const unsigned char *p = id_bytes + (len - 5);
    out->customer = p[0];
    out->card_number = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 8) | p[4];
    pmpro_hex(p, 5, out->hex, sizeof out->hex);
    snprintf(out->fob_text, sizeof out->fob_text, "%05u,%05u",
             (out->card_number >> 16) & 0xffff, out->card_number & 0xffff);
    return true;
}

void pmpro_decode_uid(const unsigned char *uid, size_t len, uid_info *out)
{
    pmpro_hex(uid, len, out->uid, sizeof out->uid);
    out->uid_len = (int)len;
}

const char *pmpro_card_type(uint8_t sak, uint16_t atqa, int uid_len, int *sectors)
{
    int s = 0;
    const char *t;
    switch (sak) {
    case 0x00:
        /* Ultralight/NTAG family — the device can't tell the variants apart
         * (would need GET_VERSION), so name the family. */
        t = (atqa == 0x0044) ? "Mifare Ultralight / NTAG (family)"
                             : "Mifare Ultralight";
        break;
    case 0x08: t = "Mifare Classic 1K (S50)"; s = 16; break;
    case 0x09: t = "Mifare Mini";             s = 5;  break;
    case 0x18: t = "Mifare Classic 4K (S70)"; s = 40; break;
    case 0x10: t = "Mifare Plus 2K (SL2)";    s = 32; break;
    case 0x11: t = "Mifare Plus 4K (SL2)";    s = 40; break;
    case 0x20:
        /* ISO14443-4: DESFire vs Plus-SL3 — ATQA 0x0344 is the DESFire family. */
        t = (atqa == 0x0344) ? "Mifare DESFire / DESFire EV1"
                             : "Mifare Plus (SL3) / DESFire";
        break;
    case 0x28: t = "JCOP / SmartMX (Classic emulation)"; s = 16; break;
    case 0x38: t = "SmartMX (Classic 4K emulation)";     s = 40; break;
    case 0x88: t = "Infineon Mifare Classic 1K";         s = 16; break;
    default:
        if      (atqa == 0x0004) { t = "Mifare Classic 1K (S50)"; s = 16; }
        else if (atqa == 0x0002) { t = "Mifare Classic 4K (S70)"; s = 40; }
        else if (atqa == 0x0044) { t = "Mifare Ultralight / NTAG (family)"; }
        else if (atqa == 0x0344) { t = "Mifare DESFire"; }
        else                       t = "Unknown ISO14443A";
        break;
    }
    /* A 7-byte UID on a "1K/4K" SAK usually means a Plus/EV1 in Classic mode,
     * but the name stays correct; uid_len is only a hint and kept for callers. */
    (void)uid_len;
    if (sectors) *sectors = s;
    return t;
}

int pmpro_value_block(const unsigned char b[16], int32_t *value, uint8_t *addr)
{
    if (memcmp(b, b + 8, 4) != 0)
        return 0;
    for (int i = 0; i < 4; i++)
        if ((unsigned char)~b[i] != b[4 + i])
            return 0;
    if (b[12] != b[14] || b[13] != b[15] || (unsigned char)~b[12] != b[13])
        return 0;
    if (value)
        *value = (int32_t)((uint32_t)b[0] | (uint32_t)b[1] << 8 |
                           (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24);
    if (addr)
        *addr = b[12];
    return 1;
}

void pmpro_decode_acs(const unsigned char tr[16], char *out, size_t n)
{
    uint8_t b7 = tr[7], b8 = tr[8];
    /* data-block access by (C1<<2|C2<<1|C3) */
    static const char *db[8] = {
        "rd A|B wr A|B",            /* 000 transport */
        "rd A|B dec A|B (value)",   /* 001 */
        "rd A|B wr never",          /* 010 read-only */
        "rd B wr B",                /* 011 */
        "rd A|B wr B",              /* 100 */
        "rd B wr never",            /* 101 */
        "rd A|B wr B inc/dec",      /* 110 */
        "no access",                /* 111 */
    };
    /* trailer access by (C1<<2|C2<<1|C3) — keyB visibility + who writes keys */
    static const char *tb[8] = {
        "keyB readable; A writes keys",       /* 000 */
        "transport; A writes keys+AC; keyB readable", /* 001 */
        "keyB readable; keys locked",         /* 010 */
        "B writes keys+AC",                   /* 011 */
        "A reads AC; B writes keys",          /* 100 */
        "AB read AC; B writes AC",            /* 101 */
        "AB read AC; B writes keys+AC",       /* 110 */
        "keys locked (no write)",             /* 111 */
    };
    int c[4];
    for (int i = 0; i < 4; i++)
        c[i] = (((b7 >> (4 + i)) & 1) << 2) | (((b8 >> i) & 1) << 1) | ((b8 >> (4 + i)) & 1);
    snprintf(out, n, "blk0 %s; blk1 %s; blk2 %s; trailer %s",
             db[c[0]], db[c[1]], db[c[2]], tb[c[3]]);
}
