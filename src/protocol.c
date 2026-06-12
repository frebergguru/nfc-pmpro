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

uint8_t pmpro_xor(const unsigned char *data, size_t len)
{
    uint8_t c = 0;
    for (size_t i = 0; i < len; ++i)
        c ^= data[i];
    return c;
}

uint8_t pmpro_sum(const unsigned char *data, size_t len)
{
    unsigned s = 0;
    for (size_t i = 0; i < len; ++i)
        s += data[i];
    return (uint8_t)(s & 0xff);
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
