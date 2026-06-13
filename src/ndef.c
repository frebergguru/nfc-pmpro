/* ndef.c — NDEF records + Mifare Classic NDEF mapping. See ndef.h.
 *
 * References: NFC Forum NDEF 1.0, RTD-Text/RTD-URI/RTD-Smart-Poster, and the
 * MIFARE Application Directory (NXP AN10787) + "MIFARE Classic as NFC Type
 * MIFARE Classic Tag" (NXP AN1305) for the on-card layout.
 */
#include "ndef.h"
#include <string.h>
#include <stdio.h>

/* NFC Forum RTD-URI abbreviation table (code -> scheme prefix), index == code. */
static const char *const URI_PREFIX[] = {
    "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
    "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://",
    "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://",
    "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
    "btgoep://", "tcpobex://", "irdaobex://", "file://", "urn:epc:id:",
    "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
};
#define URI_PREFIX_N ((int)(sizeof URI_PREFIX / sizeof URI_PREFIX[0]))

/* ---- message construction ------------------------------------------------ */

void ndef_msg_init(ndef_message *m) { m->n = 0; }

ndef_record *ndef_msg_add(ndef_message *m)
{
    if (m->n >= NDEF_MAX_RECORDS) return NULL;
    ndef_record *r = &m->rec[m->n++];
    memset(r, 0, sizeof *r);
    return r;
}

static int set_type(ndef_record *r, uint8_t tnf, const void *type, size_t tl)
{
    if (tl > NDEF_MAX_TYPE) return -1;
    r->tnf = tnf;
    memcpy(r->type, type, tl);
    r->type_len = tl;
    return 0;
}

static int set_payload(ndef_record *r, const void *p, size_t n)
{
    if (n > NDEF_MAX_PAYLOAD) return -1;
    memcpy(r->payload, p, n);
    r->payload_len = n;
    return 0;
}

int ndef_add_raw(ndef_message *m, uint8_t tnf,
                 const uint8_t *type, size_t type_len,
                 const uint8_t *payload, size_t payload_len)
{
    ndef_record *r = ndef_msg_add(m);
    if (!r) return -1;
    if (set_type(r, tnf, type, type_len) < 0) { m->n--; return -1; }
    if (set_payload(r, payload, payload_len) < 0) { m->n--; return -1; }
    return 0;
}

int ndef_add_text(ndef_message *m, const char *lang, const char *text)
{
    if (!lang) lang = "en";
    size_t ll = strlen(lang), tl = strlen(text);
    if (ll > 63) return -1;
    uint8_t buf[NDEF_MAX_PAYLOAD];
    if (1 + ll + tl > sizeof buf) return -1;
    buf[0] = (uint8_t)ll;                 /* status: bit7=0 -> UTF-8, bits0-5 = lang len */
    memcpy(buf + 1, lang, ll);
    memcpy(buf + 1 + ll, text, tl);
    ndef_record *r = ndef_msg_add(m);
    if (!r) return -1;
    set_type(r, NDEF_TNF_WELL_KNOWN, "T", 1);
    set_payload(r, buf, 1 + ll + tl);
    return 0;
}

/* Encode a URI into payload[] (1 prefix-code byte + the remainder). */
static int encode_uri(const char *uri, uint8_t *out, size_t cap)
{
    int best = 0; size_t best_len = 0;
    for (int i = 1; i < URI_PREFIX_N; i++) {     /* skip 0 = "" (no abbreviation) */
        size_t pl = strlen(URI_PREFIX[i]);
        if (pl > best_len && strncmp(uri, URI_PREFIX[i], pl) == 0) {
            best = i; best_len = pl;
        }
    }
    size_t rest = strlen(uri) - best_len;
    if (1 + rest > cap) return -1;
    out[0] = (uint8_t)best;
    memcpy(out + 1, uri + best_len, rest);
    return (int)(1 + rest);
}

int ndef_add_uri(ndef_message *m, const char *uri)
{
    uint8_t buf[NDEF_MAX_PAYLOAD];
    int n = encode_uri(uri, buf, sizeof buf);
    if (n < 0) return -1;
    ndef_record *r = ndef_msg_add(m);
    if (!r) return -1;
    set_type(r, NDEF_TNF_WELL_KNOWN, "U", 1);
    set_payload(r, buf, (size_t)n);
    return 0;
}

int ndef_add_geo(ndef_message *m, const char *latlon)
{
    char uri[256];
    snprintf(uri, sizeof uri, "geo:%s", latlon ? latlon : "");
    return ndef_add_uri(m, uri);
}

const ndef_social_site NDEF_SOCIAL[] = {
    {"X / Twitter", "https://x.com/"},
    {"Facebook",    "https://facebook.com/"},
    {"Instagram",   "https://instagram.com/"},
    {"LinkedIn",    "https://www.linkedin.com/in/"},
    {"YouTube",     "https://youtube.com/@"},
    {"TikTok",      "https://www.tiktok.com/@"},
    {"Threads",     "https://www.threads.net/@"},
    {"GitHub",      "https://github.com/"},
    {"Telegram",    "https://t.me/"},
    {"WhatsApp",    "https://wa.me/"},          /* handle = phone number */
    {"Snapchat",    "https://www.snapchat.com/add/"},
    {"Reddit",      "https://www.reddit.com/user/"},
    {NULL, NULL},
};

const ndef_social_site NDEF_SERVICE[] = {
    {"Google Review (Place ID)", "https://search.google.com/local/writereview?placeid="},
    {"Google Maps (Place ID)",   "https://www.google.com/maps/place/?q=place_id:"},
    {"Google Maps (search)",     "https://www.google.com/maps/search/?api=1&query="},
    {"Yelp business",            "https://www.yelp.com/biz/"},
    {"Play Store app",           "https://play.google.com/store/apps/details?id="},
    {"App Store app",            "https://apps.apple.com/app/id"},
    {"Spotify",                  "https://open.spotify.com/"},
    {"PayPal.me",                "https://paypal.me/"},
    {"Venmo",                    "https://venmo.com/"},
    {"Cash App",                 "https://cash.app/$"},
    {NULL, NULL},
};

/* Append `value` to the table prefix for `name` (or use a full http(s) URL as-is,
 * or trim a leading '@' for social handles), and add it as a URI record. */
static int add_from_table(ndef_message *m, const ndef_social_site *table,
                          const char *name, const char *value, int trim_at)
{
    if (!value) return -1;
    while (*value == ' ' || (trim_at && *value == '@')) value++;
    char uri[512];
    if (strncmp(value, "http://", 7) == 0 || strncmp(value, "https://", 8) == 0) {
        snprintf(uri, sizeof uri, "%s", value);          /* already a full URL */
    } else {
        const char *prefix = "https://";
        for (const ndef_social_site *s = table; s->name; s++)
            if (name && strcmp(s->name, name) == 0) { prefix = s->prefix; break; }
        snprintf(uri, sizeof uri, "%s%s", prefix, value);
    }
    return ndef_add_uri(m, uri);
}

int ndef_add_social(ndef_message *m, const char *platform, const char *handle)
{
    return add_from_table(m, NDEF_SOCIAL, platform, handle, 1);
}

int ndef_add_service(ndef_message *m, const char *service, const char *value)
{
    return add_from_table(m, NDEF_SERVICE, service, value, 0);
}

int ndef_add_smartposter(ndef_message *m, const char *uri,
                         const char *title, const char *lang)
{
    /* Build the nested message (URI + optional Text title), then wrap it. */
    ndef_message inner;
    ndef_msg_init(&inner);
    if (ndef_add_uri(&inner, uri) < 0) return -1;
    if (title && *title && ndef_add_text(&inner, lang, title) < 0) return -1;
    uint8_t buf[NDEF_MAX_PAYLOAD];
    int n = ndef_encode(&inner, buf, sizeof buf);
    if (n < 0) return -1;
    ndef_record *r = ndef_msg_add(m);
    if (!r) return -1;
    set_type(r, NDEF_TNF_WELL_KNOWN, "Sp", 2);
    set_payload(r, buf, (size_t)n);
    return 0;
}

int ndef_add_mime(ndef_message *m, const char *mime,
                  const uint8_t *data, size_t n)
{
    return ndef_add_raw(m, NDEF_TNF_MIME,
                        (const uint8_t *)mime, strlen(mime), data, n);
}

int ndef_add_external(ndef_message *m, const char *type,
                      const uint8_t *data, size_t n)
{
    return ndef_add_raw(m, NDEF_TNF_EXTERNAL,
                        (const uint8_t *)type, strlen(type), data, n);
}

int ndef_add_aar(ndef_message *m, const char *package)
{
    return ndef_add_external(m, "android.com:pkg",
                             (const uint8_t *)package, strlen(package));
}

/* append printf-style into buf[*off..cap), guarding overflow */
static void vc_add(char *buf, size_t cap, size_t *off, const char *fmt, const char *v)
{
    if (!v || !*v) return;
    int w = snprintf(buf + *off, cap - *off, fmt, v);
    if (w > 0 && (size_t)w < cap - *off) *off += (size_t)w;
}

/* vCard 3.0 text escaping: backslash-escape ';' ',' '\' and newline. */
static void vc_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (; in && *in && o + 2 < cap; in++) {
        if (*in == ';' || *in == ',' || *in == '\\') { out[o++] = '\\'; out[o++] = *in; }
        else if (*in == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else out[o++] = *in;
    }
    out[o] = 0;
}

int ndef_add_vcard(ndef_message *m, const ndef_vcard *vc)
{
    char buf[NDEF_MAX_PAYLOAD];
    size_t off = 0;
    off += (size_t)snprintf(buf, sizeof buf, "BEGIN:VCARD\r\nVERSION:3.0\r\n");
    vc_add(buf, sizeof buf, &off, "FN:%s\r\n", vc->name);
    vc_add(buf, sizeof buf, &off, "N:%s\r\n", vc->name);
    vc_add(buf, sizeof buf, &off, "TEL:%s\r\n", vc->phone);
    vc_add(buf, sizeof buf, &off, "EMAIL:%s\r\n", vc->email);
    vc_add(buf, sizeof buf, &off, "ORG:%s\r\n", vc->org);
    vc_add(buf, sizeof buf, &off, "URL:%s\r\n", vc->url);
    if (vc->address && *vc->address) {           /* ADR street component */
        char esc[512];
        vc_escape(vc->address, esc, sizeof esc);
        int w = snprintf(buf + off, sizeof buf - off, "ADR:;;%s;;;;;\r\n", esc);
        if (w > 0 && (size_t)w < sizeof buf - off) off += (size_t)w;
    }
    vc_add(buf, sizeof buf, &off, "NOTE:%s\r\n", vc->note);
    int w = snprintf(buf + off, sizeof buf - off, "END:VCARD\r\n");
    if (w > 0 && (size_t)w < sizeof buf - off) off += (size_t)w;
    return ndef_add_mime(m, "text/vcard", (const uint8_t *)buf, off);
}

/* ---- encode -------------------------------------------------------------- */

int ndef_encode(const ndef_message *m, uint8_t *out, size_t cap)
{
    size_t o = 0;
    for (int i = 0; i < m->n; i++) {
        const ndef_record *r = &m->rec[i];
        int sr = r->payload_len < 0x100;        /* short record? */
        int il = r->id_len > 0;
        uint8_t flags = r->tnf & 0x07;
        if (i == 0)        flags |= 0x80;        /* MB — message begin */
        if (i == m->n - 1) flags |= 0x40;        /* ME — message end */
        if (sr)            flags |= 0x10;        /* SR — short record */
        if (il)            flags |= 0x08;        /* IL — ID length present */

        size_t need = 1 + 1 + (sr ? 1 : 4) + (il ? 1 : 0)
                    + r->type_len + r->id_len + r->payload_len;
        if (o + need > cap) return -1;

        out[o++] = flags;
        out[o++] = (uint8_t)r->type_len;
        if (sr) {
            out[o++] = (uint8_t)r->payload_len;
        } else {
            out[o++] = (uint8_t)(r->payload_len >> 24);
            out[o++] = (uint8_t)(r->payload_len >> 16);
            out[o++] = (uint8_t)(r->payload_len >> 8);
            out[o++] = (uint8_t)(r->payload_len);
        }
        if (il) out[o++] = (uint8_t)r->id_len;
        memcpy(out + o, r->type, r->type_len);    o += r->type_len;
        memcpy(out + o, r->id, r->id_len);        o += r->id_len;
        memcpy(out + o, r->payload, r->payload_len); o += r->payload_len;
    }
    return (int)o;
}

/* ---- decode -------------------------------------------------------------- */

int ndef_decode(const uint8_t *in, size_t len, ndef_message *m)
{
    ndef_msg_init(m);
    size_t o = 0;
    while (o < len) {
        if (o + 2 > len) return -1;
        uint8_t flags = in[o++];
        uint8_t tnf = flags & 0x07;
        if (tnf == NDEF_TNF_EMPTY && o == 1 && len == 1) return 0; /* empty record */
        size_t tlen = in[o++];
        size_t plen;
        if (flags & 0x10) {                       /* SR */
            if (o + 1 > len) return -1;
            plen = in[o++];
        } else {
            if (o + 4 > len) return -1;
            plen = ((size_t)in[o] << 24) | ((size_t)in[o+1] << 16)
                 | ((size_t)in[o+2] << 8) | in[o+3];
            o += 4;
        }
        size_t ilen = 0;
        if (flags & 0x08) {                       /* IL */
            if (o + 1 > len) return -1;
            ilen = in[o++];
        }
        if (tlen > NDEF_MAX_TYPE || ilen > NDEF_MAX_TYPE || plen > NDEF_MAX_PAYLOAD)
            return -1;
        if (o + tlen + ilen + plen > len) return -1;

        ndef_record *r = ndef_msg_add(m);
        if (!r) return -1;
        r->tnf = tnf;
        memcpy(r->type, in + o, tlen); r->type_len = tlen; o += tlen;
        memcpy(r->id, in + o, ilen);   r->id_len = ilen;   o += ilen;
        memcpy(r->payload, in + o, plen); r->payload_len = plen; o += plen;

        if (flags & 0x40) break;                  /* ME — message end */
    }
    return m->n;
}

/* ---- inspection ---------------------------------------------------------- */

int ndef_uri_full(const ndef_record *r, char *out, size_t cap)
{
    if (r->tnf != NDEF_TNF_WELL_KNOWN || r->type_len != 1 || r->type[0] != 'U'
        || r->payload_len < 1)
        return -1;
    int code = r->payload[0];
    const char *pre = (code > 0 && code < URI_PREFIX_N) ? URI_PREFIX[code] : "";
    size_t pl = strlen(pre), rest = r->payload_len - 1;
    if (pl + rest + 1 > cap) return -1;
    memcpy(out, pre, pl);
    memcpy(out + pl, r->payload + 1, rest);
    out[pl + rest] = 0;
    return (int)(pl + rest);
}

void ndef_record_describe(const ndef_record *r, char *out, size_t cap)
{
    char tmp[NDEF_MAX_PAYLOAD + NDEF_MAX_TYPE + 64];
    if (r->tnf == NDEF_TNF_WELL_KNOWN && r->type_len == 1 && r->type[0] == 'U') {
        char uri[NDEF_MAX_PAYLOAD];
        if (ndef_uri_full(r, uri, sizeof uri) >= 0)
            snprintf(tmp, sizeof tmp, "URI: %s", uri);
        else
            snprintf(tmp, sizeof tmp, "URI: <malformed>");
    } else if (r->tnf == NDEF_TNF_WELL_KNOWN && r->type_len == 1 && r->type[0] == 'T'
               && r->payload_len >= 1) {
        size_t ll = r->payload[0] & 0x3f;
        char lang[64] = "", body[NDEF_MAX_PAYLOAD] = "";
        if (1 + ll <= r->payload_len) {
            memcpy(lang, r->payload + 1, ll); lang[ll] = 0;
            size_t bl = r->payload_len - 1 - ll;
            memcpy(body, r->payload + 1 + ll, bl); body[bl] = 0;
        }
        snprintf(tmp, sizeof tmp, "Text [%s]: %s", lang, body);
    } else if (r->tnf == NDEF_TNF_WELL_KNOWN && r->type_len == 2
               && r->type[0] == 'S' && r->type[1] == 'p') {
        ndef_message inner;
        char uri[NDEF_MAX_PAYLOAD] = "", title[256] = "";
        if (ndef_decode(r->payload, r->payload_len, &inner) > 0)
            for (int i = 0; i < inner.n; i++) {
                if (ndef_uri_full(&inner.rec[i], uri, sizeof uri) >= 0) continue;
                if (inner.rec[i].tnf == NDEF_TNF_WELL_KNOWN && inner.rec[i].type_len == 1
                    && inner.rec[i].type[0] == 'T' && inner.rec[i].payload_len >= 1) {
                    size_t ll = inner.rec[i].payload[0] & 0x3f, bl = inner.rec[i].payload_len - 1 - ll;
                    if (1 + ll <= inner.rec[i].payload_len && bl < sizeof title) {
                        memcpy(title, inner.rec[i].payload + 1 + ll, bl); title[bl] = 0;
                    }
                }
            }
        if (title[0]) snprintf(tmp, sizeof tmp, "Smart Poster: %s  (\"%s\")", uri, title);
        else          snprintf(tmp, sizeof tmp, "Smart Poster: %s", uri);
    } else if (r->tnf == NDEF_TNF_MIME) {
        char ty[NDEF_MAX_TYPE + 1];
        memcpy(ty, r->type, r->type_len); ty[r->type_len] = 0;
        if (strncmp(ty, "text/", 5) == 0) {        /* text MIME (e.g. vCard) — show it */
            char body[NDEF_MAX_PAYLOAD + 1];
            size_t pn = r->payload_len < NDEF_MAX_PAYLOAD ? r->payload_len : NDEF_MAX_PAYLOAD;
            memcpy(body, r->payload, pn); body[pn] = 0;
            for (size_t i = 0; i < pn; i++)        /* flatten newlines for a one-liner */
                if (body[i] == '\r' || body[i] == '\n') body[i] = ' ';
            snprintf(tmp, sizeof tmp, "MIME %s: %s", ty, body);
        } else {
            snprintf(tmp, sizeof tmp, "MIME %s (%zu B)", ty, r->payload_len);
        }
    } else if (r->tnf == NDEF_TNF_EXTERNAL) {
        char ty[NDEF_MAX_TYPE + 1], pl[NDEF_MAX_PAYLOAD + 1];
        memcpy(ty, r->type, r->type_len); ty[r->type_len] = 0;
        size_t pn = r->payload_len < NDEF_MAX_PAYLOAD ? r->payload_len : NDEF_MAX_PAYLOAD;
        memcpy(pl, r->payload, pn); pl[pn] = 0;
        snprintf(tmp, sizeof tmp, "External %s: %s", ty, pl);
    } else {
        char ty[NDEF_MAX_TYPE + 1];
        memcpy(ty, r->type, r->type_len); ty[r->type_len] = 0;
        snprintf(tmp, sizeof tmp, "TNF %u type '%s' (%zu B)", r->tnf, ty, r->payload_len);
    }
    snprintf(out, cap, "%s", tmp);
}

/* ---- Mifare Classic NDEF mapping ----------------------------------------- */

const uint8_t NDEF_MAD_KEY[6]  = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
const uint8_t NDEF_DATA_KEY[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

static const uint8_t MAD_TRAILER_TAIL[10]  = {0x78, 0x77, 0x88, 0xC1,        /* acc + GPB */
                                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t NDEF_TRAILER_TAIL[10] = {0x7F, 0x07, 0x88, 0x40,
                                              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t MAD_AID_NDEF[2] = {0x03, 0xE1};   /* app code 0x03, cluster 0xE1 */

/* CRC-8 used by the MAD: poly 0x1D, preset 0xC7, MSB-first. */
static uint8_t mad_crc8(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xC7;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x1D) : (uint8_t)(crc << 1);
    }
    return crc;
}

int ndef_to_mifare(const uint8_t *ndef, size_t ndef_len, const uint8_t block0[16],
                   int card_sectors, uint8_t image[][64], int *used)
{
    if (card_sectors < 2) return -1;
    int max_data = card_sectors < 16 ? card_sectors - 1 : 15;  /* MAD1 covers sectors 1..15 */

    /* TLV stream: 0x03 <len> <ndef> 0xFE, then 0x00 pad to a 48-byte boundary. */
    uint8_t tlv[NDEF_MAX_MESSAGE + 8];
    size_t t = 0;
    tlv[t++] = 0x03;
    if (ndef_len < 0xFF) {
        tlv[t++] = (uint8_t)ndef_len;
    } else {
        tlv[t++] = 0xFF;
        tlv[t++] = (uint8_t)(ndef_len >> 8);
        tlv[t++] = (uint8_t)ndef_len;
    }
    if (t + ndef_len + 1 > sizeof tlv) return -1;
    memcpy(tlv + t, ndef, ndef_len); t += ndef_len;
    tlv[t++] = 0xFE;                              /* terminator */

    int nsec = (int)((t + 47) / 48);
    if (nsec < 1) nsec = 1;
    if (nsec > max_data) return -1;               /* doesn't fit */
    while (t < (size_t)nsec * 48) tlv[t++] = 0x00;

    /* --- sector 0: manufacturer block + MAD + MAD trailer --- */
    uint8_t *s0 = image[0];
    memset(s0, 0, 64);
    if (block0) memcpy(s0, block0, 16);
    /* MAD body = bytes [1..31]: info(0) + AID per sector 1..15 */
    uint8_t mad[32];
    memset(mad, 0, sizeof mad);
    mad[1] = 0x00;                                /* Info byte (no publisher sector) */
    for (int s = 1; s <= 15; s++) {
        const uint8_t *aid = (s <= nsec) ? MAD_AID_NDEF : (const uint8_t[2]){0, 0};
        mad[2 * s] = aid[0];                      /* block1[2..15]=s1..7, block2[..]=s8..15 */
        mad[2 * s + 1] = aid[1];
    }
    mad[0] = mad_crc8(mad + 1, sizeof mad - 1);   /* CRC over [1..31] */
    memcpy(s0 + 16, mad, 32);                     /* blocks 1 and 2 */
    memcpy(s0 + 48, NDEF_MAD_KEY, 6);
    memcpy(s0 + 54, MAD_TRAILER_TAIL, 10);

    /* --- data sectors 1..nsec: TLV bytes + NDEF trailer --- */
    for (int s = 1; s <= nsec; s++) {
        uint8_t *sec = image[s];
        memcpy(sec, tlv + (size_t)(s - 1) * 48, 48);  /* 3 data blocks */
        memcpy(sec + 48, NDEF_DATA_KEY, 6);
        memcpy(sec + 54, NDEF_TRAILER_TAIL, 10);
    }

    if (used) *used = nsec;
    return 0;
}

int mifare_to_ndef(const uint8_t *image, int card_sectors, uint8_t *out, size_t cap)
{
    int last = card_sectors < 16 ? card_sectors - 1 : 15;
    /* Concatenate the 3 data blocks (48 B) of sectors 1..last into one stream. */
    uint8_t stream[16 * 48];
    size_t sn = 0;
    for (int s = 1; s <= last; s++) {
        memcpy(stream + sn, image + (size_t)s * 64, 48);
        sn += 48;
    }
    /* Walk the TLV stream for the 0x03 (NDEF) record. */
    size_t o = 0;
    while (o < sn) {
        uint8_t tag = stream[o++];
        if (tag == 0x00) continue;               /* NULL TLV — padding */
        if (tag == 0xFE) break;                  /* terminator */
        if (o >= sn) break;
        size_t len = stream[o++];
        if (len == 0xFF) {                       /* 3-byte length */
            if (o + 2 > sn) break;
            len = ((size_t)stream[o] << 8) | stream[o + 1];
            o += 2;
        }
        if (o + len > sn) len = sn - o;          /* clamp to what we have */
        if (tag == 0x03) {                       /* NDEF Message TLV */
            if (len > cap) len = cap;
            memcpy(out, stream + o, len);
            return (int)len;
        }
        o += len;                                /* skip other TLVs */
    }
    return -1;
}
