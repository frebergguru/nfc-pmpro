/* ndef.h — NFC Data Exchange Format (NDEF) records + the Mifare Classic mapping.
 *
 * Two layers, both pure (no device, no GTK) so they're unit-testable:
 *
 *  1. NDEF messages/records — build Text / URI / Smart Poster / vCard / Android
 *     Application Record / MIME / external / raw records, encode to bytes, and
 *     decode bytes back into records (for reading a tag).
 *
 *  2. Mifare Classic NDEF mapping — lay an NDEF message into a Classic memory
 *     image (MAD in sector 0 + the 0x03/0xFE TLV in NDEF-keyed data sectors), and
 *     pull it back out. This is the only NDEF-capable storage the FR-RATEL can
 *     write: it has no Ultralight/NTAG page write (see PROTOCOL.md), so NDEF goes
 *     on Mifare Classic 1K/4K (Android reads NDEF-on-Classic; iOS does not).
 */
#ifndef PMPRO_NDEF_H
#define PMPRO_NDEF_H

#include <stdint.h>
#include <stddef.h>

/* TNF — Type Name Format (the low 3 bits of an NDEF record header). */
enum {
    NDEF_TNF_EMPTY       = 0x00,
    NDEF_TNF_WELL_KNOWN  = 0x01,   /* RTD: "T" text, "U" URI, "Sp" smart poster */
    NDEF_TNF_MIME        = 0x02,   /* RFC-2046 media type, e.g. "text/vcard" */
    NDEF_TNF_ABS_URI     = 0x03,
    NDEF_TNF_EXTERNAL    = 0x04,   /* "domain:type", e.g. "android.com:pkg" */
    NDEF_TNF_UNKNOWN     = 0x05,
    NDEF_TNF_UNCHANGED   = 0x06,
};

#define NDEF_MAX_RECORDS  16
#define NDEF_MAX_TYPE     64
#define NDEF_MAX_PAYLOAD  2048
#define NDEF_MAX_MESSAGE  4096

typedef struct {
    uint8_t tnf;
    uint8_t type[NDEF_MAX_TYPE];   size_t type_len;
    uint8_t id[NDEF_MAX_TYPE];     size_t id_len;
    uint8_t payload[NDEF_MAX_PAYLOAD]; size_t payload_len;
} ndef_record;

typedef struct {
    ndef_record rec[NDEF_MAX_RECORDS];
    int n;
} ndef_message;

void ndef_msg_init(ndef_message *m);

/* Append an empty record and return it (NULL if the message is full). */
ndef_record *ndef_msg_add(ndef_message *m);

/* ---- record builders (return 0 on success, -1 on overflow/bad-arg) ------- */

/* Well-known Text ("T"): ISO language code (e.g. "en") + UTF-8 body. */
int ndef_add_text(ndef_message *m, const char *lang, const char *text);

/* Well-known URI ("U"): abbreviates a known scheme prefix into the 1-byte code.
 * Covers http(s), tel:, mailto:, ftp, file:, geo:, and any other URI verbatim —
 * so URL / "custom URL" / social / video / file / phone / mail are all URIs. */
int ndef_add_uri(ndef_message *m, const char *uri);

/* Well-known Smart Poster ("Sp"): a URI plus a localized title (Text record),
 * nested as a sub-message — i.e. "a link with a label". `title`/`lang` optional. */
int ndef_add_smartposter(ndef_message *m, const char *uri,
                         const char *title, const char *lang);

/* MIME media-type record (TNF 0x02), e.g. type "text/vcard". */
int ndef_add_mime(ndef_message *m, const char *mime,
                  const uint8_t *data, size_t n);

/* External type record (TNF 0x04), type "domain:name". */
int ndef_add_external(ndef_message *m, const char *type,
                      const uint8_t *data, size_t n);

/* Android Application Record — external "android.com:pkg" naming a package, so a
 * phone launches/installs that app. */
int ndef_add_aar(ndef_message *m, const char *package);

/* geo: location URI ("geo:<lat>,<lon>"). `latlon` is the part after "geo:". */
int ndef_add_geo(ndef_message *m, const char *latlon);

/* Social-media profile link. A known `platform` name (see NDEF_SOCIAL) maps to its
 * profile URL prefix, to which `handle` is appended (a leading '@' is trimmed); an
 * unknown platform or a handle that's already a full http(s) URL is used as-is.
 * Stored as an ordinary URI record. */
int ndef_add_social(ndef_message *m, const char *platform, const char *handle);

/* A "service / review / app" link template (Google Review, Maps, Yelp, app stores,
 * payment links, …): the chosen `service` maps to a URL prefix to which `value`
 * (a Place ID, package name, username, …) is appended; a value that's already a
 * full http(s) URL — e.g. a g.page/r/…/review link straight from Google Business
 * Profile — is used verbatim. Stored as an ordinary URI record. */
int ndef_add_service(ndef_message *m, const char *service, const char *value);

/* Tables of known templates (display name -> URL prefix), each terminated by a
 * {NULL, NULL} entry, used to populate the GUI/CLI lists. */
typedef struct { const char *name; const char *prefix; } ndef_social_site;
extern const ndef_social_site NDEF_SOCIAL[];    /* social profiles */
extern const ndef_social_site NDEF_SERVICE[];   /* review / maps / app / payment */

/* A contact, built as a vCard 3.0 (MIME "text/vcard"). Any field may be NULL. */
typedef struct {
    const char *name;    /* full name (FN/N) */
    const char *phone;
    const char *email;
    const char *org;
    const char *url;
    const char *address; /* free-form, stored in the ADR street component */
    const char *note;
} ndef_vcard;
int ndef_add_vcard(ndef_message *m, const ndef_vcard *vc);

/* Fully custom record — caller supplies TNF, type and payload bytes. */
int ndef_add_raw(ndef_message *m, uint8_t tnf,
                 const uint8_t *type, size_t type_len,
                 const uint8_t *payload, size_t payload_len);

/* ---- encode / decode ----------------------------------------------------- */

/* Serialize the message (sets MB/ME/SR/IL flags). Returns bytes written, -1 on
 * overflow. */
int ndef_encode(const ndef_message *m, uint8_t *out, size_t cap);

/* Parse raw NDEF bytes into records. Returns the record count, -1 on malformed
 * input. */
int ndef_decode(const uint8_t *in, size_t len, ndef_message *m);

/* ---- inspection ---------------------------------------------------------- */

/* Reconstruct the full URI of a "U" record (re-prepends the abbreviated scheme).
 * Returns the length written (excluding NUL), or -1 if not a URI record. */
int ndef_uri_full(const ndef_record *r, char *out, size_t cap);

/* One human-readable line describing a record, e.g.
 *   "URI: https://example.com"  /  "Text [en]: hi"  /  "Contact (text/vcard, 84 B)".
 * Always NUL-terminates. */
void ndef_record_describe(const ndef_record *r, char *out, size_t cap);

/* ---- Mifare Classic NDEF mapping ----------------------------------------- */

/* Standard keys/markers (also useful to callers building reads/writes). */
extern const uint8_t NDEF_MAD_KEY[6];    /* A0 A1 A2 A3 A4 A5 — MAD sector key A */
extern const uint8_t NDEF_DATA_KEY[6];   /* D3 F7 D3 F7 D3 F7 — NDEF data key A */

/* Build a Mifare Classic NDEF image from raw NDEF bytes.
 *  - `block0`     : the 16-byte manufacturer block to keep in sector 0 (or NULL
 *                   to zero it). On a genuine card block 0 is read-only, so the
 *                   writer must preserve it; this just carries it through.
 *  - `card_sectors`: 16 (1K) or 40 (4K). Only the first 16 sectors (MAD1, ~720 B
 *                   of NDEF) are used; larger 4K MAD2 storage is not written.
 *  - `image`      : caller-provided [card_sectors][64], filled for sector 0 (MAD)
 *                   and the data sectors used; other sectors are left untouched.
 *  - `*used`      : set to the count of NDEF data sectors written (sectors 1..used).
 * Returns 0 on success, -1 if the message doesn't fit. */
int ndef_to_mifare(const uint8_t *ndef, size_t ndef_len, const uint8_t block0[16],
                   int card_sectors, uint8_t image[][64], int *used);

/* Extract NDEF bytes from a Mifare Classic image (concatenates data sectors'
 * blocks from sector 1 and parses the 0x03/0xFE TLV). Returns the NDEF length, or
 * -1 if no NDEF TLV is found. */
int mifare_to_ndef(const uint8_t *image, int card_sectors, uint8_t *out, size_t cap);

#endif /* PMPRO_NDEF_H */
