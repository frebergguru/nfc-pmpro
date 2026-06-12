/* test_ndef.c — NDEF encode/decode + Mifare Classic NDEF mapping self-tests. */
#include "ndef.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } } while (0)

static void test_text(void)
{
    ndef_message m;
    ndef_msg_init(&m);
    assert(ndef_add_text(&m, "en", "Hello") == 0);

    uint8_t buf[256];
    int n = ndef_encode(&m, buf, sizeof buf);
    CHECK(n > 0, "text encode");
    /* header: MB|ME|SR|WK (0xD1), type len 1, payload len, 'T', status, "en", body */
    CHECK(buf[0] == 0xD1, "text flags MB|ME|SR|WK");
    CHECK(buf[3] == 'T', "text type T");

    ndef_message d;
    CHECK(ndef_decode(buf, (size_t)n, &d) == 1, "text decode count");
    char desc[256];
    ndef_record_describe(&d.rec[0], desc, sizeof desc);
    CHECK(strcmp(desc, "Text [en]: Hello") == 0, desc);
}

static void test_uri(void)
{
    struct { const char *uri; uint8_t code; const char *rest; } cases[] = {
        {"https://example.com",      0x04, "example.com"},
        {"https://www.example.com",  0x02, "example.com"},
        {"http://foo.test/x",        0x03, "foo.test/x"},
        {"tel:+15551234",            0x05, "+15551234"},
        {"mailto:a@b.com",           0x06, "a@b.com"},
        {"geo:59.91,10.75",          0x00, "geo:59.91,10.75"},
        {"ircs://server",            0x00, "ircs://server"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ndef_message m; ndef_msg_init(&m);
        CHECK(ndef_add_uri(&m, cases[i].uri) == 0, cases[i].uri);
        CHECK(m.rec[0].payload[0] == cases[i].code, cases[i].uri);
        uint8_t buf[256];
        int n = ndef_encode(&m, buf, sizeof buf);
        ndef_message d;
        CHECK(ndef_decode(buf, (size_t)n, &d) == 1, "uri decode");
        char full[256];
        CHECK(ndef_uri_full(&d.rec[0], full, sizeof full) > 0, "uri full");
        CHECK(strcmp(full, cases[i].uri) == 0, full);
    }
}

static void test_smartposter(void)
{
    ndef_message m; ndef_msg_init(&m);
    CHECK(ndef_add_smartposter(&m, "https://example.com", "Example", "en") == 0, "sp add");
    CHECK(m.rec[0].type_len == 2 && m.rec[0].type[0] == 'S' && m.rec[0].type[1] == 'p', "sp type");

    /* the payload is itself an NDEF message of 2 records (URI + Text) */
    ndef_message inner;
    CHECK(ndef_decode(m.rec[0].payload, m.rec[0].payload_len, &inner) == 2, "sp inner count");
    char full[256];
    CHECK(ndef_uri_full(&inner.rec[0], full, sizeof full) > 0
          && strcmp(full, "https://example.com") == 0, "sp inner uri");
}

static void test_vcard_aar_external(void)
{
    ndef_message m; ndef_msg_init(&m);
    ndef_vcard vc = { .name = "Ada", .phone = "+1555", .email = "ada@x.io" };
    CHECK(ndef_add_vcard(&m, &vc) == 0, "vcard add");
    CHECK(m.rec[0].tnf == NDEF_TNF_MIME, "vcard tnf");
    CHECK(memcmp(m.rec[0].type, "text/vcard", 10) == 0, "vcard mime type");
    CHECK(memcmp(m.rec[0].payload, "BEGIN:VCARD", 11) == 0, "vcard body");

    ndef_msg_init(&m);
    CHECK(ndef_add_aar(&m, "com.example.app") == 0, "aar add");
    CHECK(m.rec[0].tnf == NDEF_TNF_EXTERNAL, "aar tnf");
    CHECK(memcmp(m.rec[0].type, "android.com:pkg", 15) == 0, "aar type");
    char desc[256];
    ndef_record_describe(&m.rec[0], desc, sizeof desc);
    CHECK(strcmp(desc, "External android.com:pkg: com.example.app") == 0, desc);
}

static void test_social(void)
{
    ndef_message m; ndef_msg_init(&m);
    CHECK(ndef_add_social(&m, "GitHub", "@ada") == 0, "social add");   /* '@' trimmed */
    char full[256];
    CHECK(ndef_uri_full(&m.rec[0], full, sizeof full) > 0
          && strcmp(full, "https://github.com/ada") == 0, full);

    ndef_msg_init(&m);
    CHECK(ndef_add_social(&m, "Instagram", "ada") == 0, "instagram add");
    ndef_uri_full(&m.rec[0], full, sizeof full);
    CHECK(strcmp(full, "https://instagram.com/ada") == 0, full);

    /* an already-full URL passes through untouched, even with an unknown platform */
    ndef_msg_init(&m);
    ndef_add_social(&m, "Whatever", "https://mastodon.social/@ada");
    ndef_uri_full(&m.rec[0], full, sizeof full);
    CHECK(strcmp(full, "https://mastodon.social/@ada") == 0, full);
}

static void test_service(void)
{
    ndef_message m; ndef_msg_init(&m);
    CHECK(ndef_add_service(&m, "Google Review (Place ID)", "ChIJabc123") == 0, "review add");
    char full[256];
    ndef_uri_full(&m.rec[0], full, sizeof full);
    CHECK(strcmp(full, "https://search.google.com/local/writereview?placeid=ChIJabc123") == 0, full);

    ndef_msg_init(&m);
    ndef_add_service(&m, "Play Store app", "com.example.app");
    ndef_uri_full(&m.rec[0], full, sizeof full);
    CHECK(strcmp(full, "https://play.google.com/store/apps/details?id=com.example.app") == 0, full);

    /* a ready-made g.page review link passes through verbatim */
    ndef_msg_init(&m);
    ndef_add_service(&m, "Google Review (Place ID)", "https://g.page/r/CabcDEF/review");
    ndef_uri_full(&m.rec[0], full, sizeof full);
    CHECK(strcmp(full, "https://g.page/r/CabcDEF/review") == 0, full);
}

static void test_multi_record(void)
{
    ndef_message m; ndef_msg_init(&m);
    ndef_add_uri(&m, "https://a.example");
    ndef_add_text(&m, "en", "label");
    uint8_t buf[512];
    int n = ndef_encode(&m, buf, sizeof buf);
    CHECK((buf[0] & 0x80) && !(buf[0] & 0x40), "first record MB set, ME clear");
    ndef_message d;
    CHECK(ndef_decode(buf, (size_t)n, &d) == 2, "multi decode count");
    CHECK(d.rec[1].type[0] == 'T', "second record is Text");
}

static void test_mifare_roundtrip(void)
{
    ndef_message m; ndef_msg_init(&m);
    ndef_add_uri(&m, "https://example.com/some/longer/path?q=1");
    ndef_add_text(&m, "en", "A reasonably long label to push past one block");
    uint8_t ndef[512];
    int nl = ndef_encode(&m, ndef, sizeof ndef);
    CHECK(nl > 48, "multi-block ndef");

    uint8_t block0[16] = {0xDE,0xAD,0xBE,0xEF, 0x08, 0x04,0x00, 0,0,0,0,0,0,0,0,0};
    uint8_t image[16][64];
    memset(image, 0, sizeof image);
    int used = 0;
    CHECK(ndef_to_mifare(ndef, (size_t)nl, block0, 16, image, &used) == 0, "to_mifare");
    CHECK(used >= 2, "spans >=2 data sectors");

    /* sector 0: block0 preserved, MAD AID for used data sectors, MAD trailer key */
    CHECK(memcmp(image[0], block0, 16) == 0, "block0 preserved");
    CHECK(image[0][16 + 2] == 0x03 && image[0][16 + 3] == 0xE1, "MAD AID sector1 = NDEF");
    CHECK(memcmp(image[0] + 48, NDEF_MAD_KEY, 6) == 0, "MAD sector key A");
    CHECK(image[0][57] == 0xC1, "MAD GPB 0xC1");

    /* data sector 1: NDEF data key + TLV starts with 0x03 */
    CHECK(memcmp(image[1] + 48, NDEF_DATA_KEY, 6) == 0, "NDEF data key A");
    CHECK(image[1][0] == 0x03, "TLV tag 0x03");

    /* round-trip back to the same NDEF bytes */
    uint8_t got[512];
    int gl = mifare_to_ndef((const uint8_t *)image, 16, got, sizeof got);
    CHECK(gl == nl, "mifare->ndef length matches");
    CHECK(gl == nl && memcmp(got, ndef, (size_t)nl) == 0, "mifare->ndef bytes match");
}

int main(void)
{
    test_text();
    test_uri();
    test_smartposter();
    test_vcard_aar_external();
    test_social();
    test_service();
    test_multi_record();
    test_mifare_roundtrip();
    if (fails) { printf("%d NDEF check(s) failed\n", fails); return 1; }
    printf("NDEF tests passed\n");
    return 0;
}
