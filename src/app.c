/* app.c — FURUI NFC PM-Pro companion (GTK4 + libadwaita).
 *
 * Speaks the reverse-engineered FURUI "talk" protocol (RC4 + CRC16 + framing,
 * see PROTOCOL.md / furui.c / session.c) over raw hidraw. Device operations run
 * on a background thread and post results back to the UI via g_idle_add.
 *
 * Tabs: Device · HF (Mifare) · LF / HID · Crack · Dump · Console. Each tab has
 * its own log view so an action's output appears where the action lives.
 */
#include <adwaita.h>
#include <gtk/gtk.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include "hidraw.h"
#include "furui.h"
#include "session.h"
#include "crack.h"
#include "hardnested_glue.h"
#include "nested.h"
#include "protocol.h"
#include "dump.h"
#include "ndef.h"

#define APP_ID "com.furui.pmpro"

typedef struct {
    AdwApplication *app;
    GtkWindow *win;
    pmpro_dev dev;
    gboolean opened;       /* hidraw fd open */
    gboolean connected;    /* handshake done */
    gboolean busy;
    gboolean mute;         /* suppress confirmation beeps */
    gboolean loading;      /* set while restoring settings (suppresses save) */
    GMutex lock;

    GtkWidget *status_pill;
    GtkWidget *info_label;
    GtkWidget *mute_check;     /* the "Mute beeps" toggle (for restore) */
    GPtrArray *key_files;      /* paths of imported .keys files (persisted) */

    /* HF (Mifare) tab */
    GtkWidget *key_entry;      /* read key A */
    GtkWidget *ws_sector, *ws_key, *ws_data;   /* write sector */
    GtkWidget *fmt_sector, *fmt_key;           /* format sector */
    GtkWidget *clone_key;                       /* clone destination key A */
    GtkWidget *setkey_entry;                     /* set-password: new key */
    GtkTextBuffer *hf_buf; GtkWidget *hf_view;

    /* LF / HID tab */
    GtkWidget *lf_entry;       /* LF write fields */
    GtkWidget *hid_entry;      /* HID write 12-byte card id */
    uint8_t lf_copy[6];        /* last LF copy (for write fallback) */
    gboolean lf_copy_have;
    GtkTextBuffer *lfhid_buf; GtkWidget *lfhid_view;

    /* Crack tab */
    GtkWidget *crack_block, *crack_typeB;
    GtkTextBuffer *crack_buf; GtkWidget *crack_view;
    char mfd_path[512];

    /* Dump tab */
    GtkWidget *edit_area;              /* editable hex editor for the buffer */
    GtkTextBuffer *dump_buf; GtkWidget *dump_view;   /* read-only log */

    /* Console tab */
    GtkWidget *hex_entry;
    GtkTextBuffer *console_buf; GtkWidget *console_view;

    /* Records (NDEF) tab */
    GtkWidget *rec_type;             /* GtkDropDown: record type */
    GtkWidget *rec_stack;            /* per-type field group, switched by rec_type */
    GtkWidget *rec_text_lang, *rec_text_body;
    GtkWidget *rec_uri;
    GtkWidget *rec_sp_uri, *rec_sp_title;
    GtkWidget *rec_vc_name, *rec_vc_phone, *rec_vc_email, *rec_vc_org, *rec_vc_url;
    GtkWidget *rec_aar;
    GtkWidget *rec_geo;
    GtkWidget *rec_social_site, *rec_social_handle;
    GtkWidget *rec_service_site, *rec_service_value;
    GtkWidget *rec_mime_type, *rec_mime_data;
    GtkWidget *rec_ext_type, *rec_ext_data;
    GtkWidget *rec_raw_tnf, *rec_raw_type, *rec_raw_payload;
    GtkTextBuffer *rec_buf; GtkWidget *rec_view;
    ndef_message rec_msg;            /* the message being built (main-thread only) */

    AdwToastOverlay *toasts;

    pmpro_dump last;       /* read/loaded card buffer */
    gboolean have_last;
    uint8_t cur_key[6];    /* key for the next sector read (main->worker) */

    gboolean auto_read;    /* poll + auto-read on card detect */
    guint poll_id;         /* g_timeout source id (0 = none) */
    uint8_t poll_uid[10];  /* last seen UID (debounce) */
    int poll_uid_len;
} App;

/* ---- UI marshalling (worker thread -> main loop) ----------------------- */

enum { K_STATUS, K_TOAST, K_INFO, K_HF, K_LFHID, K_CRACK, K_DUMP, K_CONSOLE, K_RECORDS };

typedef struct {
    App *a; int kind; int ok; char text[1024];
    int is_sector;            /* render sdata as an MCT-style sector block */
    int sector; uint8_t sdata[256]; int sdlen;
} UiMsg;

/* colour tags, matching MifareClassicTool's scheme so dumps look familiar:
 * UID/manufacturer block = orange, Key A = green, ACs = red, Key B = blue.
 * Plus the two sides of a diff (dump A green, dump B red). Added only to the
 * buffers that show card data (HF + Dump). */
static void buf_add_tags(GtkTextBuffer *b)
{
    gtk_text_buffer_create_tag(b, "uid",  "foreground", "#ff7800",
                               "weight", PANGO_WEIGHT_BOLD, NULL);   /* UID/manuf — orange */
    gtk_text_buffer_create_tag(b, "keyA", "foreground", "#2ec27e",
                               "weight", PANGO_WEIGHT_BOLD, NULL);   /* key A — green */
    gtk_text_buffer_create_tag(b, "acs",  "foreground", "#e01b24", NULL); /* ACs — red */
    gtk_text_buffer_create_tag(b, "keyB", "foreground", "#3584e4",
                               "weight", PANGO_WEIGHT_BOLD, NULL);   /* key B — blue */
    gtk_text_buffer_create_tag(b, "value", "foreground", "#f5c211", NULL); /* value block — yellow */
    gtk_text_buffer_create_tag(b, "dim", "foreground", "#9a9a9a",
                               "style", PANGO_STYLE_ITALIC, NULL);  /* decode notes */
    gtk_text_buffer_create_tag(b, "diffA", "foreground", "#2ec27e", NULL); /* dump A — green */
    gtk_text_buffer_create_tag(b, "diffB", "foreground", "#e01b24", NULL); /* dump B — red */
}

static int is_hexch(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static void tag_range(GtkTextBuffer *b, int base, int from, int to, const char *tag)
{
    GtkTextIter a, z;
    gtk_text_buffer_get_iter_at_offset(b, &a, base + from);
    gtk_text_buffer_get_iter_at_offset(b, &z, base + to);
    gtk_text_buffer_apply_tag_by_name(b, tag, &a, &z);
}

/* Colour one just-inserted line `t` starting at char offset `base`. */
static void colorize_line(GtkTextBuffer *buf, int base, const char *t)
{
    if (!gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "keyA"))
        return;   /* this buffer isn't colourised */

    /* diff sides: leading spaces then "A:" / "B:" → colour the whole line */
    const char *p = t;
    while (*p == ' ') p++;
    int len = (int)strlen(t);
    if ((p[0] == 'A' || p[0] == 'a') && p[1] == ':') { tag_range(buf, base, 0, len, "diffA"); return; }
    if ((p[0] == 'B' || p[0] == 'b') && p[1] == ':') { tag_range(buf, base, 0, len, "diffB"); return; }

    /* otherwise: find the trailing "XX XX …" hex run and colour the trailer
     * keys (last 16 bytes = keyA[0..5], access[6..9], keyB[10..15]). */
    int hs = len;
    while (hs > 0 && (is_hexch(t[hs - 1]) || t[hs - 1] == ' ')) hs--;
    while (hs < len && t[hs] == ' ') hs++;
    int runlen = len - hs;
    if (runlen < 16) return;
    int bytes = (runlen + 1) / 3;                 /* "XX XX … XX" = 3*bytes-1 chars */
    if (bytes != 16 && bytes != 64 && bytes != 256) return;   /* a sector w/ trailer */

    /* sector index = first integer in the prefix; sector 0 block 0 is the
     * UID/manufacturer block (colour its first 16 bytes orange). */
    int sec = -1;
    for (const char *q = t; q < t + hs; q++)
        if (*q >= '0' && *q <= '9') { sec = atoi(q); break; }
    if (sec == 0)
        tag_range(buf, base, hs, hs + 15 * 3 + 2, "uid");

    /* trailer = last 16 bytes: keyA[0..5] ACs[6..9] keyB[10..15] */
    int ka = bytes - 16;
    tag_range(buf, base, hs + ka * 3,          hs + (ka + 5) * 3 + 2,  "keyA");
    tag_range(buf, base, hs + (ka + 6) * 3,    hs + (ka + 9) * 3 + 2,  "acs");
    tag_range(buf, base, hs + (ka + 10) * 3,   hs + (ka + 15) * 3 + 2, "keyB");
}

static void append_view(GtkTextBuffer *buf, GtkWidget *view, const char *t)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    int base = gtk_text_iter_get_offset(&end);
    gtk_text_buffer_insert(buf, &end, t, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);
    colorize_line(buf, base, t);
    GtkTextMark *m = gtk_text_buffer_get_insert(buf);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_move_mark(buf, m, &end);
    if (view)
        gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(view), m);
}

/* insert a dim/italic note line (decode hints), tagged "dim" if available */
static void append_dim(GtkTextBuffer *buf, const char *text)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    int base = gtk_text_iter_get_offset(&end);
    gtk_text_buffer_insert(buf, &end, text, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);
    if (gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "dim")) {
        GtkTextIter s, e;
        gtk_text_buffer_get_iter_at_offset(buf, &s, base);
        gtk_text_buffer_get_iter_at_offset(buf, &e, base + (int)strlen(text));
        gtk_text_buffer_apply_tag_by_name(buf, "dim", &s, &e);
    }
}

/* Render a sector MCT-style: "Sector: N" header, one line per 16-byte block,
 * coloured (UID/keyA/ACs/keyB/value). With show_acs, append dim notes decoding
 * value blocks and the trailer's access conditions (read-only views only). */
static void append_sector(GtkTextBuffer *buf, GtkWidget *view, int sec,
                          const uint8_t *d, int n, int show_acs)
{
    int has_tags = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buf), "keyA") != NULL;
    GtkTextIter end;
    char line[64];
    snprintf(line, sizeof line, "Sector: %d\n", sec);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, line, -1);

    int nblocks = n / 16;
    for (int b = 0; b < nblocks; b++) {
        char hex[64];
        pmpro_hex(d + b * 16, 16, hex, sizeof hex);
        gtk_text_buffer_get_end_iter(buf, &end);
        int base = gtk_text_iter_get_offset(&end);
        gtk_text_buffer_insert(buf, &end, "  ", -1);
        gtk_text_buffer_insert(buf, &end, hex, -1);
        gtk_text_buffer_insert(buf, &end, "\n", -1);
        int is_trailer = (b == nblocks - 1);
        int is_manuf = (sec == 0 && b == 0);
        if (has_tags) {
            int hs = base + 2;                 /* hex starts after the "  " indent */
            if (is_manuf) {
                tag_range(buf, hs, 0, 15 * 3 + 2, "uid");
            } else if (is_trailer) {
                tag_range(buf, hs, 0,        5 * 3 + 2,  "keyA");
                tag_range(buf, hs, 6 * 3,    9 * 3 + 2,  "acs");
                tag_range(buf, hs, 10 * 3,   15 * 3 + 2, "keyB");
            } else if (pmpro_value_block(d + b * 16, NULL, NULL)) {
                tag_range(buf, hs, 0, 15 * 3 + 2, "value");
            }
        }
        if (show_acs && is_trailer) {
            char acs[256], note[300];
            pmpro_decode_acs(d + b * 16, acs, sizeof acs);
            snprintf(note, sizeof note, "    ACs: %s", acs);
            append_dim(buf, note);
        } else if (show_acs && !is_manuf) {
            int32_t v; uint8_t ad;
            if (pmpro_value_block(d + b * 16, &v, &ad)) {
                char note[64];
                snprintf(note, sizeof note, "    = value %d (addr %u)", v, ad);
                append_dim(buf, note);
            }
        }
    }
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, "\n", -1);   /* blank line between sectors */
    GtkTextMark *m = gtk_text_buffer_get_insert(buf);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_move_mark(buf, m, &end);
    if (view)
        gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(view), m);
}

static void set_status(App *a, gboolean ok, const char *text)
{
    gtk_label_set_text(GTK_LABEL(a->status_pill), text);
    gtk_widget_remove_css_class(a->status_pill, "ok");
    gtk_widget_remove_css_class(a->status_pill, "bad");
    gtk_widget_add_css_class(a->status_pill, ok ? "ok" : "bad");
}

static gboolean ui_apply(gpointer p)
{
    UiMsg *m = p;
    App *a = m->a;
    switch (m->kind) {
    case K_STATUS:  set_status(a, m->ok, m->text); break;
    case K_TOAST:   adw_toast_overlay_add_toast(a->toasts, adw_toast_new(m->text)); break;
    case K_INFO:    gtk_label_set_text(GTK_LABEL(a->info_label), m->text); break;
    case K_HF:
        if (m->is_sector) append_sector(a->hf_buf, a->hf_view, m->sector, m->sdata, m->sdlen, 1);
        else append_view(a->hf_buf, a->hf_view, m->text);
        break;
    case K_LFHID:   append_view(a->lfhid_buf, a->lfhid_view, m->text); break;
    case K_CRACK:   append_view(a->crack_buf, a->crack_view, m->text); break;
    case K_DUMP:
        if (m->is_sector) append_sector(a->dump_buf, a->dump_view, m->sector, m->sdata, m->sdlen, 1);
        else append_view(a->dump_buf, a->dump_view, m->text);
        break;
    case K_CONSOLE: append_view(a->console_buf, a->console_view, m->text); break;
    case K_RECORDS: append_view(a->rec_buf, a->rec_view, m->text); break;
    }
    g_free(m);
    return G_SOURCE_REMOVE;
}

static void post(App *a, int kind, int ok, const char *fmt, ...)
{
    UiMsg *m = g_new0(UiMsg, 1);
    m->a = a; m->kind = kind; m->ok = ok;
    va_list ap; va_start(ap, fmt);
    vsnprintf(m->text, sizeof m->text, fmt, ap);
    va_end(ap);
    g_idle_add(ui_apply, m);
}

static void toast(App *a, const char *t)
{
    adw_toast_overlay_add_toast(a->toasts, adw_toast_new(t));
}

/* queue a sector for MCT-style rendering on the main thread (kind = K_HF/K_DUMP) */
static void post_sector(App *a, int kind, int sector, const uint8_t *d, int n)
{
    UiMsg *m = g_new0(UiMsg, 1);
    m->a = a; m->kind = kind; m->is_sector = 1; m->sector = sector;
    if (n > 256) n = 256;
    memcpy(m->sdata, d, n);
    m->sdlen = n;
    g_idle_add(ui_apply, m);
}

/* ---- device helpers (run on worker thread, hold a->lock) --------------- */

static gboolean ensure_ready(App *a)
{
    if (!a->opened) {
        if (!pmpro_open(&a->dev, NULL)) {
            post(a, K_STATUS, 0, "No device");
            post(a, K_TOAST, 0, "%s", a->dev.err);
            return FALSE;
        }
        a->opened = TRUE;
    }
    if (!a->connected) {
        a->connected = furui_connect(&a->dev);
        if (a->connected)
            post(a, K_STATUS, 1, "Connected — %s", a->dev.path);
    }
    return TRUE;
}

/* Rotating buffers so several hex_str() results can be live in one expression. */
static char *hex_str(const uint8_t *d, size_t n)
{
    static char bufs[4][256];
    static int next;
    char *buf = bufs[next++ & 3];
    pmpro_hex(d, n, buf, sizeof bufs[0]);
    return buf;
}

/* confirmation beep, gated by the mute toggle */
static void app_beep(App *a)
{
    if (!a->mute)
        furui_beep(&a->dev, 0x01, 0x02);
}

/* ---- worker ops -------------------------------------------------------- */

static gpointer w_connect(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        if (a->connected) {
            post(a, K_INFO, 1, "FR-RATEL connected on %s. Handshake OK (RC4/CRC16).",
                 a->dev.path);
            post(a, K_TOAST, 1, "Connected");
            app_beep(a);
        } else {
            post(a, K_STATUS, 0, "Handshake failed");
            post(a, K_TOAST, 0, "Connect failed");
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

static gpointer w_beep(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        int ok = furui_beep(&a->dev, 0x01, 0x02);
        post(a, K_TOAST, ok, ok ? "Beep" : "Beep failed");
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

static gpointer w_openfind(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        int ok = furui_openfind(&a->dev);
        post(a, K_TOAST, ok, ok ? "Scan indicator on" : "Find failed");
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

/* read a detected HF card's sectors into the buffer + post them (holds lock) */
static void read_hf_show(App *a, furui_hf_card *c)
{
    uid_info ui; pmpro_decode_uid(c->uid, c->uid_len, &ui);
    char tail[32];
    pmpro_hex(c->tail, c->tail_len, tail, sizeof tail);
    post(a, K_HF, 1, "HF (13.56 MHz)  UID: %s (%d-byte)   [ATQA/SAK: %s]",
         ui.uid, ui.uid_len, tail);
    pmpro_dump_init(&a->last);
    snprintf(a->last.card_type, sizeof a->last.card_type, "ISO14443A");
    snprintf(a->last.frequency, sizeof a->last.frequency, "13.56MHz");
    snprintf(a->last.uid, sizeof a->last.uid, "%s", ui.uid);
    a->have_last = TRUE;
    char kh[20]; pmpro_hex(a->cur_key, 6, kh, sizeof kh);
    uint16_t atqa = c->tail_len >= 2 ? (c->tail[0] | (uint16_t)c->tail[1] << 8) : 0;
    int sak0 = -1;
    int open_sectors = 0;
    for (int s = 0; s < 16; s++) {
        uint8_t blk[64], usekey[6];
        int usetype = -1;
        furui_activate(&a->dev);
        size_t bl = furui_read_sector(&a->dev, (uint8_t)s, 1, a->cur_key, NULL, blk, sizeof blk);
        if (bl >= 64) { memcpy(usekey, a->cur_key, 6); usetype = 0; }
        if (usetype < 0) {
            uint8_t fk[6];
            if (furui_dict_attack(&a->dev, (uint8_t)(s * 4), 0, fk)) {
                furui_activate(&a->dev);
                bl = furui_read_sector(&a->dev, (uint8_t)s, 1, fk, NULL, blk, sizeof blk);
                if (bl >= 64) { memcpy(usekey, fk, 6); usetype = 0; }
            }
            if (usetype < 0 && furui_dict_attack(&a->dev, (uint8_t)(s * 4), 1, fk)) {
                furui_activate(&a->dev);
                bl = furui_read_sector(&a->dev, (uint8_t)s, 2, NULL, fk, blk, sizeof blk);
                if (bl >= 64) { memcpy(usekey, fk, 6); usetype = 1; }
            }
        }
        if (usetype >= 0) {
            open_sectors++;
            if (s == 0) sak0 = blk[5];
            if (usetype == 0) memcpy(blk + 48, usekey, 6);
            else              memcpy(blk + 58, usekey, 6);
            char h[200]; pmpro_hex(blk, 64, h, sizeof h);
            pmpro_dump_add_block(&a->last, h);
            post_sector(a, K_HF, s, blk, 64);
        }
    }
    const char *ct = pmpro_card_type(sak0 >= 0 ? (uint8_t)sak0 : 0xFF, atqa, c->uid_len, NULL);
    post(a, K_HF, 1, "Type: %s", ct);
    snprintf(a->last.card_type, sizeof a->last.card_type, "%s", ct);
    if (!open_sectors)
        post(a, K_HF, 0, "no sectors readable (tried key %s + dictionary). "
             "Recover keys on the Crack tab, load a .keys file, or import a dump's keys.", kh);
    else
        post(a, K_HF, 1, "%d/16 sectors → buffer (Clone, or the Dump tab)", open_sectors);
    post(a, K_TOAST, 1, "HF card read");
    app_beep(a);
}

static gpointer w_read_hf(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        furui_hf_card c;
        if (furui_read_hf(&a->dev, &c)) {
            memcpy(a->poll_uid, c.uid, c.uid_len); a->poll_uid_len = c.uid_len;
            read_hf_show(a, &c);
        } else {
            post(a, K_HF, 0, "HF: no card on reader");
            post(a, K_TOAST, 0, "No HF card");
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

/* auto-read poll worker: if a new card appeared since last poll, read it */
static gpointer w_autoread(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (a->connected) {
        furui_hf_card c;
        if (furui_read_hf(&a->dev, &c)) {
            if (c.uid_len != a->poll_uid_len ||
                memcmp(c.uid, a->poll_uid, c.uid_len) != 0) {
                memcpy(a->poll_uid, c.uid, c.uid_len); a->poll_uid_len = c.uid_len;
                read_hf_show(a, &c);
            }
        } else {
            a->poll_uid_len = 0;   /* card removed → re-read next time it returns */
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

static gpointer w_read_lf(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t cmd[3] = {0x28, 0x01, 0x00}, resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, cmd, 3, resp, sizeof resp, 5000);  /* 5 s like the OEM app */
        if (r >= 3 && resp[2] == 1) {
            size_t dlen = (r > 5) ? r - 5 : 0;
            post(a, K_LFHID, 1, "LF (125 kHz)  data: %s", hex_str(resp + 3, dlen));
            pmpro_dump_init(&a->last);
            snprintf(a->last.card_type, sizeof a->last.card_type, "EM4100/ID");
            snprintf(a->last.frequency, sizeof a->last.frequency, "125kHz");
            snprintf(a->last.uid, sizeof a->last.uid, "%.120s", hex_str(resp + 3, dlen));
            a->have_last = TRUE;
            em4100_info em;
            if (pmpro_decode_em4100(resp + 3, dlen, &em)) {
                post(a, K_LFHID, 1, "  EM4100: id %s  customer %u  card %u  (fob %s)",
                     em.hex, em.customer, em.card_number, em.fob_text);
                snprintf(a->last.meta, sizeof a->last.meta,
                         "EM4100 id %s customer %u card %u fob %s",
                         em.hex, em.customer, em.card_number, em.fob_text);
            }
            post(a, K_TOAST, 1, "LF card read");
            app_beep(a);
        } else {
            post(a, K_LFHID, 0, "LF: no 125 kHz card on reader");
            post(a, K_TOAST, 0, "No LF card");
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

static gpointer w_read_hid(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t buf[64];
        size_t n = furui_read_hid(&a->dev, buf, sizeof buf);
        if (n) {
            post(a, K_LFHID, 1, "HID prox (%zu bytes): %s", n, hex_str(buf, n));
            app_beep(a);
        } else {
            post(a, K_LFHID, 0, "HID: no prox card on reader");
            post(a, K_TOAST, 0, "No HID card");
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

/* Identify: auto-detect whatever tag is on the reader (HF → LF → HID), name its
 * type, and show a summary on the Device page + detail on the matching tab. */
static gpointer w_identify(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        furui_tag_id t;
        switch (furui_identify(&a->dev, &t)) {
        case FURUI_TAG_HF: {
            uid_info ui; pmpro_decode_uid(t.hf.uid, t.hf.uid_len, &ui);
            char tail[32]; pmpro_hex(t.hf.tail, t.hf.tail_len, tail, sizeof tail);
            const char *magic = t.magic_gen1a ? "  ·  gen1a magic (UID-changeable)" : "";
            post(a, K_INFO, 1, "Identified: %s  ·  UID %s (%d-byte)  ·  13.56 MHz%s",
                 t.type, ui.uid, ui.uid_len, magic);
            post(a, K_HF, 1, "Identify → %s", t.type);
            post(a, K_HF, 1, "  UID %s (%d-byte)   ATQA %04X  SAK %02X   [tail %s]%s",
                 ui.uid, ui.uid_len, t.atqa, t.sak, tail, magic);
            memcpy(a->poll_uid, t.hf.uid, t.hf.uid_len); a->poll_uid_len = t.hf.uid_len;
            post(a, K_TOAST, 1, "Identified: %s", t.type);
            app_beep(a);
            break;
        }
        case FURUI_TAG_LF: {
            post(a, K_INFO, 1, "Identified: %s (125 kHz LF)  ·  %s",
                 t.type, hex_str(t.data, t.data_len));
            post(a, K_LFHID, 1, "Identify → LF (125 kHz)  data: %s",
                 hex_str(t.data, t.data_len));
            em4100_info em;
            if (pmpro_decode_em4100(t.data, t.data_len, &em))
                post(a, K_LFHID, 1, "  EM4100: id %s  customer %u  card %u  (fob %s)",
                     em.hex, em.customer, em.card_number, em.fob_text);
            post(a, K_TOAST, 1, "Identified: 125 kHz LF tag");
            app_beep(a);
            break;
        }
        case FURUI_TAG_HID:
            post(a, K_INFO, 1, "Identified: HID Prox  ·  %s", hex_str(t.data, t.data_len));
            post(a, K_LFHID, 1, "Identify → HID prox (%zu bytes): %s",
                 t.data_len, hex_str(t.data, t.data_len));
            post(a, K_TOAST, 1, "Identified: HID prox");
            app_beep(a);
            break;
        default:
            post(a, K_INFO, 0, "No tag detected on the reader "
                 "(tried HF 13.56 MHz, LF 125 kHz, and HID prox).");
            post(a, K_TOAST, 0, "No tag found");
        }
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

/* Magic test: detect a UID-changeable (gen1a / gen2-CUID) card. WRITES block 0
 * (and restores it) — gated behind a confirm dialog. */
static gpointer w_magic(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        char d[160];
        furui_magic_kind k = furui_magic_test(&a->dev, d, sizeof d);
        const char *label =
            k == FURUI_MAGIC_GEN1A  ? "gen1a magic (UID-changeable)" :
            k == FURUI_MAGIC_GEN2   ? "gen2/CUID magic (UID-changeable)" :
            k == FURUI_MAGIC_NONE   ? "genuine card (not magic)" :
            k == FURUI_MAGIC_NOCARD ? "no HF card" : "couldn't probe";
        int magic = (k == FURUI_MAGIC_GEN1A || k == FURUI_MAGIC_GEN2);
        post(a, K_HF, magic, "Magic test: %s — %s", label, d);
        post(a, K_TOAST, magic, "Magic test: %s", label);
        if (magic) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

typedef struct { App *a; uint8_t payload[64]; int len; } RawJob;

static gpointer w_raw(gpointer p)
{
    RawJob *j = p;
    App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, j->payload, j->len, resp, sizeof resp, 2000);
        post(a, K_CONSOLE, 1, "TX %s", hex_str(j->payload, j->len));
        if (r)
            post(a, K_CONSOLE, r >= 3 && resp[2] == 1,
                 "RX(dec) [%zu] %s", r, hex_str(resp, r < 60 ? r : 60));
        else
            post(a, K_CONSOLE, 0, "RX: (no response)");
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    g_free(j);
    return NULL;
}

static gpointer w_write_lf(gpointer p)
{
    RawJob *j = p;     /* payload already built as cmd 2D ... */
    App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, j->payload, j->len, resp, sizeof resp, 3000);
        int ok = r >= 3 && resp[2] == 1;
        post(a, K_LFHID, ok, ok ? "LF write OK (%s)" : "LF write FAILED (%s)",
             hex_str(j->payload, j->len));
        post(a, K_TOAST, ok, ok ? "Wrote LF card" : "LF write failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    g_free(j);
    return NULL;
}

typedef struct { App *a; uint8_t id[12]; } HidJob;

static gpointer w_write_hid(gpointer p)
{
    HidJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        int ok = furui_write_hid(&a->dev, j->id);
        post(a, K_LFHID, ok, ok ? "HID write OK (%s)" : "HID write FAILED (%s)",
             hex_str(j->id, 12));
        post(a, K_TOAST, ok, ok ? "Wrote HID card" : "HID write failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

typedef struct { App *a; uint8_t sector; uint8_t key[6]; uint8_t data[64]; int datalen; } WSJob;

static gpointer w_write_sector(gpointer p)
{
    WSJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        furui_activate(&a->dev);
        int ok = furui_write_sector(&a->dev, j->sector, 1, j->key, NULL, j->data, j->datalen);
        post(a, K_HF, ok, ok ? "Wrote sector %d (%d bytes)" : "Write sector %d FAILED",
             j->sector, j->datalen);
        post(a, K_TOAST, ok, ok ? "Sector written" : "Write failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

typedef struct { App *a; uint8_t sector; uint8_t key[6]; } FmtJob;

static gpointer w_format(gpointer p)
{
    FmtJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        int ok = furui_format_sector(&a->dev, j->sector, 1, j->key, NULL);
        post(a, K_HF, ok, ok ? "Formatted sector %d (data zeroed, default trailer)"
                             : "Format sector %d FAILED", j->sector);
        post(a, K_TOAST, ok, ok ? "Sector formatted" : "Format failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

typedef struct { App *a; uint8_t key[6]; } CloneJob;

static gpointer w_write_buffer(gpointer p)
{
    CloneJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        if (!a->have_last || a->last.n_blocks == 0) {
            post(a, K_TOAST, 0, "Buffer empty — read an HF card or load a dump first");
        } else {
            int wrote = 0;
            for (int s = 0; s < a->last.n_blocks; s++) {
                uint8_t data[64];
                int dl = pmpro_parse_hex(a->last.blocks[s], data, sizeof data);
                if (dl <= 0) continue;
                if (dl >= 64) memcpy(data + 48, j->key, 6);   /* restore trailer keyA */
                furui_activate(&a->dev);
                if (furui_write_sector(&a->dev, (uint8_t)s, 1, j->key, NULL, data, dl)) {
                    wrote++;
                    post(a, K_HF, 1, "  wrote sector %d (%d bytes)", s, dl);
                } else {
                    post(a, K_HF, 0, "  sector %d write FAILED", s);
                }
            }
            post(a, K_TOAST, wrote > 0, "Wrote %d/%d buffered sectors", wrote, a->last.n_blocks);
            if (wrote) app_beep(a);
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

/* ---- whole-card tag operations (Mifare Classic) ------------------------ */

static const uint8_t ACC_DEFAULT[4] = {0xFF, 0x07, 0x80, 0x69};   /* transport access */

/* find a working key for sector s: the box key (A), then dictionary A/B */
static int hf_find_key(App *a, int s, uint8_t key[6], int *type)
{
    uint8_t blk[64];
    furui_activate(&a->dev);
    if (furui_read_sector(&a->dev, (uint8_t)s, 1, a->cur_key, NULL, blk, sizeof blk) >= 64) {
        memcpy(key, a->cur_key, 6); *type = 0; return 1;
    }
    uint8_t fk[6];
    if (furui_dict_attack(&a->dev, (uint8_t)(s * 4), 0, fk)) { memcpy(key, fk, 6); *type = 0; return 1; }
    if (furui_dict_attack(&a->dev, (uint8_t)(s * 4), 1, fk)) { memcpy(key, fk, 6); *type = 1; return 1; }
    return 0;
}

/* read sector s into cur[64] with a working key (sets key/type). returns 1 ok */
static int hf_read(App *a, int s, uint8_t cur[64], uint8_t key[6], int *type)
{
    if (!hf_find_key(a, s, key, type)) return 0;
    furui_activate(&a->dev);
    return furui_read_sector(&a->dev, (uint8_t)s, *type ? 2 : 1,
                             *type ? NULL : key, *type ? key : NULL, cur, 64) >= 64;
}

/* read sector s back and check the data blocks + access bits match `out`.
 * (keyA/keyB aren't readable, but the access bytes prove the trailer was
 * actually rewritten — the device ACKs writes the card silently rejected.) */
static int hf_verify(App *a, int s, const uint8_t out[64])
{
    uint8_t cur[64], key[6]; int type;
    if (!hf_read(a, s, cur, key, &type)) return 0;
    int start = (s == 0) ? 16 : 0;                   /* sector 0 block 0 is preserved */
    if (memcmp(cur + start, out + start, 48 - start) != 0) return 0;   /* data blocks */
    if (memcmp(cur + 54, out + 54, 4) != 0) return 0;                  /* access bits */
    return 1;
}

/* try writing out[64] to sector s with Key B `kb`, verify by read-back */
static int hf_try_keyb(App *a, int s, const uint8_t out[64], const uint8_t kb[6])
{
    furui_activate(&a->dev);
    furui_write_sector(&a->dev, (uint8_t)s, 2, NULL, kb, out, 64);
    return hf_verify(a, s, out);
}

/* write out[64] to sector s, verifying by read-back. If the read key can't
 * change the trailer, try a dictionary Key B, then recover Key B via the
 * nested attack and retry. TW_OK / TW_DENIED / TW_NOKEY. */
enum { TW_OK, TW_DENIED, TW_NOKEY };
static int hf_write(App *a, int s, const uint8_t out[64])
{
    uint8_t key[6]; int type;
    if (!hf_find_key(a, s, key, &type)) return TW_NOKEY;
    furui_activate(&a->dev);
    furui_write_sector(&a->dev, (uint8_t)s, type ? 2 : 1,
                       type ? NULL : key, type ? key : NULL, out, 64);
    if (hf_verify(a, s, out)) return TW_OK;

    uint8_t kb[6];               /* the write didn't take — the trailer needs Key B */
    if (furui_dict_attack(&a->dev, (uint8_t)(s * 4), 1, kb) && hf_try_keyb(a, s, out, kb))
        return TW_OK;

    /* last resort: recover Key B with the nested attack, then retry */
    char log[256];
    post(a, K_HF, 1, "  sector %d: recovering Key B via nested (slow)…", s);
    if (furui_nested_auto(&a->dev, (uint8_t)(s * 4), 1, kb, log, sizeof log)) {
        furui_keys_add(kb);
        if (hf_try_keyb(a, s, out, kb)) return TW_OK;
    }
    return TW_DENIED;
}

static const uint8_t KEY_FF6[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* after a reset: can we read the sector with FF, and is it zeroed + default? */
static int format_ok(App *a, int s)
{
    uint8_t cur[64];
    furui_activate(&a->dev);
    if (furui_read_sector(&a->dev, (uint8_t)s, 1, KEY_FF6, NULL, cur, 64) < 64) return 0;
    int start = (s == 0) ? 16 : 0;                 /* sector 0 block 0 preserved */
    for (int i = start; i < 48; i++) if (cur[i]) return 0;
    return memcmp(cur + 54, ACC_DEFAULT, 4) == 0;
}

/* Factory-reset sector s. Tries cmd18 (zero data + FF trailer) and the device's
 * native cmd16 format, with the read key, a dictionary Key B, then a nested-
 * recovered Key B. cmd16 is the only hope for sector 0 (block 0 is read-only, so
 * a whole-sector cmd18 write is rejected). Returns TW_OK / TW_DENIED / TW_NOKEY. */
static int hf_format_sector(App *a, int s, const uint8_t out[64])
{
    uint8_t key[6]; int type;
    if (!hf_find_key(a, s, key, &type)) return TW_NOKEY;

    /* read key: try raw write, then device format */
    furui_activate(&a->dev);
    furui_write_sector(&a->dev, (uint8_t)s, type ? 2 : 1, type ? NULL : key, type ? key : NULL, out, 64);
    if (hf_verify(a, s, out)) return TW_OK;
    furui_activate(&a->dev);
    furui_format_sector(&a->dev, (uint8_t)s, type ? 2 : 1, type ? NULL : key, type ? key : NULL);
    if (format_ok(a, s)) return TW_OK;

    uint8_t kb[6];
    for (int pass = 0; pass < 2; pass++) {
        int have;
        if (pass == 0) {
            have = furui_dict_attack(&a->dev, (uint8_t)(s * 4), 1, kb);
        } else {
            char log[256];
            post(a, K_HF, 1, "  sector %d: recovering Key B via nested (slow)…", s);
            have = furui_nested_auto(&a->dev, (uint8_t)(s * 4), 1, kb, log, sizeof log);
            if (have) furui_keys_add(kb);
        }
        if (!have) continue;
        if (hf_try_keyb(a, s, out, kb)) return TW_OK;       /* cmd18 with Key B */
        furui_activate(&a->dev);
        furui_format_sector(&a->dev, (uint8_t)s, 2, NULL, kb);   /* cmd16 with Key B */
        if (format_ok(a, s)) return TW_OK;
    }
    return TW_DENIED;
}

static void tw_report(App *a, int s, int r, const char *okmsg)
{
    if (r == TW_OK)          post(a, K_HF, 1, "  sector %d %s", s, okmsg);
    else if (r == TW_DENIED) post(a, K_HF, 0, "  sector %d: write rejected — Key B not usable%s", s,
                                  s == 0 ? " (sector 0 block 0 is read-only on a normal card — needs a magic card)" : "");
    else                     post(a, K_HF, 0, "  sector %d: no key found", s);
}

static gpointer w_format_all(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        post(a, K_HF, 1, "Format memory: resetting every sector to defaults…");
        int done = 0, needB = 0;
        for (int s = 0; s < 16; s++) {
            uint8_t out[64];
            memset(out, 0, 48);
            if (s == 0) {                        /* keep the UID/manufacturer block */
                uint8_t cur[64], key[6]; int type;
                if (hf_read(a, 0, cur, key, &type)) memcpy(out, cur, 16);
            }
            memset(out + 48, 0xFF, 6);           /* keyA -> FF */
            memcpy(out + 54, ACC_DEFAULT, 4);
            memset(out + 58, 0xFF, 6);           /* keyB -> FF */
            int r = hf_format_sector(a, s, out);
            tw_report(a, s, r, "formatted (keys -> FF)");
            if (r == TW_OK) done++; else if (r == TW_DENIED) needB++;
        }
        post(a, K_TOAST, done > 0, "Formatted %d/16 sectors%s", done, needB ? " - some need Key B" : "");
        if (done) { furui_keys_add((const uint8_t[6]){0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}); app_beep(a); }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

static gpointer w_erase(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        post(a, K_HF, 1, "Erase: zeroing data blocks (keeping the card usable)…");
        int done = 0, needB = 0;
        for (int s = 0; s < 16; s++) {
            uint8_t cur[64], key[6]; int type;
            if (!hf_read(a, s, cur, key, &type)) { post(a, K_HF, 0, "  sector %d: no key found", s); continue; }
            uint8_t out[64];
            memset(out, 0, 48);
            if (s == 0) memcpy(out, cur, 16);            /* keep manufacturer block */
            memcpy(out + 48, key, 6);                    /* keep the working key */
            memcpy(out + 54, ACC_DEFAULT, 4);
            memcpy(out + 58, key, 6);
            int r = hf_write(a, s, out);
            tw_report(a, s, r, "erased");
            if (r == TW_OK) done++; else if (r == TW_DENIED) needB++;
        }
        post(a, K_TOAST, done > 0, "Erased %d/16 sectors%s", done, needB ? " - some need Key B" : "");
        if (done) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

/* write a chosen key to every trailer (Set password); j->key == FF = Remove */
static gpointer w_setkey(gpointer p)
{
    CloneJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        post(a, K_HF, 1, "Writing new key to every sector trailer…");
        int done = 0, needB = 0;
        for (int s = 0; s < 16; s++) {
            uint8_t cur[64], key[6]; int type;
            if (!hf_read(a, s, cur, key, &type)) { post(a, K_HF, 0, "  sector %d: no key found", s); continue; }
            uint8_t out[64];
            memcpy(out, cur, 48);                          /* keep data */
            memcpy(out + 48, j->key, 6);                   /* new keyA */
            memcpy(out + 54, ACC_DEFAULT, 4);
            memcpy(out + 58, j->key, 6);                   /* new keyB */
            int r = hf_write(a, s, out);
            tw_report(a, s, r, "key updated");
            if (r == TW_OK) done++; else if (r == TW_DENIED) needB++;
        }
        if (done) { furui_keys_add(j->key); app_beep(a); }   /* so later reads work */
        post(a, K_TOAST, done > 0, "Updated key on %d/16 sectors%s", done, needB ? " - some need Key B" : "");
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

static gpointer w_erase_lf(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t payload[7] = {0x2D, 0, 0, 0, 0, 0, 0};   /* blank EM4100 */
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, payload, 7, resp, sizeof resp, 3000);
        int ok = r >= 3 && resp[2] == 1;
        post(a, K_LFHID, ok, ok ? "LF erased (blank ID written)" : "LF erase FAILED");
        post(a, K_TOAST, ok, ok ? "LF erased" : "LF erase failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

static gpointer w_copy_lf(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t cmd[3] = {0x28, 0x01, 0x00}, resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, cmd, 3, resp, sizeof resp, 5000);  /* 5 s like the OEM app */
        if (r >= 3 && resp[2] == 1) {
            size_t dlen = r > 5 ? r - 5 : 0;
            int nb = dlen < 6 ? (int)dlen : 6;
            memset(a->lf_copy, 0, 6);
            memcpy(a->lf_copy, resp + 3, nb);
            a->lf_copy_have = TRUE;
            post(a, K_LFHID, 1, "LF copied: %s — swap to a blank T5577/EM4305 and "
                 "click \"Write LF card\" (best-effort; verify the result).",
                 hex_str(a->lf_copy, 6));
            post(a, K_TOAST, 1, "LF copied to buffer");
            app_beep(a);
        } else {
            post(a, K_LFHID, 0, "LF: no card to copy");
            post(a, K_TOAST, 0, "No LF card");
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

/* ---- Records (NDEF on Mifare Classic) ---------------------------------- */

typedef struct { App *a; uint8_t ndef[NDEF_MAX_MESSAGE]; int nl; } NdefJob;

/* Write one NDEF sector image. Try the sector as-is; if the card's current access
 * bits block the found key from rewriting the trailer, factory-reset the sector to
 * default keys + transport access (cmd16, which also handles sector 0) and retry. */
static int ndef_write_sector(App *a, int s, const uint8_t img[64])
{
    int r = hf_write(a, s, img);
    if (r == TW_OK) return TW_OK;
    uint8_t fmt[64];
    memset(fmt, 0, 48);
    if (s == 0) memcpy(fmt, img, 16);            /* keep the manufacturer block */
    memset(fmt + 48, 0xFF, 6);                   /* keyA -> FF */
    memcpy(fmt + 54, ACC_DEFAULT, 4);            /* transport access */
    memset(fmt + 58, 0xFF, 6);                   /* keyB -> FF */
    if (hf_format_sector(a, s, fmt) != TW_OK) return r;   /* couldn't reset: keep verdict */
    return hf_write(a, s, img);
}

static gpointer w_ndef_write(gpointer p)
{
    NdefJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        /* add the NDEF keys up front so reads/verification can authenticate the
         * MAD and the new trailers */
        furui_keys_add(NDEF_MAD_KEY);
        furui_keys_add(NDEF_DATA_KEY);

        /* preserve the manufacturer block (sector 0 block 0 is read-only) */
        uint8_t block0[16]; memset(block0, 0, 16);
        uint8_t s0[64], key[6]; int type;
        int have_s0 = hf_read(a, 0, s0, key, &type);
        if (have_s0) memcpy(block0, s0, 16);

        uint8_t image[16][64]; memset(image, 0, sizeof image);
        int used = 0;
        if (ndef_to_mifare(j->ndef, (size_t)j->nl, block0, 16, image, &used) != 0) {
            post(a, K_RECORDS, 0, "Message too large for a 1K NDEF tag (~720 bytes max).");
            post(a, K_TOAST, 0, "NDEF too large");
        } else {
            /* If the card already carries a MAD that marks sectors 1..used as NDEF
             * (AID 03 E1), keep it — we only need to (re)write the data sectors.
             * This lets us write to an already-formatted *genuine* card, whose
             * read-only block 0 would otherwise reject any sector-0 rewrite. */
            int mad_ok = have_s0;
            for (int s = 1; s <= used && mad_ok; s++)
                if (s0[16 + 2 * s] != 0x03 || s0[16 + 2 * s + 1] != 0xE1) mad_ok = 0;

            if (mad_ok)
                post(a, K_RECORDS, 1, "Writing NDEF (%d bytes) → data sectors 1..%d (MAD already present)…",
                     j->nl, used);
            else
                post(a, K_RECORDS, 1, "Writing NDEF (%d bytes) → MAD (sector 0) + data sectors 1..%d…",
                     j->nl, used);

            int done = 0, total = used + 1;
            for (int s = 0; s <= used; s++) {
                if (s == 0 && mad_ok) {
                    post(a, K_RECORDS, 1, "  sector 0: MAD already present — kept");
                    done++;
                    continue;
                }
                int r = ndef_write_sector(a, s, image[s]);
                if (r == TW_OK) {
                    post(a, K_RECORDS, 1, "  sector %d: %s written", s, s == 0 ? "MAD" : "NDEF data");
                    done++;
                } else if (r == TW_NOKEY) {
                    post(a, K_RECORDS, 0, "  sector %d: no working key (unknown/unrecoverable) — "
                         "can't write here", s);
                } else if (s == 0) {
                    post(a, K_RECORDS, 0, "  sector 0 (MAD): write rejected — block 0 is read-only "
                         "on a genuine card. Use a magic (gen2/CUID) card, or an already "
                         "NDEF-formatted card.");
                } else {
                    post(a, K_RECORDS, 0, "  sector %d: write rejected — the trailer needs Key B "
                         "and it couldn't be recovered", s);
                }
            }
            if (done) app_beep(a);
            if (done == total)
                post(a, K_RECORDS, 1, "Wrote %d/%d sectors. Tap the card with an Android phone to read it.",
                     done, total);
            else
                post(a, K_RECORDS, 0, "Wrote %d/%d sectors. The card must be writable with a known key, "
                     "and writing the MAD (sector 0) needs a magic card unless the card is already "
                     "NDEF-formatted.", done, total);
            post(a, K_TOAST, done == total, "NDEF written (%d/%d)", done, total);
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

static gpointer w_ndef_read(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        furui_keys_add(NDEF_MAD_KEY);             /* so hf_read can authenticate them */
        furui_keys_add(NDEF_DATA_KEY);
        uint8_t image[16][64]; memset(image, 0, sizeof image);
        for (int s = 0; s < 16; s++) {
            uint8_t cur[64], key[6]; int type;
            if (hf_read(a, s, cur, key, &type)) memcpy(image[s], cur, 64);
        }
        uint8_t ndef[NDEF_MAX_MESSAGE];
        int nl = mifare_to_ndef((const uint8_t *)image, 16, ndef, sizeof ndef);
        if (nl < 0) {
            post(a, K_RECORDS, 0, "No NDEF message found — the card isn't NDEF-formatted "
                 "(or its keys are unknown).");
            post(a, K_TOAST, 0, "No NDEF found");
        } else {
            ndef_message m;
            if (ndef_decode(ndef, (size_t)nl, &m) < 0) {
                post(a, K_RECORDS, 0, "Found an NDEF TLV (%d bytes) but it didn't parse.", nl);
            } else {
                post(a, K_RECORDS, 1, "Read NDEF: %d record(s), %d bytes:", m.n, nl);
                for (int i = 0; i < m.n; i++) {
                    char d[NDEF_MAX_PAYLOAD + 128];
                    ndef_record_describe(&m.rec[i], d, sizeof d);
                    post(a, K_RECORDS, 1, "  [%d] %s", i, d);
                }
                post(a, K_TOAST, 1, "Read %d NDEF record(s)", m.n);
                app_beep(a);
            }
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

typedef struct { App *a; uint8_t block; uint8_t type; int mode; } CrackJob;

static gpointer w_crack(gpointer p)
{
    CrackJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        uint8_t found[6];
        const char *kt = j->type ? "B" : "A";
        if (j->mode == 3) {
            post(a, K_CRACK, 1, "Nested: finding a foothold key + collecting nonces "
                 "for block %d (key %s)…", j->block, kt);
            char log[256];
            int ok = furui_nested_auto(&a->dev, j->block, j->type, found, log, sizeof log);
            post(a, K_CRACK, ok, "  %s", log);
            if (ok) {
                post(a, K_CRACK, 1, "  KEY %s: %02x%02x%02x%02x%02x%02x", kt,
                     found[0],found[1],found[2],found[3],found[4],found[5]);
                app_beep(a);
            }
        } else if (j->mode == 2) {
            uint8_t fk[6];
            post(a, K_CRACK, 1, "Hardnested: finding a foothold key (dictionary on block 0)…");
            if (!furui_dict_attack(&a->dev, 0, 0, fk)) {
                post(a, K_CRACK, 0, "  no foothold key found — hardnested needs one "
                     "known/default sector key (progress prints to the terminal)");
            } else {
                post(a, K_CRACK, 1, "  foothold block 0 key A = %02x%02x%02x%02x%02x%02x; "
                     "attacking block %d (progress on terminal)…",
                     fk[0],fk[1],fk[2],fk[3],fk[4],fk[5], j->block);
                char log[256];
                int ok = furui_hardnested(&a->dev, 0, 0, fk, j->block, j->type, found, log, sizeof log);
                post(a, K_CRACK, ok, "  %s", log);
                if (ok) {
                    post(a, K_CRACK, 1, "  KEY %s: %02x%02x%02x%02x%02x%02x", kt,
                         found[0],found[1],found[2],found[3],found[4],found[5]);
                    app_beep(a);
                }
            }
        } else if (j->mode == 1) {
            char st[256];
            post(a, K_CRACK, 1, "Darkside on block %d (key %s) — collecting nonces…",
                 j->block, kt);
            int ok = furui_darkside(&a->dev, j->block, j->type, found, st, sizeof st);
            post(a, K_CRACK, ok, "  %s", st);
            if (ok) {
                post(a, K_CRACK, 1, "  KEY %s: %02x%02x%02x%02x%02x%02x", kt,
                     found[0],found[1],found[2],found[3],found[4],found[5]);
                app_beep(a);
            }
        } else {
            post(a, K_CRACK, 1, "Dictionary check on block %d (key %s)…", j->block, kt);
            int ok = furui_dict_attack(&a->dev, j->block, j->type, found);
            if (ok) {
                post(a, K_CRACK, 1, "  KEY FOUND %s: %02x%02x%02x%02x%02x%02x", kt,
                     found[0],found[1],found[2],found[3],found[4],found[5]);
                app_beep(a);
            } else {
                post(a, K_CRACK, 0, "  no dictionary key authenticates this block");
            }
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

static gboolean start_op(App *a, GThreadFunc fn, gpointer arg)
{
    if (!g_atomic_int_compare_and_exchange(&a->busy, FALSE, TRUE)) {
        toast(a, "Busy…");
        if (arg) g_free(arg);
        return FALSE;
    }
    g_thread_unref(g_thread_new("pmpro-op", fn, arg ? arg : a));
    return TRUE;
}

/* confirm-before-write: present an AdwAlertDialog; on "write" run the op. */
typedef struct { App *a; GThreadFunc fn; gpointer job; } ConfirmCtx;

static void confirm_resp(AdwAlertDialog *dlg, const char *resp, gpointer u)
{
    (void)dlg;
    ConfirmCtx *c = u;
    if (g_strcmp0(resp, "write") == 0)
        start_op(c->a, c->fn, c->job);
    else if (c->job)
        g_free(c->job);
    g_free(c);
}

static void confirm_write(App *a, const char *body, GThreadFunc fn, gpointer job)
{
    AdwDialog *dlg = adw_alert_dialog_new("Write to card?", body);
    adw_alert_dialog_add_responses(ADW_ALERT_DIALOG(dlg), "cancel", "Cancel", "write", "Write", NULL);
    adw_alert_dialog_set_response_appearance(ADW_ALERT_DIALOG(dlg), "write", ADW_RESPONSE_DESTRUCTIVE);
    adw_alert_dialog_set_default_response(ADW_ALERT_DIALOG(dlg), "cancel");
    adw_alert_dialog_set_close_response(ADW_ALERT_DIALOG(dlg), "cancel");
    ConfirmCtx *c = g_new0(ConfirmCtx, 1);
    c->a = a; c->fn = fn; c->job = job;
    g_signal_connect(dlg, "response", G_CALLBACK(confirm_resp), c);
    adw_dialog_present(dlg, GTK_WIDGET(a->win));
}

/* auto-read: a timer kicks a poll worker when idle + connected */
static gboolean poll_tick(gpointer u)
{
    App *a = u;
    if (!a->auto_read) { a->poll_id = 0; return G_SOURCE_REMOVE; }
    if (a->connected && g_atomic_int_compare_and_exchange(&a->busy, FALSE, TRUE))
        g_thread_unref(g_thread_new("pmpro-poll", w_autoread, a));
    return G_SOURCE_CONTINUE;
}

static void on_auto_toggle(GtkCheckButton *b, gpointer u)
{
    App *a = u;
    a->auto_read = gtk_check_button_get_active(b);
    if (a->auto_read && !a->poll_id)
        a->poll_id = g_timeout_add(1500, poll_tick, a);
    else if (!a->auto_read && a->poll_id) {
        g_source_remove(a->poll_id);
        a->poll_id = 0;
    }
}

/* ---- button callbacks (main thread) ------------------------------------ */

static void settings_save(App *a);   /* fwd: defined with the settings code */
static GtkWidget *scrolled(GtkWidget *child);   /* fwd: UI helper */

static void on_connect(GtkButton *b, gpointer u) { (void)b; start_op(u, w_connect, NULL); }
static void on_beep(GtkButton *b, gpointer u)    { (void)b; start_op(u, w_beep, NULL); }
static void on_openfind(GtkButton *b, gpointer u){ (void)b; start_op(u, w_openfind, NULL); }
static void on_mute(GtkCheckButton *b, gpointer u)
{
    App *a = u;
    a->mute = gtk_check_button_get_active(b);
    settings_save(a);
}

/* read the key entry into cur_key (default FFFFFFFFFFFF) before reading HF */
static void on_read_hf(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->key_entry));
    uint8_t k[6];
    if (pmpro_parse_hex(t, k, sizeof k) == 6)
        memcpy(a->cur_key, k, 6);
    else
        memset(a->cur_key, 0xFF, 6);
    start_op(a, w_read_hf, NULL);
}
static void on_read_lf(GtkButton *b, gpointer u) { (void)b; start_op(u, w_read_lf, NULL); }
static void on_read_hid(GtkButton *b, gpointer u) { (void)b; start_op(u, w_read_hid, NULL); }
static void on_identify(GtkButton *b, gpointer u) { (void)b; start_op(u, w_identify, NULL); }
static void on_magic(GtkButton *b, gpointer u)
{
    (void)b;
    confirm_write(u, "Run the magic-card test? It writes block 0 of the card "
        "(flips one byte, then restores it) to check whether the UID/block 0 is "
        "changeable (gen1a or gen2/CUID magic). A genuine card just rejects the write.",
        w_magic, NULL);
}

static void on_send_raw(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->hex_entry));
    RawJob *j = g_new0(RawJob, 1);
    j->a = a;
    int n = pmpro_parse_hex(t, j->payload, sizeof j->payload);
    if (n <= 0) { g_free(j); toast(a, "Bad hex"); return; }
    j->len = n;
    start_op(a, w_raw, j);
}

static void on_write_lf(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->lf_entry));
    uint8_t fields[16];
    int n = pmpro_parse_hex(t, fields, sizeof fields);
    if (n < 6) {
        if (a->lf_copy_have) { memcpy(fields, a->lf_copy, 6); n = 6; }   /* use Copy LF result */
        else { toast(a, "Need: freq id0 id1 id2 id3 plant (or use Copy LF)"); return; }
    }
    RawJob *j = g_new0(RawJob, 1);
    j->a = a;
    j->payload[0] = 0x2D;
    memcpy(j->payload + 1, fields, 6);
    j->len = 7;
    confirm_write(a, "Write the 125 kHz LF card?", w_write_lf, j);
}

static void on_write_hid(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->hid_entry));
    HidJob *j = g_new0(HidJob, 1); j->a = a;
    if (pmpro_parse_hex(t, j->id, 12) != 12) {
        g_free(j); toast(a, "HID needs a 12-byte card id in hex"); return;
    }
    confirm_write(a, "Write the HID prox card?", w_write_hid, j);
}

static void on_write_sector(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    WSJob *j = g_new0(WSJob, 1); j->a = a;
    j->sector = (uint8_t)gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->ws_sector));
    const char *kt = gtk_editable_get_text(GTK_EDITABLE(a->ws_key));
    if (pmpro_parse_hex(kt, j->key, 6) != 6) memset(j->key, 0xFF, 6);
    const char *dt = gtk_editable_get_text(GTK_EDITABLE(a->ws_data));
    int dl = pmpro_parse_hex(dt, j->data, sizeof j->data);
    if (dl <= 0) { g_free(j); toast(a, "Enter sector data hex"); return; }
    j->datalen = dl;
    char msg[96];
    snprintf(msg, sizeof msg, "Overwrite sector %d on the card?", j->sector);
    confirm_write(a, msg, w_write_sector, j);
}

static void on_format(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    FmtJob *j = g_new0(FmtJob, 1); j->a = a;
    j->sector = (uint8_t)gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->fmt_sector));
    const char *kt = gtk_editable_get_text(GTK_EDITABLE(a->fmt_key));
    if (pmpro_parse_hex(kt, j->key, 6) != 6) memset(j->key, 0xFF, 6);
    char msg[96];
    snprintf(msg, sizeof msg, "Format (erase) sector %d to defaults?", j->sector);
    confirm_write(a, msg, w_format, j);
}

static void on_write_buffer(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    CloneJob *j = g_new0(CloneJob, 1); j->a = a;
    const char *kt = gtk_editable_get_text(GTK_EDITABLE(a->clone_key));
    if (pmpro_parse_hex(kt, j->key, 6) != 6) memset(j->key, 0xFF, 6);
    confirm_write(a, "Write the buffer to the card? This overwrites its sectors.", w_write_buffer, j);
}

/* ---- whole-card tag operations (buttons) ------------------------------- */

static void on_copy_tag(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    toast(a, "Reading source → buffer. Then swap to a blank and use \"Write buffer → card\".");
    on_read_hf(NULL, u);
}

static void on_erase(GtkButton *b, gpointer u)
{
    (void)b;
    confirm_write(u, "Erase ALL data blocks on the card (keys kept)?", w_erase, NULL);
}

static void on_format_all(GtkButton *b, gpointer u)
{
    (void)b;
    confirm_write(u, "Factory-reset ALL sectors — default key FFFFFFFFFFFF and zeroed data?",
                  w_format_all, NULL);
}

static void on_setpw(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    CloneJob *j = g_new0(CloneJob, 1); j->a = a;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->setkey_entry));
    if (pmpro_parse_hex(t, j->key, 6) != 6) { g_free(j); toast(a, "Enter a 6-byte key (12 hex)"); return; }
    confirm_write(a, "Write this key to EVERY sector trailer? You will need it to read the card afterwards.",
                  w_setkey, j);
}

static void on_removepw(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    CloneJob *j = g_new0(CloneJob, 1); j->a = a; memset(j->key, 0xFF, 6);
    confirm_write(a, "Reset every sector key to the default FFFFFFFFFFFF?", w_setkey, j);
}

static void on_erase_lf(GtkButton *b, gpointer u)
{
    (void)b;
    confirm_write(u, "Overwrite the LF card with a blank ID?", w_erase_lf, NULL);
}

static void on_copy_lf(GtkButton *b, gpointer u) { (void)b; start_op(u, w_copy_lf, NULL); }

/* ---- Records (NDEF) callbacks (main thread) ---------------------------- */

static const char *const REC_PAGES[] =
    {"text", "uri", "social", "service", "sp", "vcard", "aar", "geo", "mime", "ext", "raw"};

static void on_rectype_changed(GObject *o, GParamSpec *ps, gpointer u)
{
    (void)ps; App *a = u;
    guint s = gtk_drop_down_get_selected(GTK_DROP_DOWN(o));
    if (s < G_N_ELEMENTS(REC_PAGES))
        gtk_stack_set_visible_child_name(GTK_STACK(a->rec_stack), REC_PAGES[s]);
}

/* append the currently-selected record type (from its fields) to rec_msg.
 * Dispatches on the visible stack page name, so it's independent of dropdown order. */
static int rec_append_current(App *a)
{
    const char *pg = gtk_stack_get_visible_child_name(GTK_STACK(a->rec_stack));
    if (!pg) return -1;
#define TXT(w) gtk_editable_get_text(GTK_EDITABLE(a->w))
    if (!strcmp(pg, "text")) return ndef_add_text(&a->rec_msg, TXT(rec_text_lang), TXT(rec_text_body));
    if (!strcmp(pg, "uri"))  return ndef_add_uri(&a->rec_msg, TXT(rec_uri));
    if (!strcmp(pg, "sp"))   return ndef_add_smartposter(&a->rec_msg, TXT(rec_sp_uri), TXT(rec_sp_title), "en");
    if (!strcmp(pg, "geo"))  return ndef_add_geo(&a->rec_msg, TXT(rec_geo));
    if (!strcmp(pg, "aar"))  return ndef_add_aar(&a->rec_msg, TXT(rec_aar));
    if (!strcmp(pg, "social")) {
        guint i = gtk_drop_down_get_selected(GTK_DROP_DOWN(a->rec_social_site));
        const char *platform = NDEF_SOCIAL[i].name;     /* table is the dropdown source */
        return ndef_add_social(&a->rec_msg, platform, TXT(rec_social_handle));
    }
    if (!strcmp(pg, "service")) {
        guint i = gtk_drop_down_get_selected(GTK_DROP_DOWN(a->rec_service_site));
        return ndef_add_service(&a->rec_msg, NDEF_SERVICE[i].name, TXT(rec_service_value));
    }
    if (!strcmp(pg, "vcard")) {
        ndef_vcard vc = {0};
        vc.name = TXT(rec_vc_name); vc.phone = TXT(rec_vc_phone);
        vc.email = TXT(rec_vc_email); vc.org = TXT(rec_vc_org); vc.url = TXT(rec_vc_url);
        return ndef_add_vcard(&a->rec_msg, &vc);
    }
    if (!strcmp(pg, "mime")) { const char *d = TXT(rec_mime_data);
        return ndef_add_mime(&a->rec_msg, TXT(rec_mime_type), (const uint8_t *)d, strlen(d)); }
    if (!strcmp(pg, "ext")) { const char *d = TXT(rec_ext_data);
        return ndef_add_external(&a->rec_msg, TXT(rec_ext_type), (const uint8_t *)d, strlen(d)); }
    if (!strcmp(pg, "raw")) {
        uint8_t type[64], pl[NDEF_MAX_PAYLOAD];
        int tl = pmpro_parse_hex(TXT(rec_raw_type), type, sizeof type);
        int pn = pmpro_parse_hex(TXT(rec_raw_payload), pl, sizeof pl);
        if (tl < 0) tl = 0;
        if (pn < 0) pn = 0;
        return ndef_add_raw(&a->rec_msg, (uint8_t)atoi(TXT(rec_raw_tnf)), type, tl, pl, pn);
    }
#undef TXT
    return -1;
}

static void on_ndef_add(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (a->rec_msg.n >= NDEF_MAX_RECORDS) { toast(a, "Message is full"); return; }
    int before = a->rec_msg.n;
    if (rec_append_current(a) != 0 || a->rec_msg.n == before) {
        toast(a, "Fill in the record fields"); return;
    }
    char d[NDEF_MAX_PAYLOAD + 128];
    ndef_record_describe(&a->rec_msg.rec[a->rec_msg.n - 1], d, sizeof d);
    post(a, K_RECORDS, 1, "Added record [%d]: %s", a->rec_msg.n - 1, d);
}

static void on_ndef_clear(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    ndef_msg_init(&a->rec_msg);
    post(a, K_RECORDS, 1, "Cleared — message is now empty.");
}

static void on_ndef_preview(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (a->rec_msg.n == 0) { toast(a, "Add a record first"); return; }
    uint8_t ndef[NDEF_MAX_MESSAGE];
    int nl = ndef_encode(&a->rec_msg, ndef, sizeof ndef);
    if (nl < 0) { toast(a, "Message too large"); return; }
    post(a, K_RECORDS, 1, "Preview: %d record(s), %d NDEF bytes", a->rec_msg.n, nl);
    for (int i = 0; i < a->rec_msg.n; i++) {
        char d[NDEF_MAX_PAYLOAD + 128];
        ndef_record_describe(&a->rec_msg.rec[i], d, sizeof d);
        post(a, K_RECORDS, 1, "  [%d] %s", i, d);
    }
    uint8_t image[16][64]; int used = 0;
    if (ndef_to_mifare(ndef, (size_t)nl, NULL, 16, image, &used) == 0)
        post(a, K_RECORDS, 1, "  → Mifare 1K: MAD (sector 0) + data sectors 1..%d", used);
    else
        post(a, K_RECORDS, 0, "  → too large for a 1K NDEF tag (~720 bytes max)");
}

static void on_ndef_write(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (a->rec_msg.n == 0) { toast(a, "Add at least one record first"); return; }
    NdefJob *j = g_new0(NdefJob, 1);
    j->a = a;
    j->nl = ndef_encode(&a->rec_msg, j->ndef, sizeof j->ndef);
    if (j->nl < 0) { g_free(j); toast(a, "Message too large"); return; }
    confirm_write(a, "Write the NDEF message to the Mifare card? This rewrites sector 0 "
                     "(the MAD) and the NDEF data sectors with the standard NDEF keys.",
                  w_ndef_write, j);
}

static void on_ndef_read(GtkButton *b, gpointer u) { (void)b; start_op(u, w_ndef_read, NULL); }

static void start_crack(App *a, int mode)
{
    CrackJob *j = g_new0(CrackJob, 1);
    j->a = a;
    j->block = (uint8_t)gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->crack_block));
    j->type = gtk_check_button_get_active(GTK_CHECK_BUTTON(a->crack_typeB)) ? 1 : 0;
    j->mode = mode;
    start_op(a, w_crack, j);
}
static void on_dict(GtkButton *b, gpointer u) { (void)b; start_crack(u, 0); }
static void on_darkside(GtkButton *b, gpointer u) { (void)b; start_crack(u, 1); }
static void on_hardnested(GtkButton *b, gpointer u) { (void)b; start_crack(u, 2); }
static void on_nested(GtkButton *b, gpointer u) { (void)b; start_crack(u, 3); }

/* ---- dump tab: file + edit + diff (main thread) ------------------------ */

/* ---- editable hex editor (Dump tab) ----------------------------------- */

/* render the buffer into the editable area (block-per-line, sector-spaced) */
static void editor_reload(App *a)
{
    GtkTextBuffer *eb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->edit_area));
    gtk_text_buffer_set_text(eb, "", -1);
    for (int i = 0; i < a->last.n_blocks; i++) {
        uint8_t d[256];
        int n = pmpro_parse_hex(a->last.blocks[i], d, sizeof d);
        if (n > 0) append_sector(eb, a->edit_area, i, d, n, 0);   /* editor: no notes */
    }
}

/* parse the editor back into the buffer: hex lines grouped by blank/header
 * lines become one sector entry each. Metadata is preserved. */
static int apply_editor(App *a)
{
    GtkTextBuffer *eb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->edit_area));
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(eb, &s, &e);
    char *txt = gtk_text_buffer_get_text(eb, &s, &e, FALSE);
    char **lines = g_strsplit(txt, "\n", -1);
    a->last.n_blocks = 0;                       /* keep uid/type/freq/meta */
    GString *grp = g_string_new(NULL);
    for (char **lp = lines; *lp; lp++) {
        const char *p = *lp;
        while (*p == ' ' || *p == '\t') p++;
        if (is_hexch(*p)) {                     /* a data line */
            if (grp->len) g_string_append_c(grp, ' ');
            g_string_append(grp, p);
        } else if (grp->len) {                  /* blank/header → flush a sector */
            uint8_t d[256];
            int n = pmpro_parse_hex(grp->str, d, sizeof d);
            if (n > 0) { char h[256]; pmpro_hex(d, n, h, sizeof h); pmpro_dump_add_block(&a->last, h); }
            g_string_truncate(grp, 0);
        }
    }
    if (grp->len) {
        uint8_t d[256];
        int n = pmpro_parse_hex(grp->str, d, sizeof d);
        if (n > 0) { char h[256]; pmpro_hex(d, n, h, sizeof h); pmpro_dump_add_block(&a->last, h); }
    }
    g_string_free(grp, TRUE);
    g_strfreev(lines);
    g_free(txt);
    a->have_last = a->last.n_blocks > 0;
    return a->last.n_blocks;
}

static void on_editor_apply(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    int n = apply_editor(a);
    post(a, K_DUMP, n > 0, "Applied editor → buffer (%d sector(s))", n);
    post(a, K_TOAST, n > 0, n > 0 ? "Buffer updated from editor" : "Editor is empty");
}

static void on_editor_reload(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (!a->have_last) { toast(a, "Buffer empty — read or load a card first"); return; }
    editor_reload(a);
    post(a, K_TOAST, 1, "Editor reloaded from buffer");
}

static void on_save_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    if (a->have_last && pmpro_dump_save_auto(&a->last, path, err, sizeof err))
        post(a, K_DUMP, 1, "Saved → %s", path);
    else
        toast(a, a->have_last ? "Save error" : "Buffer empty — nothing to save");
    g_free(path);
    g_object_unref(f);
}

static void on_save(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    apply_editor(a);                 /* what you see in the editor is what you save */
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_initial_name(d, "card.pmdump");
    gtk_file_dialog_save(d, a->win, NULL, on_save_finish, a);
}

static void on_export_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    if (a->have_last && pmpro_dump_save_mfd(&a->last, path, err, sizeof err))
        post(a, K_DUMP, 1, "Exported raw .mfd → %s", path);
    else
        toast(a, a->have_last ? "Export failed" : "Buffer empty — nothing to export");
    g_free(path);
    g_object_unref(f);
}

static void on_export(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    apply_editor(a);
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_initial_name(d, "card.mfd");
    gtk_file_dialog_save(d, a->win, NULL, on_export_finish, a);
}

static void on_save_keys_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    int n = pmpro_dump_save_keys(&a->last, path, err, sizeof err);
    if (n >= 0) post(a, K_DUMP, 1, "Saved %d key(s) → %s", n, path);
    else        toast(a, err);
    g_free(path);
    g_object_unref(f);
}

static void on_save_keys(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    apply_editor(a);
    if (!a->have_last) { toast(a, "Buffer empty — load a dump first"); return; }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_initial_name(d, "card.keys");
    gtk_file_dialog_save(d, a->win, NULL, on_save_keys_finish, a);
}

static void on_load_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    if (pmpro_dump_load(&a->last, path, err, sizeof err)) {
        a->have_last = TRUE;
        editor_reload(a);
        post(a, K_DUMP, 1, "Loaded %s — %s / %s, UID %s, %d sector(s)%s%s",
             path, a->last.card_type, a->last.frequency, a->last.uid,
             a->last.n_blocks, a->last.meta[0] ? " — " : "", a->last.meta);
        post(a, K_TOAST, 1, "Dump loaded into editor");
    } else {
        post(a, K_DUMP, 0, "Load failed: %s", err);
        toast(a, err);
    }
    g_free(path);
    g_object_unref(f);
}

static void on_load(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (g_atomic_int_get(&a->busy)) { toast(a, "Busy…"); return; }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_open(d, a->win, NULL, on_load_finish, a);
}

static void on_keys_from_dump(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    apply_editor(a);
    if (!a->have_last || a->last.n_blocks == 0) { toast(a, "Buffer empty — load a dump first"); return; }
    static const uint8_t zero[6] = {0};
    int added = 0;
    for (int i = 0; i < a->last.n_blocks; i++) {
        uint8_t d[256];
        int n = pmpro_parse_hex(a->last.blocks[i], d, sizeof d);
        if (n < 16) continue;
        int tr = ((n / 16) - 1) * 16;     /* trailer = last block of the sector */
        if (memcmp(d + tr, zero, 6))      { furui_keys_add(d + tr); added++; }       /* key A */
        if (memcmp(d + tr + 10, zero, 6)) { furui_keys_add(d + tr + 10); added++; }  /* key B */
    }
    post(a, K_DUMP, 1, "Added %d key(s) from the buffer to the dictionary (%d total). "
         "Read HF will now try them.", added, furui_keys_count());
    post(a, K_TOAST, 1, "Added %d keys to dictionary", added);
}

/* ---- Diff Tool window (byte-level, MCT-style) -------------------------- */

typedef struct {
    pmpro_dump A, B;          /* A = editor buffer, B = the file */
    GtkWidget *view; GtkTextBuffer *buf;
    GtkWidget *hide, *pct;
} DiffCtx;

/* one "A:"/"B:" block line; differing bytes (vs `other`) tagged red */
static void diff_line(GtkTextBuffer *buf, const char *label,
                      const uint8_t *d, int has, const uint8_t *other, int other_has)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    int base = gtk_text_iter_get_offset(&end);
    gtk_text_buffer_insert(buf, &end, label, -1);
    if (!has) { gtk_text_buffer_insert(buf, &end, "(missing)\n", -1); return; }
    char hex[64];
    pmpro_hex(d, 16, hex, sizeof hex);
    int hb = base + (int)strlen(label);
    gtk_text_buffer_insert(buf, &end, hex, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);
    for (int i = 0; i < 16; i++) {
        if (!other_has || d[i] != other[i]) {
            GtkTextIter s, e;
            gtk_text_buffer_get_iter_at_offset(buf, &s, hb + i * 3);
            gtk_text_buffer_get_iter_at_offset(buf, &e, hb + i * 3 + 2);
            gtk_text_buffer_apply_tag_by_name(buf, "d", &s, &e);
        }
    }
}

static void diff_render(DiffCtx *c, gboolean hide_identical)
{
    gtk_text_buffer_set_text(c->buf, "", -1);
    long total = 0, diff = 0;
    int nsec = c->A.n_blocks > c->B.n_blocks ? c->A.n_blocks : c->B.n_blocks;
    for (int i = 0; i < nsec; i++) {
        uint8_t ad[256], bd[256];
        int an = i < c->A.n_blocks ? pmpro_parse_hex(c->A.blocks[i], ad, sizeof ad) : 0;
        int bn = i < c->B.n_blocks ? pmpro_parse_hex(c->B.blocks[i], bd, sizeof bd) : 0;
        int nb = (an > bn ? an : bn) / 16;
        int sdiff = an != bn;
        for (int k = 0; k < nb * 16; k++) {
            int av = k < an, bv = k < bn;
            total++;
            if (av != bv || (av && bv && ad[k] != bd[k])) { diff++; sdiff = 1; }
        }
        if (hide_identical && !sdiff) continue;
        GtkTextIter end;
        char hdr[32]; snprintf(hdr, sizeof hdr, "Sector: %d\n", i);
        gtk_text_buffer_get_end_iter(c->buf, &end);
        gtk_text_buffer_insert(c->buf, &end, hdr, -1);
        for (int b = 0; b < nb; b++) {
            const uint8_t *ab = (b * 16 < an) ? ad + b * 16 : NULL;
            const uint8_t *bb = (b * 16 < bn) ? bd + b * 16 : NULL;
            diff_line(c->buf, "  A: ", ab, ab != NULL, bb, bb != NULL);
            diff_line(c->buf, "  B: ", bb, bb != NULL, ab, ab != NULL);
        }
        gtk_text_buffer_get_end_iter(c->buf, &end);
        gtk_text_buffer_insert(c->buf, &end, "\n", -1);
    }
    char lbl[64];
    snprintf(lbl, sizeof lbl, "Difference: %.2f%%", total ? 100.0 * diff / total : 0.0);
    gtk_label_set_text(GTK_LABEL(c->pct), lbl);
}

static void on_diff_hide(GtkCheckButton *b, gpointer u)
{
    diff_render((DiffCtx *)u, gtk_check_button_get_active(b));
}

static void on_diff_destroy(GtkWidget *w, gpointer u) { (void)w; g_free(u); }

static void open_diff_window(App *a, const pmpro_dump *B, const char *path)
{
    DiffCtx *c = g_new0(DiffCtx, 1);
    c->A = a->last;       /* struct copy */
    c->B = *B;

    GtkWidget *win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(win), "Diff Tool");
    gtk_window_set_transient_for(GTK_WINDOW(win), a->win);
    gtk_window_set_default_size(GTK_WINDOW(win), 900, 720);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 12); gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12); gtk_widget_set_margin_bottom(box, 12);

    char hdr[600];
    snprintf(hdr, sizeof hdr, "A = editor buffer (UID %s)\nB = %s", a->last.uid, path);
    GtkWidget *hl = gtk_label_new(hdr);
    gtk_label_set_xalign(GTK_LABEL(hl), 0);
    gtk_label_set_wrap(GTK_LABEL(hl), TRUE);
    gtk_box_append(GTK_BOX(box), hl);

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    c->pct = gtk_label_new("Difference: …");
    gtk_widget_add_css_class(c->pct, "heading");
    gtk_box_append(GTK_BOX(row), c->pct);
    c->hide = gtk_check_button_new_with_label("Hide identical sectors");
    g_signal_connect(c->hide, "toggled", G_CALLBACK(on_diff_hide), c);
    gtk_box_append(GTK_BOX(row), c->hide);
    gtk_box_append(GTK_BOX(box), row);

    c->view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(c->view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(c->view), TRUE);
    gtk_widget_set_margin_start(c->view, 8); gtk_widget_set_margin_end(c->view, 8);
    gtk_widget_set_margin_top(c->view, 8); gtk_widget_set_margin_bottom(c->view, 8);
    c->buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(c->view));
    gtk_text_buffer_create_tag(c->buf, "d", "foreground", "#e01b24",
                               "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_box_append(GTK_BOX(box), scrolled(c->view));

    gtk_window_set_child(GTK_WINDOW(win), box);
    g_signal_connect(win, "destroy", G_CALLBACK(on_diff_destroy), c);
    diff_render(c, FALSE);
    gtk_window_present(GTK_WINDOW(win));
}

static void on_diff_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    pmpro_dump *other = g_new0(pmpro_dump, 1);
    char err[128];
    if (pmpro_dump_load(other, path, err, sizeof err))
        open_diff_window(a, other, path);
    else
        toast(a, err);
    g_free(other);
    g_free(path);
    g_object_unref(f);
}

static void on_diff(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    apply_editor(a);
    if (!a->have_last) { toast(a, "Buffer empty — read or load a card first"); return; }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_open(d, a->win, NULL, on_diff_finish, a);
}

/* ---- key map: per-sector A/B grid from the buffer trailers ------------- */

static void keymap_label(GtkWidget *grid, int col, int row, const char *markup)
{
    GtkWidget *l = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(l), markup);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_label_set_selectable(GTK_LABEL(l), TRUE);
    gtk_grid_attach(GTK_GRID(grid), l, col, row, 1, 1);
}

static void on_keymap(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (!a->have_last || a->last.n_blocks == 0) { toast(a, "Buffer empty — read or load a card first"); return; }

    GtkWidget *win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(win), "Key map");
    gtk_window_set_transient_for(GTK_WINDOW(win), a->win);
    gtk_window_set_default_size(GTK_WINDOW(win), 460, 620);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 20);
    gtk_widget_set_margin_start(grid, 14); gtk_widget_set_margin_end(grid, 14);
    gtk_widget_set_margin_top(grid, 14); gtk_widget_set_margin_bottom(grid, 14);

    keymap_label(grid, 0, 0, "<b>Sector</b>");
    keymap_label(grid, 1, 0, "<b>Key A</b>");
    keymap_label(grid, 2, 0, "<b>Key B</b>");

    static const unsigned char zero[6] = {0};
    for (int i = 0; i < a->last.n_blocks; i++) {
        uint8_t d[256];
        int n = pmpro_parse_hex(a->last.blocks[i], d, sizeof d);
        if (n < 16) continue;
        int tr = ((n / 16) - 1) * 16;
        char ka[96], kb[96], sec[16];
        snprintf(sec, sizeof sec, "%d", i);
        if (memcmp(d + tr, zero, 6))
            snprintf(ka, sizeof ka, "<span foreground='#2ec27e' font_family='monospace'>"
                     "%02x%02x%02x%02x%02x%02x</span>", d[tr],d[tr+1],d[tr+2],d[tr+3],d[tr+4],d[tr+5]);
        else snprintf(ka, sizeof ka, "<span foreground='#9a9a9a'>—</span>");
        if (memcmp(d + tr + 10, zero, 6))
            snprintf(kb, sizeof kb, "<span foreground='#3584e4' font_family='monospace'>"
                     "%02x%02x%02x%02x%02x%02x</span>", d[tr+10],d[tr+11],d[tr+12],d[tr+13],d[tr+14],d[tr+15]);
        else snprintf(kb, sizeof kb, "<span foreground='#9a9a9a'>—</span>");
        keymap_label(grid, 0, i + 1, sec);
        keymap_label(grid, 1, i + 1, ka);
        keymap_label(grid, 2, i + 1, kb);
    }

    gtk_window_set_child(GTK_WINDOW(win), scrolled(grid));
    gtk_window_present(GTK_WINDOW(win));
}

/* ---- crack tab: load keys + autopwn ------------------------------------ */

static void on_load_keys_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    int n = furui_keys_load(path, err, sizeof err);
    if (n >= 0) {
        if (!a->key_files)
            a->key_files = g_ptr_array_new_with_free_func(g_free);
        g_ptr_array_add(a->key_files, g_strdup(path));
        settings_save(a);
        post(a, K_CRACK, 1, "Loaded %d key(s) from %s — %d in dictionary now",
             n, path, furui_keys_count());
        post(a, K_TOAST, 1, "Loaded %d keys (%d total)", n, furui_keys_count());
    } else {
        toast(a, err);
    }
    g_free(path);
    g_object_unref(f);
}

static void on_load_keys(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (g_atomic_int_get(&a->busy)) { toast(a, "Busy…"); return; }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_open(d, a->win, NULL, on_load_keys_finish, a);
}

static void gui_prog(const char *msg, void *u) { post((App *)u, K_CRACK, 1, "  %s", msg); }

static gpointer w_autopwn(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_ready(a)) {
        post(a, K_CRACK, 1, "Autopwn → %s : dictionary + nested across every "
             "sector, then dumping the whole card…", a->mfd_path);
        char log[256];
        int ok = furui_autopwn(&a->dev, a->mfd_path, gui_prog, a, log, sizeof log);
        post(a, K_CRACK, ok, "%s", log);
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); return NULL;
}

static void on_autopwn_save_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    g_strlcpy(a->mfd_path, path, sizeof a->mfd_path);
    g_free(path);
    g_object_unref(f);
    start_op(a, w_autopwn, NULL);
}

static void on_autopwn(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    if (g_atomic_int_get(&a->busy)) { toast(a, "Busy…"); return; }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_initial_name(d, "card.mfd");
    gtk_file_dialog_save(d, a->win, NULL, on_autopwn_save_finish, a);
}

/* ---- persistent settings (~/.config/pmpro/settings.ini) ---------------- */

static char *settings_path(void)
{
    return g_build_filename(g_get_user_config_dir(), "pmpro", "settings.ini", NULL);
}

static void settings_save(App *a)
{
    if (a->loading)
        return;
    GKeyFile *kf = g_key_file_new();
    g_key_file_set_boolean(kf, "ui", "mute", a->mute);
    if (a->key_entry) {
        const char *k = gtk_editable_get_text(GTK_EDITABLE(a->key_entry));
        g_key_file_set_string(kf, "ui", "key", k ? k : "");
    }
    if (a->win) {
        int w = 0, h = 0;
        gtk_window_get_default_size(a->win, &w, &h);
        if (w > 0 && h > 0) {
            g_key_file_set_integer(kf, "ui", "width", w);
            g_key_file_set_integer(kf, "ui", "height", h);
        }
    }
    if (a->key_files && a->key_files->len) {
        GString *s = g_string_new(NULL);
        for (guint i = 0; i < a->key_files->len; i++) {
            if (i) g_string_append_c(s, ';');
            g_string_append(s, g_ptr_array_index(a->key_files, i));
        }
        g_key_file_set_string(kf, "keys", "files", s->str);
        g_string_free(s, TRUE);
    }
    char *path = settings_path();
    char *dir = g_path_get_dirname(path);
    g_mkdir_with_parents(dir, 0700);
    g_key_file_save_to_file(kf, path, NULL);
    g_free(dir);
    g_free(path);
    g_key_file_free(kf);
}

static void settings_load(App *a)
{
    char *path = settings_path();
    GKeyFile *kf = g_key_file_new();
    a->loading = TRUE;
    if (g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, NULL)) {
        if (g_key_file_has_key(kf, "ui", "mute", NULL)) {
            a->mute = g_key_file_get_boolean(kf, "ui", "mute", NULL);
            if (a->mute_check)
                gtk_check_button_set_active(GTK_CHECK_BUTTON(a->mute_check), a->mute);
        }
        char *k = g_key_file_get_string(kf, "ui", "key", NULL);
        if (k) {
            if (a->key_entry && *k) gtk_editable_set_text(GTK_EDITABLE(a->key_entry), k);
            g_free(k);
        }
        int w = g_key_file_get_integer(kf, "ui", "width", NULL);
        int h = g_key_file_get_integer(kf, "ui", "height", NULL);
        if (w > 0 && h > 0 && a->win) {
            if (w < 1000) w = 1000;   /* never restore narrower than the switcher needs */
            gtk_window_set_default_size(a->win, w, h);
        }
        char *files = g_key_file_get_string(kf, "keys", "files", NULL);
        if (files) {
            char **parts = g_strsplit(files, ";", -1);
            int total = 0;
            for (char **p = parts; *p; p++) {
                if (**p == '\0') continue;
                char err[128];
                int n = furui_keys_load(*p, err, sizeof err);
                if (n >= 0) {
                    total += n;
                    if (!a->key_files)
                        a->key_files = g_ptr_array_new_with_free_func(g_free);
                    g_ptr_array_add(a->key_files, g_strdup(*p));
                }
            }
            g_strfreev(parts);
            g_free(files);
            if (total)
                post(a, K_CRACK, 1, "Restored %d key(s) from saved .keys files "
                     "(%d in dictionary)", total, furui_keys_count());
        }
    }
    a->loading = FALSE;
    g_key_file_free(kf);
    g_free(path);
}

/* ---- UI construction helpers ------------------------------------------- */

static GtkWidget *mono_view(GtkTextBuffer **buf, const char *intro)
{
    GtkWidget *v = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(v), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(v), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(v), GTK_WRAP_WORD_CHAR);
    gtk_widget_set_margin_start(v, 8); gtk_widget_set_margin_end(v, 8);
    gtk_widget_set_margin_top(v, 8); gtk_widget_set_margin_bottom(v, 8);
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(v));
    if (buf) *buf = b;
    if (intro) gtk_text_buffer_set_text(b, intro, -1);
    return v;
}

static GtkWidget *scrolled(GtkWidget *child)
{
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), child);
    gtk_widget_set_vexpand(s, TRUE); gtk_widget_set_hexpand(s, TRUE);
    return s;
}

/* a tab page is a vertical box (controls) over a scrolled log view */
static GtkWidget *page_box(void)
{
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(b, 12); gtk_widget_set_margin_end(b, 12);
    gtk_widget_set_margin_top(b, 12); gtk_widget_set_margin_bottom(b, 12);
    return b;
}

static GtkWidget *hrow(void) { return gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8); }

static GtkWidget *section_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_add_css_class(l, "heading");
    gtk_widget_set_margin_top(l, 6);
    return l;
}

static GtkWidget *hint_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_widget_add_css_class(l, "dim-label");
    return l;
}

static GtkWidget *btn(const char *label, const char *css, GCallback cb, gpointer u)
{
    GtkWidget *b = gtk_button_new_with_label(label);
    if (css) gtk_widget_add_css_class(b, css);
    g_signal_connect(b, "clicked", cb, u);
    return b;
}

static GtkWidget *entry_exp(const char *placeholder)
{
    GtkWidget *e = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(e), placeholder);
    gtk_widget_set_hexpand(e, TRUE);
    return e;
}

/* a "<label>  [entry........]" row; creates the entry and returns it via *out */
static GtkWidget *field_row(const char *label, const char *placeholder, GtkWidget **out)
{
    GtkWidget *row = hrow();
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_set_size_request(l, 80, -1);
    gtk_box_append(GTK_BOX(row), l);
    GtkWidget *e = entry_exp(placeholder);
    gtk_box_append(GTK_BOX(row), e);
    *out = e;
    return row;
}

/* a "<label>  [dropdown]" row whose items are an ndef template table's names */
static GtkWidget *table_dropdown_row(const char *label, const ndef_social_site *table,
                                     GtkWidget **out)
{
    GtkWidget *row = hrow();
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_set_size_request(l, 80, -1);
    gtk_box_append(GTK_BOX(row), l);
    int n = 0;
    while (table[n].name) n++;
    const char **names = g_new0(const char *, n + 1);
    for (int i = 0; i < n; i++) names[i] = table[i].name;
    GtkWidget *d = gtk_drop_down_new_from_strings(names);
    g_free(names);
    gtk_widget_set_hexpand(d, TRUE);
    gtk_box_append(GTK_BOX(row), d);
    *out = d;
    return row;
}

/* ---- pages ------------------------------------------------------------- */

static GtkWidget *page_device(App *a)
{
    GtkWidget *box = page_box();
    GtkWidget *row = hrow();
    gtk_box_append(GTK_BOX(row), btn("Connect", "suggested-action", G_CALLBACK(on_connect), a));
    GtkWidget *ident = btn("Identify tag", NULL, G_CALLBACK(on_identify), a);
    gtk_widget_set_tooltip_text(ident, "Detect whatever tag is on the reader and name its "
        "type — tries HF 13.56 MHz, then 125 kHz LF, then HID prox (requires Connect)");
    gtk_box_append(GTK_BOX(row), ident);
    gtk_box_append(GTK_BOX(row), btn("Beep", NULL, G_CALLBACK(on_beep), a));
    GtkWidget *find = btn("Find / scan", NULL, G_CALLBACK(on_openfind), a);
    gtk_widget_set_tooltip_text(find, "Turn on the device's card-scan indicator (cmd 0F)");
    gtk_box_append(GTK_BOX(row), find);
    GtkWidget *mute = gtk_check_button_new_with_label("Mute beeps");
    a->mute_check = mute;
    gtk_widget_set_tooltip_text(mute, "Suppress confirmation beeps (the Beep button still works)");
    g_signal_connect(mute, "toggled", G_CALLBACK(on_mute), a);
    gtk_box_append(GTK_BOX(row), mute);
    gtk_box_append(GTK_BOX(box), row);

    a->info_label = gtk_label_new("Not connected. Click Connect to identify the "
                                  "FR-RATEL and run the RC4 handshake.");
    gtk_label_set_xalign(GTK_LABEL(a->info_label), 0);
    gtk_label_set_wrap(GTK_LABEL(a->info_label), TRUE);
    gtk_widget_add_css_class(a->info_label, "dim-label");
    gtk_box_append(GTK_BOX(box), a->info_label);

    gtk_box_append(GTK_BOX(box), hint_label(
        "Quick start:\n"
        "• HF (Mifare): read a 13.56 MHz card, write/format sectors, clone to a blank.\n"
        "• LF / HID: read & write 125 kHz EM4100/T5577 and HID prox cards.\n"
        "• Crack: recover Mifare keys (dictionary / nested / darkside / hardnested) and autopwn.\n"
        "• Dump: load/save/export (.pmdump or raw .mfd), edit a block, diff two dumps.\n"
        "• Records: write/read NDEF records (Text, URL, contact, app, …) on a Classic card.\n"
        "• Console: send raw protocol payloads.\n\n"
        "Use only on cards you own or are authorized to test."));
    return box;
}

static GtkWidget *page_hf(App *a)
{
    GtkWidget *box = page_box();

    /* read */
    gtk_box_append(GTK_BOX(box), section_label("Read Mifare card"));
    GtkWidget *r0 = hrow();
    gtk_box_append(GTK_BOX(r0), gtk_label_new("Key A"));
    a->key_entry = entry_exp("FF FF FF FF FF FF (default)");
    gtk_box_append(GTK_BOX(r0), a->key_entry);
    gtk_box_append(GTK_BOX(r0), btn("Read HF", "suggested-action", G_CALLBACK(on_read_hf), a));
    GtkWidget *autochk = gtk_check_button_new_with_label("Auto-read");
    gtk_widget_set_tooltip_text(autochk, "Poll the reader and read automatically "
        "when a (new) card is placed (requires Connect)");
    g_signal_connect(autochk, "toggled", G_CALLBACK(on_auto_toggle), a);
    gtk_box_append(GTK_BOX(r0), autochk);
    gtk_box_append(GTK_BOX(box), r0);

    /* write sector */
    gtk_box_append(GTK_BOX(box), section_label("Write sector"));
    GtkWidget *r1 = hrow();
    gtk_box_append(GTK_BOX(r1), gtk_label_new("Sector"));
    a->ws_sector = gtk_spin_button_new_with_range(0, 39, 1);
    gtk_box_append(GTK_BOX(r1), a->ws_sector);
    a->ws_key = entry_exp("key A: FF FF FF FF FF FF");
    gtk_box_append(GTK_BOX(r1), a->ws_key);
    gtk_box_append(GTK_BOX(box), r1);
    GtkWidget *r2 = hrow();
    a->ws_data = entry_exp("sector data hex (up to 64 bytes = 4 blocks)");
    gtk_box_append(GTK_BOX(r2), a->ws_data);
    gtk_box_append(GTK_BOX(r2), btn("Write sector", "destructive-action", G_CALLBACK(on_write_sector), a));
    gtk_box_append(GTK_BOX(box), r2);

    /* format sector */
    gtk_box_append(GTK_BOX(box), section_label("Format sector"));
    GtkWidget *r3 = hrow();
    gtk_box_append(GTK_BOX(r3), gtk_label_new("Sector"));
    a->fmt_sector = gtk_spin_button_new_with_range(0, 39, 1);
    gtk_box_append(GTK_BOX(r3), a->fmt_sector);
    a->fmt_key = entry_exp("key A: FF FF FF FF FF FF");
    gtk_box_append(GTK_BOX(r3), a->fmt_key);
    gtk_box_append(GTK_BOX(r3), btn("Format", "destructive-action", G_CALLBACK(on_format), a));
    gtk_box_append(GTK_BOX(box), r3);

    /* clone */
    gtk_box_append(GTK_BOX(box), section_label("Clone buffer → blank card"));
    gtk_box_append(GTK_BOX(box), hint_label(
        "Read a source card above (or load a dump on the Dump tab), then swap to a "
        "UID-changeable/magic blank, set its key A, and write the buffer."));
    GtkWidget *r4 = hrow();
    a->clone_key = entry_exp("blank key A: FF FF FF FF FF FF");
    gtk_box_append(GTK_BOX(r4), a->clone_key);
    gtk_box_append(GTK_BOX(r4), btn("Write buffer → card", "destructive-action", G_CALLBACK(on_write_buffer), a));
    gtk_box_append(GTK_BOX(box), r4);

    /* ---- whole-card tag operations ---- */
    gtk_box_append(GTK_BOX(box), section_label("Tag operations (whole card)"));
    GtkWidget *t0 = hrow();
    gtk_box_append(GTK_BOX(t0), btn("Copy tag", "suggested-action", G_CALLBACK(on_copy_tag), a));
    gtk_box_append(GTK_BOX(t0), btn("Erase tag", "destructive-action", G_CALLBACK(on_erase), a));
    gtk_box_append(GTK_BOX(t0), btn("Format memory", "destructive-action", G_CALLBACK(on_format_all), a));
    GtkWidget *magicbtn = btn("Magic test", NULL, G_CALLBACK(on_magic), a);
    gtk_widget_set_tooltip_text(magicbtn, "Check whether the card is a UID-changeable magic "
        "card (gen1a or gen2/CUID). Writes block 0 and restores it; a genuine card rejects the write.");
    gtk_box_append(GTK_BOX(t0), magicbtn);
    gtk_box_append(GTK_BOX(box), t0);
    GtkWidget *t1 = hrow();
    gtk_box_append(GTK_BOX(t1), gtk_label_new("New key"));
    a->setkey_entry = entry_exp("new key A/B for all sectors, e.g. A0A1A2A3A4A5");
    gtk_box_append(GTK_BOX(t1), a->setkey_entry);
    gtk_box_append(GTK_BOX(t1), btn("Set password", "destructive-action", G_CALLBACK(on_setpw), a));
    gtk_box_append(GTK_BOX(t1), btn("Remove password", "destructive-action", G_CALLBACK(on_removepw), a));
    gtk_box_append(GTK_BOX(box), t1);
    gtk_box_append(GTK_BOX(box), hint_label(
        "These act on every sector using the box key or the dictionary. \"Set/Remove "
        "password\" writes the sector keys (Mifare's password). Lock is intentionally "
        "omitted for now — it is irreversible."));

    GtkWidget *hfv = mono_view(&a->hf_buf,
        "Place a Mifare card on the reader and click Read HF.\n");
    a->hf_view = hfv;
    buf_add_tags(a->hf_buf);
    gtk_box_append(GTK_BOX(box), scrolled(hfv));
    return box;
}

static GtkWidget *page_lfhid(App *a)
{
    GtkWidget *box = page_box();

    gtk_box_append(GTK_BOX(box), section_label("LF 125 kHz (EM4100 / T5577 / EM4305)"));
    GtkWidget *r0 = hrow();
    gtk_box_append(GTK_BOX(r0), btn("Read LF", "suggested-action", G_CALLBACK(on_read_lf), a));
    gtk_box_append(GTK_BOX(r0), btn("Copy LF", "suggested-action", G_CALLBACK(on_copy_lf), a));
    gtk_box_append(GTK_BOX(r0), btn("Erase LF", "destructive-action", G_CALLBACK(on_erase_lf), a));
    gtk_box_append(GTK_BOX(box), r0);
    gtk_box_append(GTK_BOX(box), hint_label(
        "Copy LF reads the ID for write-back to a blank. T5577 password/lock aren't "
        "exposed by the device's LF protocol, so they're not offered here."));
    gtk_box_append(GTK_BOX(box), hint_label("Write: 6 hex bytes — freq id0 id1 id2 id3 plant"));
    GtkWidget *r1 = hrow();
    a->lf_entry = entry_exp("00 12 34 56 78 00");
    gtk_box_append(GTK_BOX(r1), a->lf_entry);
    gtk_box_append(GTK_BOX(r1), btn("Write LF card", "destructive-action", G_CALLBACK(on_write_lf), a));
    gtk_box_append(GTK_BOX(box), r1);

    gtk_box_append(GTK_BOX(box), section_label("HID Prox"));
    GtkWidget *r2 = hrow();
    gtk_box_append(GTK_BOX(r2), btn("Read HID", "suggested-action", G_CALLBACK(on_read_hid), a));
    gtk_box_append(GTK_BOX(box), r2);
    gtk_box_append(GTK_BOX(box), hint_label("Write: a 12-byte HID card id in hex"));
    GtkWidget *r3 = hrow();
    a->hid_entry = entry_exp("12-byte card id, e.g. 00 00 ...");
    gtk_box_append(GTK_BOX(r3), a->hid_entry);
    gtk_box_append(GTK_BOX(r3), btn("Write HID card", "destructive-action", G_CALLBACK(on_write_hid), a));
    gtk_box_append(GTK_BOX(box), r3);

    GtkWidget *lv = mono_view(&a->lfhid_buf, "Read/write 125 kHz and HID prox cards here.\n");
    a->lfhid_view = lv;
    gtk_box_append(GTK_BOX(box), scrolled(lv));
    return box;
}

static GtkWidget *page_crack(App *a)
{
    GtkWidget *box = page_box();
    GtkWidget *row = hrow();
    gtk_box_append(GTK_BOX(row), gtk_label_new("Block"));
    a->crack_block = gtk_spin_button_new_with_range(0, 255, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(a->crack_block), 4);
    gtk_box_append(GTK_BOX(row), a->crack_block);
    a->crack_typeB = gtk_check_button_new_with_label("Key B");
    gtk_box_append(GTK_BOX(row), a->crack_typeB);
    gtk_box_append(GTK_BOX(row), btn("Dictionary", "suggested-action", G_CALLBACK(on_dict), a));
    gtk_box_append(GTK_BOX(row), btn("Nested", "suggested-action", G_CALLBACK(on_nested), a));
    gtk_box_append(GTK_BOX(row), btn("Darkside", NULL, G_CALLBACK(on_darkside), a));
    gtk_box_append(GTK_BOX(row), btn("Hardnested", NULL, G_CALLBACK(on_hardnested), a));
    gtk_box_append(GTK_BOX(box), row);

    GtkWidget *arow = hrow();
    gtk_box_append(GTK_BOX(arow), gtk_label_new("Whole card:"));
    GtkWidget *autop = btn("Autopwn → .mfd", "suggested-action", G_CALLBACK(on_autopwn), a);
    gtk_widget_set_tooltip_text(autop, "Recover every sector key (dictionary + nested) "
        "and dump the whole card to a .mfd file");
    gtk_box_append(GTK_BOX(arow), autop);
    GtkWidget *lkeys = btn("Load keys…", NULL, G_CALLBACK(on_load_keys), a);
    gtk_widget_set_tooltip_text(lkeys, "Import a MifareClassicTool .keys file; the keys "
        "extend the dictionary used by Dictionary/Nested/Autopwn (remembered across launches)");
    gtk_box_append(GTK_BOX(arow), lkeys);
    GtkWidget *kmap = btn("Key map", NULL, G_CALLBACK(on_keymap), a);
    gtk_widget_set_tooltip_text(kmap, "Show a per-sector Key A / Key B table from the "
        "current buffer (read or load a card first)");
    gtk_box_append(GTK_BOX(arow), kmap);
    gtk_box_append(GTK_BOX(box), arow);

    GtkWidget *cv = mono_view(&a->crack_buf,
        "Mifare key recovery:\n"
        "• Dictionary — try common/default keys against the block (cmd 13).\n"
        "• Nested — auto-find a foothold key, recover the target (Crypto-1, ~10–30 s).\n"
        "• Darkside — collect nonces (cmd 15), solve + confirm (vulnerable cards only).\n"
        "• Hardnested — foothold + hardnested solver (progress prints to the terminal).\n"
        "• Autopwn → .mfd — recover every sector key and dump the whole card.\n"
        "• Load keys… — add a .keys dictionary file.\n\n");
    a->crack_view = cv;
    gtk_box_append(GTK_BOX(box), scrolled(cv));
    return box;
}

static GtkWidget *page_dump(App *a)
{
    GtkWidget *box = page_box();

    gtk_box_append(GTK_BOX(box), section_label("Dump file"));
    GtkWidget *r0 = hrow();
    gtk_box_append(GTK_BOX(r0), btn("Load…", "suggested-action", G_CALLBACK(on_load), a));
    gtk_box_append(GTK_BOX(r0), btn("Save .pmdump…", NULL, G_CALLBACK(on_save), a));
    gtk_box_append(GTK_BOX(r0), btn("Export .mfd…", NULL, G_CALLBACK(on_export), a));
    gtk_box_append(GTK_BOX(box), r0);

    GtkWidget *rk = hrow();
    gtk_box_append(GTK_BOX(rk), gtk_label_new("Keys:"));
    GtkWidget *lk = btn("Import .keys…", NULL, G_CALLBACK(on_load_keys), a);
    gtk_widget_set_tooltip_text(lk, "Load a MifareClassicTool .keys file into the "
        "dictionary (also on the Crack tab; remembered across launches)");
    gtk_box_append(GTK_BOX(rk), lk);
    GtkWidget *sk = btn("Save .keys…", NULL, G_CALLBACK(on_save_keys), a);
    gtk_widget_set_tooltip_text(sk, "Write this dump's Key A/Key B values to a "
        ".keys file (MifareClassicTool format)");
    gtk_box_append(GTK_BOX(rk), sk);
    GtkWidget *k2d = btn("Keys → dict", NULL, G_CALLBACK(on_keys_from_dump), a);
    gtk_widget_set_tooltip_text(k2d, "Add this dump's trailer keys to the dictionary "
        "so Read HF (and the Crack tab) can use them");
    gtk_box_append(GTK_BOX(rk), k2d);
    gtk_box_append(GTK_BOX(box), rk);

    gtk_box_append(GTK_BOX(box), section_label("Hex editor"));
    gtk_box_append(GTK_BOX(box), hint_label(
        "Click anywhere and type to edit bytes directly — one block (16 bytes) per "
        "line, a blank line between sectors. \"Apply edits\" writes the editor back "
        "to the buffer (Save / Export / Diff / key actions apply it automatically)."));
    GtkWidget *r1 = hrow();
    gtk_box_append(GTK_BOX(r1), btn("Apply edits", "suggested-action", G_CALLBACK(on_editor_apply), a));
    gtk_box_append(GTK_BOX(r1), btn("Reload from buffer", NULL, G_CALLBACK(on_editor_reload), a));
    gtk_box_append(GTK_BOX(r1), btn("Diff vs file…", NULL, G_CALLBACK(on_diff), a));
    gtk_box_append(GTK_BOX(box), r1);

    a->edit_area = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->edit_area), TRUE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(a->edit_area), TRUE);
    gtk_widget_set_margin_start(a->edit_area, 8); gtk_widget_set_margin_end(a->edit_area, 8);
    gtk_widget_set_margin_top(a->edit_area, 8); gtk_widget_set_margin_bottom(a->edit_area, 8);
    GtkTextBuffer *eb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->edit_area));
    buf_add_tags(eb);
    gtk_text_buffer_set_text(eb,
        "Load a dump, or read a card then \"Reload from buffer\", to edit here.\n", -1);
    gtk_box_append(GTK_BOX(box), scrolled(a->edit_area));

    /* small read-only log for messages + diff output */
    GtkWidget *dv = mono_view(&a->dump_buf, NULL);
    a->dump_view = dv;
    buf_add_tags(a->dump_buf);
    GtkWidget *logsc = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(logsc), dv);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(logsc), 110);
    gtk_widget_set_hexpand(logsc, TRUE);
    gtk_box_append(GTK_BOX(box), logsc);
    return box;
}

static GtkWidget *page_console(App *a)
{
    GtkWidget *box = page_box();
    GtkWidget *cv = mono_view(&a->console_buf,
        "Raw protocol console. Enter a command PAYLOAD in hex (the app adds framing, "
        "CRC16 and RC4). Response is shown decrypted.\n"
        "Examples:  06 (identify)   09 01 02 (beep)   21 (read HF)\n\n");
    a->console_view = cv;
    gtk_box_append(GTK_BOX(box), scrolled(cv));

    GtkWidget *row = hrow();
    a->hex_entry = entry_exp("payload hex, e.g. 21");
    g_signal_connect(a->hex_entry, "activate", G_CALLBACK(on_send_raw), a);
    gtk_box_append(GTK_BOX(row), a->hex_entry);
    gtk_box_append(GTK_BOX(row), btn("Send", "suggested-action", G_CALLBACK(on_send_raw), a));
    gtk_box_append(GTK_BOX(box), row);
    return box;
}

static GtkWidget *rec_group(void)
{
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    return b;
}

static GtkWidget *page_records(App *a)
{
    GtkWidget *box = page_box();
    ndef_msg_init(&a->rec_msg);

    gtk_box_append(GTK_BOX(box), section_label("Build an NDEF record"));

    /* type selector */
    GtkWidget *tr = hrow();
    gtk_box_append(GTK_BOX(tr), gtk_label_new("Type"));
    const char *types[] = {
        "Text", "URL / URI", "Social media", "Review / app link",
        "Smart Poster (URL + title)", "Contact (vCard)", "Android App (AAR)",
        "Geo location", "MIME (custom)", "External (custom)", "Raw record", NULL
    };
    a->rec_type = gtk_drop_down_new_from_strings(types);
    gtk_widget_set_hexpand(a->rec_type, TRUE);
    gtk_box_append(GTK_BOX(tr), a->rec_type);
    gtk_box_append(GTK_BOX(box), tr);

    /* per-type field groups, switched by the dropdown */
    a->rec_stack = gtk_stack_new();
    GtkWidget *g;

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("Language", "en", &a->rec_text_lang));
    gtk_box_append(GTK_BOX(g), field_row("Text", "Hello from NFC", &a->rec_text_body));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "text");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("URI", "https://example.com  ·  tel:+1…  ·  mailto:a@b.com", &a->rec_uri));
    gtk_box_append(GTK_BOX(g), hint_label("Any URI works — web links, phone, mail, social, "
        "video or file URLs. Common schemes are abbreviated to one byte automatically."));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "uri");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), table_dropdown_row("Platform", NDEF_SOCIAL, &a->rec_social_site));
    gtk_box_append(GTK_BOX(g), field_row("Handle", "username (or phone for WhatsApp)", &a->rec_social_handle));
    gtk_box_append(GTK_BOX(g), hint_label("Builds the profile URL for the chosen platform "
        "(a leading @ is trimmed). Paste a full https:// link to use it verbatim."));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "social");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), table_dropdown_row("Service", NDEF_SERVICE, &a->rec_service_site));
    gtk_box_append(GTK_BOX(g), field_row("ID / URL", "Place ID, package, username — or a full https:// link", &a->rec_service_value));
    gtk_box_append(GTK_BOX(g), hint_label("For Google Review: paste your Place ID, or the full "
        "review link from your Google Business Profile (g.page/r/…/review). The business-specific "
        "ID/link must come from you — the app can't look it up."));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "service");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("URL", "https://example.com", &a->rec_sp_uri));
    gtk_box_append(GTK_BOX(g), field_row("Title", "A label shown with the link", &a->rec_sp_title));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "sp");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("Name", "Ada Lovelace", &a->rec_vc_name));
    gtk_box_append(GTK_BOX(g), field_row("Phone", "+1 555 1234", &a->rec_vc_phone));
    gtk_box_append(GTK_BOX(g), field_row("Email", "ada@example.io", &a->rec_vc_email));
    gtk_box_append(GTK_BOX(g), field_row("Org", "Analytical Engines", &a->rec_vc_org));
    gtk_box_append(GTK_BOX(g), field_row("URL", "https://example.io", &a->rec_vc_url));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "vcard");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("Package", "com.example.app", &a->rec_aar));
    gtk_box_append(GTK_BOX(g), hint_label("Android Application Record — a phone opens this app, "
        "or the Play Store page if it isn't installed."));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "aar");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("Lat,Lon", "59.9139,10.7522", &a->rec_geo));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "geo");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("MIME type", "application/json", &a->rec_mime_type));
    gtk_box_append(GTK_BOX(g), field_row("Data", "{\"k\":1}", &a->rec_mime_data));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "mime");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("Type", "example.com:myrec", &a->rec_ext_type));
    gtk_box_append(GTK_BOX(g), field_row("Data", "payload text", &a->rec_ext_data));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "ext");

    g = rec_group();
    gtk_box_append(GTK_BOX(g), field_row("TNF", "1  (0=empty 1=well-known 2=MIME 4=external)", &a->rec_raw_tnf));
    gtk_box_append(GTK_BOX(g), field_row("Type hex", "55", &a->rec_raw_type));
    gtk_box_append(GTK_BOX(g), field_row("Payload hex", "04 65 78 …", &a->rec_raw_payload));
    gtk_stack_add_named(GTK_STACK(a->rec_stack), g, "raw");

    gtk_box_append(GTK_BOX(box), a->rec_stack);
    g_signal_connect(a->rec_type, "notify::selected", G_CALLBACK(on_rectype_changed), a);

    /* compose / preview */
    GtkWidget *cr = hrow();
    gtk_box_append(GTK_BOX(cr), btn("Add record", "suggested-action", G_CALLBACK(on_ndef_add), a));
    gtk_box_append(GTK_BOX(cr), btn("Preview", NULL, G_CALLBACK(on_ndef_preview), a));
    gtk_box_append(GTK_BOX(cr), btn("Clear", NULL, G_CALLBACK(on_ndef_clear), a));
    gtk_box_append(GTK_BOX(box), cr);

    /* card I/O */
    gtk_box_append(GTK_BOX(box), section_label("Card"));
    GtkWidget *io = hrow();
    gtk_box_append(GTK_BOX(io), btn("Read records", "suggested-action", G_CALLBACK(on_ndef_read), a));
    gtk_box_append(GTK_BOX(io), btn("Write to card", "destructive-action", G_CALLBACK(on_ndef_write), a));
    gtk_box_append(GTK_BOX(box), io);
    gtk_box_append(GTK_BOX(box), hint_label(
        "Records are written onto a Mifare Classic card (MAD + NDEF mapping) — the only "
        "NDEF storage this device can write. Android phones read NDEF-on-Classic; iPhones "
        "do not. Use a magic (gen2/CUID) card: the MAD lives in sector 0, and on a genuine "
        "card block 0 is read-only so the MAD can't be written (the data sectors still get "
        "written, but a phone won't find them without the MAD). Unknown keys are recovered "
        "automatically (dictionary → nested)."));

    GtkWidget *rv = mono_view(&a->rec_buf,
        "Build a record (pick a type, fill the fields, Add record), then Write to card.\n"
        "Read records parses an NDEF-formatted card back into a list.\n\n");
    a->rec_view = rv;
    gtk_box_append(GTK_BOX(box), scrolled(rv));
    return box;
}

static void load_css(void)
{
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p,
        ".pill{padding:2px 12px;border-radius:12px;font-weight:bold;}"
        ".pill.ok{background:alpha(@success_color,.2);color:@success_color;}"
        ".pill.bad{background:alpha(@error_color,.2);color:@error_color;}");
    gtk_style_context_add_provider_for_display(gdk_display_get_default(),
        GTK_STYLE_PROVIDER(p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

static gboolean on_close_request(GtkWindow *w, gpointer u)
{
    (void)w;
    settings_save((App *)u);
    return FALSE;
}

static void activate(GtkApplication *gapp, gpointer user)
{
    App *a = user;
    load_css();

    /* Make the embedded app icon available to the icon theme (the GResource is
     * auto-registered at load), so the window/taskbar icon shows even when run
     * from the build tree — not only after a system install. */
    gtk_icon_theme_add_resource_path(
        gtk_icon_theme_get_for_display(gdk_display_get_default()),
        "/com/furui/pmpro/icons");
    gtk_window_set_default_icon_name(APP_ID);

    GtkWidget *win = adw_application_window_new(gapp);
    a->win = GTK_WINDOW(win);
    gtk_window_set_icon_name(GTK_WINDOW(win), APP_ID);
    gtk_window_set_title(GTK_WINDOW(win), "NFC PM-Pro");
    gtk_window_set_default_size(GTK_WINDOW(win), 1320, 700);
    /* keep the window wide enough that the 7-tab view switcher shows full labels */
    gtk_widget_set_size_request(win, 1100, 560);

    GtkWidget *toolbar = adw_toolbar_view_new();
    GtkWidget *header = adw_header_bar_new();
    a->status_pill = gtk_label_new("Not connected");
    gtk_widget_add_css_class(a->status_pill, "pill");
    gtk_widget_add_css_class(a->status_pill, "bad");
    adw_header_bar_pack_start(ADW_HEADER_BAR(header), a->status_pill);

    GtkWidget *stack = adw_view_stack_new();
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_device(a),
        "device", "Device", "preferences-system-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_hf(a),
        "hf", "HF · Mifare", "view-reveal-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_lfhid(a),
        "lfhid", "LF · HID", "network-wireless-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_crack(a),
        "crack", "Crack", "dialog-password-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_dump(a),
        "dump", "Dump", "document-save-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_records(a),
        "records", "Records", "emblem-documents-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_console(a),
        "console", "Console", "utilities-terminal-symbolic");

    GtkWidget *sw = adw_view_switcher_new();
    adw_view_switcher_set_stack(ADW_VIEW_SWITCHER(sw), ADW_VIEW_STACK(stack));
    adw_view_switcher_set_policy(ADW_VIEW_SWITCHER(sw), ADW_VIEW_SWITCHER_POLICY_WIDE);
    adw_header_bar_set_title_widget(ADW_HEADER_BAR(header), sw);
    adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);

    a->toasts = ADW_TOAST_OVERLAY(adw_toast_overlay_new());
    adw_toast_overlay_set_child(a->toasts, stack);
    adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), GTK_WIDGET(a->toasts));
    adw_application_window_set_content(ADW_APPLICATION_WINDOW(win), toolbar);

    settings_load(a);
    g_signal_connect(win, "close-request", G_CALLBACK(on_close_request), a);
    gtk_window_present(GTK_WINDOW(win));
}

int main(int argc, char **argv)
{
    App a;
    memset(&a, 0, sizeof a);
    a.dev.fd = -1;
    g_mutex_init(&a.lock);
    a.app = adw_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(a.app, "activate", G_CALLBACK(activate), &a);
    int status = g_application_run(G_APPLICATION(a.app), argc, argv);
    pmpro_close(&a.dev);
    g_object_unref(a.app);
    return status;
}
