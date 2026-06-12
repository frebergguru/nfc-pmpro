/* app.c — FURUI NFC PM-Pro companion (GTK4 + libadwaita).
 *
 * Speaks the reverse-engineered FURUI "talk" protocol (RC4 + CRC16 + framing,
 * see PROTOCOL.md / furui.c / session.c) over raw hidraw. Device operations run
 * on a background thread and post results back to the UI via g_idle_add.
 */
#include <adwaita.h>
#include <gtk/gtk.h>
#include <string.h>
#include <stdarg.h>

#include "hidraw.h"
#include "furui.h"
#include "session.h"
#include "crack.h"
#include "hardnested_glue.h"
#include "nested.h"
#include "protocol.h"
#include "dump.h"

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
    GtkTextBuffer *read_buf;
    GtkWidget *read_view;
    GtkWidget *key_entry;
    GtkTextBuffer *console_buf;
    GtkWidget *console_view;
    GtkWidget *hex_entry;
    GtkWidget *wr_entry;
    GtkWidget *ws_sector;   /* write-sector: sector number */
    GtkWidget *ws_key;      /* write-sector: key A */
    GtkWidget *ws_data;     /* write-sector: data hex */
    GtkWidget *clone_key;   /* clone: destination key A */
    AdwToastOverlay *toasts;

    pmpro_dump last;       /* last successful read, for Save */
    gboolean have_last;
    uint8_t cur_key[6];    /* key to use for the next sector read (main->worker) */
    GtkWidget *crack_block;
    GtkWidget *crack_typeB;
    GtkTextBuffer *crack_buf;
    GtkWidget *crack_view;
    char mfd_path[512];
} App;

/* ---- UI marshalling (worker thread -> main loop) ----------------------- */

enum { K_STATUS, K_TOAST, K_CONSOLE, K_READ, K_INFO, K_CRACK };

typedef struct { App *a; int kind; int ok; char text[1024]; } UiMsg;

static void append_view(GtkTextBuffer *buf, GtkWidget *view, const char *t)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, t, -1);
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
    case K_STATUS: set_status(a, m->ok, m->text); break;
    case K_TOAST:  adw_toast_overlay_add_toast(a->toasts, adw_toast_new(m->text)); break;
    case K_INFO:   gtk_label_set_text(GTK_LABEL(a->info_label), m->text); break;
    case K_CONSOLE: append_view(a->console_buf, a->console_view, m->text);
                    append_view(a->console_buf, a->console_view, "\n"); break;
    case K_READ:   append_view(a->read_buf, a->read_view, m->text);
                   append_view(a->read_buf, a->read_view, "\n"); break;
    case K_CRACK:  append_view(a->crack_buf, a->crack_view, m->text);
                   append_view(a->crack_buf, a->crack_view, "\n"); break;
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

/* ---- device helpers (run on worker thread, hold a->lock) --------------- */

static gboolean ensure_open(App *a)
{
    if (a->opened)
        return TRUE;
    if (pmpro_open(&a->dev, NULL)) {
        a->opened = TRUE;
        return TRUE;
    }
    post(a, K_STATUS, 0, "No device");
    post(a, K_TOAST, 0, "%s", a->dev.err);
    return FALSE;
}

/* Rotating buffers so several hex_str() results can be live in one expression
 * (e.g. two %s args) without clobbering each other. Worker-thread only. */
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
    if (ensure_open(a)) {
        a->connected = furui_connect(&a->dev);
        if (a->connected) {
            post(a, K_STATUS, 1, "Connected — %s", a->dev.path);
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
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        int ok = furui_beep(&a->dev, 0x01, 0x02);
        post(a, K_TOAST, ok, ok ? "Beep" : "Beep failed");
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    return NULL;
}

static gpointer w_read_hf(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        furui_hf_card c;
        if (furui_read_hf(&a->dev, &c)) {
            uid_info ui; pmpro_decode_uid(c.uid, c.uid_len, &ui);
            char tail[32];
            pmpro_hex(c.tail, c.tail_len, tail, sizeof tail);
            post(a, K_READ, 1, "HF (13.56MHz)  UID: %s (%d-byte)   [ATQA/SAK: %s]",
                 ui.uid, ui.uid_len, tail);
            pmpro_dump_init(&a->last);
            snprintf(a->last.card_type, sizeof a->last.card_type, "ISO14443A");
            snprintf(a->last.frequency, sizeof a->last.frequency, "13.56MHz");
            snprintf(a->last.uid, sizeof a->last.uid, "%s", ui.uid);
            a->have_last = TRUE;
            /* sector sweep with the chosen key (default FF) */
            char kh[20]; pmpro_hex(a->cur_key, 6, kh, sizeof kh);
            int open_sectors = 0;
            for (int s = 0; s < 16; s++) {
                furui_activate(&a->dev);
                uint8_t blk[64];
                size_t bl = furui_read_sector(&a->dev, (uint8_t)s, 1, a->cur_key, NULL,
                                              blk, sizeof blk);
                if (bl >= 64) {        /* auth succeeded -> real 64-byte sector */
                    open_sectors++;
                    char h[200]; pmpro_hex(blk, 64, h, sizeof h);
                    post(a, K_READ, 1, "  sector %2d (key %s): %s", s, kh, h);
                    pmpro_dump_add_block(&a->last, h);
                }
            }
            if (!open_sectors)
                post(a, K_READ, 0, "  no sectors readable with key %s "
                     "(card uses other keys — try a known key, or it's hardened)", kh);
            else
                post(a, K_READ, 1, "  %d/16 sectors read into buffer (use Write/Clone "
                     "to write them to a blank)", open_sectors);
            post(a, K_TOAST, 1, "HF card read");
            app_beep(a);
        } else {
            post(a, K_READ, 0, "HF: no card on reader");
            post(a, K_TOAST, 0, "No HF card");
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
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        uint8_t cmd[3] = {0x28, 0x01, 0x00}, resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, cmd, 3, resp, sizeof resp, 3000);
        if (r >= 3 && resp[2] == 1) {
            size_t dlen = (r > 5) ? r - 5 : 0;
            post(a, K_READ, 1, "LF (125kHz)  data: %s", hex_str(resp + 3, dlen));
            pmpro_dump_init(&a->last);
            snprintf(a->last.card_type, sizeof a->last.card_type, "EM4100/ID");
            snprintf(a->last.frequency, sizeof a->last.frequency, "125kHz");
            snprintf(a->last.uid, sizeof a->last.uid, "%.120s", hex_str(resp + 3, dlen));
            a->have_last = TRUE;
            em4100_info em;
            if (pmpro_decode_em4100(resp + 3, dlen, &em)) {
                post(a, K_READ, 1, "  EM4100: id %s  customer %u  card %u  (fob %s)",
                     em.hex, em.customer, em.card_number, em.fob_text);
                snprintf(a->last.meta, sizeof a->last.meta,
                         "EM4100 id %s customer %u card %u fob %s",
                         em.hex, em.customer, em.card_number, em.fob_text);
            }
            post(a, K_TOAST, 1, "LF card read");
            app_beep(a);
        } else {
            post(a, K_READ, 0, "LF: no 125kHz card on reader");
            post(a, K_TOAST, 0, "No LF card");
        }
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
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
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
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        uint8_t resp[FURUI_MAXMSG];
        size_t r = furui_exec(&a->dev, j->payload, j->len, resp, sizeof resp, 3000);
        int ok = r >= 3 && resp[2] == 1;
        post(a, K_READ, ok, ok ? "LF write OK (%s)" : "LF write FAILED (%s)",
             hex_str(j->payload, j->len));
        post(a, K_TOAST, ok, ok ? "Wrote LF card" : "LF write failed");
        if (ok) furui_beep(&a->dev, 0x01, 0x02);
    }
    g_atomic_int_set(&a->busy, FALSE);
    g_mutex_unlock(&a->lock);
    g_free(j);
    return NULL;
}

typedef struct { App *a; uint8_t sector; uint8_t key[6]; uint8_t data[64]; int datalen; } WSJob;

static gpointer w_write_sector(gpointer p)
{
    WSJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        furui_activate(&a->dev);
        int ok = furui_write_sector(&a->dev, j->sector, 1, j->key, NULL, j->data, j->datalen);
        post(a, K_READ, ok, ok ? "Wrote sector %d (%d bytes)" : "Write sector %d FAILED",
             j->sector, j->datalen);
        post(a, K_TOAST, ok, ok ? "Sector written" : "Write failed");
        if (ok) app_beep(a);
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

typedef struct { App *a; uint8_t key[6]; } CloneJob;

static gpointer w_write_buffer(gpointer p)
{
    CloneJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        if (!a->have_last || a->last.n_blocks == 0) {
            post(a, K_TOAST, 0, "Buffer empty — read a source card first (Read tab)");
        } else {
            int wrote = 0;
            for (int s = 0; s < a->last.n_blocks; s++) {
                uint8_t data[64];
                int dl = pmpro_parse_hex(a->last.blocks[s], data, sizeof data);
                if (dl <= 0) continue;
                /* a read-back trailer has keyA masked to 00 — restore the dst
                 * key so the cloned sector stays accessible. */
                if (dl >= 64) memcpy(data + 48, j->key, 6);
                furui_activate(&a->dev);
                if (furui_write_sector(&a->dev, (uint8_t)s, 1, j->key, NULL, data, dl)) {
                    wrote++;
                    post(a, K_READ, 1, "  wrote sector %d (%d bytes)", s, dl);
                } else {
                    post(a, K_READ, 0, "  sector %d write FAILED", s);
                }
            }
            post(a, K_TOAST, wrote > 0, "Wrote %d/%d buffered sectors", wrote, a->last.n_blocks);
            if (wrote) app_beep(a);
        }
    }
    g_atomic_int_set(&a->busy, FALSE); g_mutex_unlock(&a->lock); g_free(j); return NULL;
}

typedef struct { App *a; uint8_t block; uint8_t type; int mode; } CrackJob; /* mode 0=dict,1=darkside,2=hardnested */

static gpointer w_crack(gpointer p)
{
    CrackJob *j = p; App *a = j->a;
    g_mutex_lock(&a->lock);
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
        uint8_t found[6];
        const char *kt = j->type ? "B" : "A";
        if (j->mode == 3) {
            /* nested (cmd 14): auto-find a foothold key, then crack the target */
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
            /* hardnested with auto-foothold: dictionary on sector 0 first */
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
    /* atomic test-and-set: refuse a second op while one is running */
    if (!g_atomic_int_compare_and_exchange(&a->busy, FALSE, TRUE)) {
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Busy…"));
        if (arg) g_free(arg);
        return FALSE;
    }
    g_thread_unref(g_thread_new("pmpro-op", fn, arg ? arg : a));
    return TRUE;
}

/* ---- button callbacks -------------------------------------------------- */

static void on_connect(GtkButton *b, gpointer u) { (void)b; start_op(u, w_connect, NULL); }
static void on_beep(GtkButton *b, gpointer u)    { (void)b; start_op(u, w_beep, NULL); }
static void settings_save(App *a);   /* fwd: defined with the settings code */
static void on_mute(GtkCheckButton *b, gpointer u)
{
    App *a = u;
    a->mute = gtk_check_button_get_active(b);
    settings_save(a);
}
static void on_read_hf(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    /* capture the key on the main thread (default to FFFFFFFFFFFF) */
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->key_entry));
    uint8_t k[6];
    if (pmpro_parse_hex(t, k, sizeof k) == 6)
        memcpy(a->cur_key, k, 6);
    else
        memset(a->cur_key, 0xFF, 6);
    start_op(a, w_read_hf, NULL);
}
static void on_read_lf(GtkButton *b, gpointer u) { (void)b; start_op(u, w_read_lf, NULL); }

static void on_send_raw(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->hex_entry));
    RawJob *j = g_new0(RawJob, 1);
    j->a = a;
    int n = pmpro_parse_hex(t, j->payload, sizeof j->payload);
    if (n <= 0) { g_free(j); adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Bad hex")); return; }
    j->len = n;
    start_op(a, w_raw, j);
}

static void on_write_lf(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    /* entry holds "freq,id0,id1,id2,id3,plant" hex; build cmd 2D payload */
    const char *t = gtk_editable_get_text(GTK_EDITABLE(a->wr_entry));
    uint8_t fields[16];
    int n = pmpro_parse_hex(t, fields, sizeof fields);
    if (n < 6) { adw_toast_overlay_add_toast(a->toasts,
                 adw_toast_new("Need: freq id0 id1 id2 id3 plant")); return; }
    RawJob *j = g_new0(RawJob, 1);
    j->a = a;
    j->payload[0] = 0x2D;
    memcpy(j->payload + 1, fields, 6);
    j->len = 7;
    start_op(a, w_write_lf, j);
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
    if (dl <= 0) { g_free(j); adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Enter data hex")); return; }
    j->datalen = dl;
    start_op(a, w_write_sector, j);
}

static void on_write_buffer(GtkButton *b, gpointer u)
{
    (void)b; App *a = u;
    CloneJob *j = g_new0(CloneJob, 1); j->a = a;
    const char *kt = gtk_editable_get_text(GTK_EDITABLE(a->clone_key));
    if (pmpro_parse_hex(kt, j->key, 6) != 6) memset(j->key, 0xFF, 6);
    start_op(a, w_write_buffer, j);
}

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

static void on_save_finish(GObject *src, GAsyncResult *res, gpointer u)
{
    App *a = u;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    char *path = g_file_get_path(f);
    char err[128];
    if (a->have_last && pmpro_dump_save(&a->last, path, err, sizeof err))
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Saved dump"));
    else
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Nothing to save / error"));
    g_free(path);
    g_object_unref(f);
}

static void on_save(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_initial_name(d, "card.pmdump");
    gtk_file_dialog_save(d, a->win, NULL, on_save_finish, a);
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
        post(a, K_READ, 1, "Loaded dump: %s — %s/%s, UID %s, %d block(s)%s%s",
             path, a->last.card_type, a->last.frequency, a->last.uid,
             a->last.n_blocks, a->last.meta[0] ? " — " : "", a->last.meta);
        post(a, K_TOAST, 1, "Dump loaded into buffer");
    } else {
        post(a, K_TOAST, 0, "%s", err);
    }
    g_free(path);
    g_object_unref(f);
}

static void on_load(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    if (g_atomic_int_get(&a->busy)) {
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Busy…"));
        return;
    }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_open(d, a->win, NULL, on_load_finish, a);
}

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
        settings_save(a);     /* remember the file so it reloads next launch */
        post(a, K_CRACK, 1, "Loaded %d key(s) from %s — %d in dictionary now",
             n, path, furui_keys_count());
        post(a, K_TOAST, 1, "Loaded %d keys (%d total)", n, furui_keys_count());
    } else {
        post(a, K_TOAST, 0, "%s", err);
    }
    g_free(path);
    g_object_unref(f);
}

static void on_load_keys(GtkButton *b, gpointer u)
{
    (void)b;
    App *a = u;
    if (g_atomic_int_get(&a->busy)) {
        adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Busy…"));
        return;
    }
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_open(d, a->win, NULL, on_load_keys_finish, a);
}

/* ---- autopwn → .mfd ---------------------------------------------------- */

/* progress hook, called on the worker thread from inside furui_autopwn */
static void gui_prog(const char *msg, void *u)
{
    post((App *)u, K_CRACK, 1, "  %s", msg);
}

static gpointer w_autopwn(gpointer p)
{
    App *a = p;
    g_mutex_lock(&a->lock);
    if (ensure_open(a)) {
        if (!a->connected) a->connected = furui_connect(&a->dev);
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
    (void)b;
    App *a = u;
    if (g_atomic_int_get(&a->busy)) { adw_toast_overlay_add_toast(a->toasts, adw_toast_new("Busy…")); return; }
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
        if (w > 0 && h > 0 && a->win)
            gtk_window_set_default_size(a->win, w, h);
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

/* ---- UI construction --------------------------------------------------- */

static GtkWidget *mono_view(GtkTextBuffer **buf)
{
    GtkWidget *v = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(v), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(v), TRUE);
    gtk_widget_set_margin_start(v, 8); gtk_widget_set_margin_end(v, 8);
    gtk_widget_set_margin_top(v, 8); gtk_widget_set_margin_bottom(v, 8);
    if (buf) *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(v));
    return v;
}

static GtkWidget *scrolled(GtkWidget *child)
{
    GtkWidget *s = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(s), child);
    gtk_widget_set_vexpand(s, TRUE); gtk_widget_set_hexpand(s, TRUE);
    return s;
}

static GtkWidget *pad_box(int spacing)
{
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, spacing);
    gtk_widget_set_margin_start(b, 12); gtk_widget_set_margin_end(b, 12);
    gtk_widget_set_margin_top(b, 12); gtk_widget_set_margin_bottom(b, 12);
    return b;
}

static GtkWidget *page_device(App *a)
{
    GtkWidget *box = pad_box(10);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *conn = gtk_button_new_with_label("Connect");
    gtk_widget_add_css_class(conn, "suggested-action");
    g_signal_connect(conn, "clicked", G_CALLBACK(on_connect), a);
    GtkWidget *beep = gtk_button_new_with_label("Beep");
    g_signal_connect(beep, "clicked", G_CALLBACK(on_beep), a);
    GtkWidget *mute = gtk_check_button_new_with_label("Mute beeps");
    a->mute_check = mute;
    gtk_widget_set_tooltip_text(mute, "Suppress the confirmation beep after "
                                "connect/read/write/crack (the Beep button still works)");
    g_signal_connect(mute, "toggled", G_CALLBACK(on_mute), a);
    gtk_box_append(GTK_BOX(row), conn);
    gtk_box_append(GTK_BOX(row), beep);
    gtk_box_append(GTK_BOX(row), mute);
    gtk_box_append(GTK_BOX(box), row);

    a->info_label = gtk_label_new("Not connected. Click Connect to identify the "
                                  "FR-RATEL and run the RC4 handshake.");
    gtk_label_set_xalign(GTK_LABEL(a->info_label), 0);
    gtk_label_set_wrap(GTK_LABEL(a->info_label), TRUE);
    gtk_widget_add_css_class(a->info_label, "dim-label");
    gtk_box_append(GTK_BOX(box), a->info_label);
    return box;
}

static GtkWidget *page_read(App *a)
{
    GtkWidget *box = pad_box(8);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *hf = gtk_button_new_with_label("Read HF (13.56 MHz)");
    gtk_widget_add_css_class(hf, "suggested-action");
    g_signal_connect(hf, "clicked", G_CALLBACK(on_read_hf), a);
    GtkWidget *lf = gtk_button_new_with_label("Read LF (125 kHz)");
    g_signal_connect(lf, "clicked", G_CALLBACK(on_read_lf), a);
    GtkWidget *save = gtk_button_new_with_label("Save dump…");
    g_signal_connect(save, "clicked", G_CALLBACK(on_save), a);
    GtkWidget *load = gtk_button_new_with_label("Load dump…");
    gtk_widget_set_tooltip_text(load, "Load a .pmdump into the buffer, then write "
                                "it to a blank from the Write / Clone tab");
    g_signal_connect(load, "clicked", G_CALLBACK(on_load), a);
    gtk_box_append(GTK_BOX(row), hf);
    gtk_box_append(GTK_BOX(row), lf);
    gtk_box_append(GTK_BOX(row), save);
    gtk_box_append(GTK_BOX(row), load);
    gtk_box_append(GTK_BOX(box), row);

    GtkWidget *krow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *klab = gtk_label_new("Mifare key A:");
    a->key_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->key_entry),
                                   "FF FF FF FF FF FF (default)");
    gtk_widget_set_hexpand(a->key_entry, TRUE);
    gtk_box_append(GTK_BOX(krow), klab);
    gtk_box_append(GTK_BOX(krow), a->key_entry);
    gtk_box_append(GTK_BOX(box), krow);

    GtkWidget *v = mono_view(&a->read_buf);
    a->read_view = v;
    gtk_text_buffer_set_text(a->read_buf,
        "Place a card on the reader and click Read.\n", -1);
    gtk_box_append(GTK_BOX(box), scrolled(v));
    return box;
}

static GtkWidget *section_label(const char *text)
{
    GtkWidget *l = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_add_css_class(l, "heading");
    gtk_widget_set_margin_top(l, 6);
    return l;
}

static GtkWidget *page_write(App *a)
{
    GtkWidget *box = pad_box(8);

    /* ---- HF: write one Mifare sector ---- */
    gtk_box_append(GTK_BOX(box), section_label("Write Mifare sector (13.56 MHz)"));
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(r1), gtk_label_new("Sector"));
    a->ws_sector = gtk_spin_button_new_with_range(0, 39, 1);
    a->ws_key = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->ws_key), "key A: FF FF FF FF FF FF");
    gtk_widget_set_hexpand(a->ws_key, TRUE);
    gtk_box_append(GTK_BOX(r1), a->ws_sector);
    gtk_box_append(GTK_BOX(r1), a->ws_key);
    gtk_box_append(GTK_BOX(box), r1);
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->ws_data = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->ws_data),
                                   "sector data hex (up to 64 bytes = 4 blocks)");
    gtk_widget_set_hexpand(a->ws_data, TRUE);
    GtkWidget *wsbtn = gtk_button_new_with_label("Write sector");
    gtk_widget_add_css_class(wsbtn, "destructive-action");
    g_signal_connect(wsbtn, "clicked", G_CALLBACK(on_write_sector), a);
    gtk_box_append(GTK_BOX(r2), a->ws_data);
    gtk_box_append(GTK_BOX(r2), wsbtn);
    gtk_box_append(GTK_BOX(box), r2);

    /* ---- Clone: write the read buffer to a blank ---- */
    gtk_box_append(GTK_BOX(box), section_label("Clone to a blank card"));
    GtkWidget *chint = gtk_label_new(
        "1. On the Read tab, read the SOURCE card (with its key) — sectors go to a buffer.\n"
        "2. Swap to a UID-changeable/magic blank, set its key A below, and write the buffer.");
    gtk_label_set_xalign(GTK_LABEL(chint), 0);
    gtk_label_set_wrap(GTK_LABEL(chint), TRUE);
    gtk_widget_add_css_class(chint, "dim-label");
    gtk_box_append(GTK_BOX(box), chint);
    GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->clone_key = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->clone_key), "blank key A: FF FF FF FF FF FF");
    gtk_widget_set_hexpand(a->clone_key, TRUE);
    GtkWidget *clbtn = gtk_button_new_with_label("Write buffer → card");
    gtk_widget_add_css_class(clbtn, "destructive-action");
    g_signal_connect(clbtn, "clicked", G_CALLBACK(on_write_buffer), a);
    gtk_box_append(GTK_BOX(r3), a->clone_key);
    gtk_box_append(GTK_BOX(r3), clbtn);
    gtk_box_append(GTK_BOX(box), r3);

    /* ---- LF: write a 125 kHz ID card ---- */
    gtk_box_append(GTK_BOX(box), section_label("Write 125 kHz ID card (T5577/EM4305)"));
    GtkWidget *lhint = gtk_label_new("6 hex bytes: freq id0 id1 id2 id3 plant");
    gtk_label_set_xalign(GTK_LABEL(lhint), 0);
    gtk_widget_add_css_class(lhint, "dim-label");
    gtk_box_append(GTK_BOX(box), lhint);
    GtkWidget *r4 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->wr_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->wr_entry), "00 12 34 56 78 00");
    gtk_widget_set_hexpand(a->wr_entry, TRUE);
    GtkWidget *w = gtk_button_new_with_label("Write LF card");
    gtk_widget_add_css_class(w, "destructive-action");
    g_signal_connect(w, "clicked", G_CALLBACK(on_write_lf), a);
    gtk_box_append(GTK_BOX(r4), a->wr_entry);
    gtk_box_append(GTK_BOX(r4), w);
    gtk_box_append(GTK_BOX(box), r4);
    return box;
}

static GtkWidget *page_console(App *a)
{
    GtkWidget *box = pad_box(8);
    GtkWidget *v = mono_view(&a->console_buf);
    a->console_view = v;
    gtk_text_buffer_set_text(a->console_buf,
        "Raw protocol console. Enter a command PAYLOAD in hex (the app adds "
        "framing, CRC16 and RC4). Response is shown decrypted.\n"
        "Examples:  06 (identify)   09 01 02 (beep)   21 (read HF)\n\n", -1);
    gtk_box_append(GTK_BOX(box), scrolled(v));

    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    a->hex_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->hex_entry), "payload hex, e.g. 21");
    gtk_widget_set_hexpand(a->hex_entry, TRUE);
    g_signal_connect(a->hex_entry, "activate", G_CALLBACK(on_send_raw), a);
    GtkWidget *send = gtk_button_new_with_label("Send");
    gtk_widget_add_css_class(send, "suggested-action");
    g_signal_connect(send, "clicked", G_CALLBACK(on_send_raw), a);
    gtk_box_append(GTK_BOX(row), a->hex_entry);
    gtk_box_append(GTK_BOX(row), send);
    gtk_box_append(GTK_BOX(box), row);
    return box;
}

static GtkWidget *page_crack(App *a)
{
    GtkWidget *box = pad_box(8);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(row), gtk_label_new("Block"));
    a->crack_block = gtk_spin_button_new_with_range(0, 255, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(a->crack_block), 4);
    a->crack_typeB = gtk_check_button_new_with_label("Key B");
    GtkWidget *dict = gtk_button_new_with_label("Dictionary check");
    gtk_widget_add_css_class(dict, "suggested-action");
    g_signal_connect(dict, "clicked", G_CALLBACK(on_dict), a);
    GtkWidget *dark = gtk_button_new_with_label("Darkside crack");
    g_signal_connect(dark, "clicked", G_CALLBACK(on_darkside), a);
    GtkWidget *nest = gtk_button_new_with_label("Nested crack");
    gtk_widget_add_css_class(nest, "suggested-action");
    g_signal_connect(nest, "clicked", G_CALLBACK(on_nested), a);
    GtkWidget *hard = gtk_button_new_with_label("Hardnested");
    g_signal_connect(hard, "clicked", G_CALLBACK(on_hardnested), a);
    gtk_box_append(GTK_BOX(row), a->crack_block);
    gtk_box_append(GTK_BOX(row), a->crack_typeB);
    gtk_box_append(GTK_BOX(row), dict);
    gtk_box_append(GTK_BOX(row), nest);
    gtk_box_append(GTK_BOX(row), dark);
    gtk_box_append(GTK_BOX(row), hard);
    gtk_box_append(GTK_BOX(box), row);

    /* whole-card autopwn → .mfd dump, on its own row */
    GtkWidget *arow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *autop = gtk_button_new_with_label("Autopwn → .mfd");
    gtk_widget_add_css_class(autop, "suggested-action");
    gtk_widget_set_tooltip_text(autop, "Recover every sector key (dictionary + "
        "nested) and dump the whole card to a .mfd file");
    g_signal_connect(autop, "clicked", G_CALLBACK(on_autopwn), a);
    gtk_box_append(GTK_BOX(arow), gtk_label_new("Whole card:"));
    gtk_box_append(GTK_BOX(arow), autop);
    GtkWidget *lkeys = gtk_button_new_with_label("Load keys…");
    gtk_widget_set_tooltip_text(lkeys, "Import a MifareClassicTool .keys file; the "
        "keys extend the dictionary used by Dictionary/Nested/Autopwn");
    g_signal_connect(lkeys, "clicked", G_CALLBACK(on_load_keys), a);
    gtk_box_append(GTK_BOX(arow), lkeys);
    gtk_box_append(GTK_BOX(box), arow);

    GtkWidget *view = mono_view(&a->crack_buf);
    a->crack_view = view;
    gtk_text_buffer_set_text(a->crack_buf,
        "Mifare key recovery.\n"
        "• Dictionary check: tries common/default keys against the block (cmd 13).\n"
        "• Nested crack: auto-finds a foothold key, then recovers the target key\n"
        "  with the nested attack (Crypto-1, ~10–30 s).\n"
        "• Darkside crack: collects nonces (cmd 15), solves with Crypto-1, and\n"
        "  confirms the key on the card — only works on cards vulnerable to the\n"
        "  darkside attack (hardened/EV1 cards resist it).\n"
        "• Hardnested: foothold + hardnested solver for cards that resist nested.\n"
        "• Autopwn → .mfd: recover every sector key and dump the whole card.\n"
        "Use only on cards you own or are authorized to test.\n\n", -1);
    gtk_box_append(GTK_BOX(box), scrolled(view));
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

/* persist size + current key entry on close */
static gboolean on_close_request(GtkWindow *w, gpointer u)
{
    (void)w;
    settings_save((App *)u);
    return FALSE;   /* allow the close to proceed */
}

static void activate(GtkApplication *gapp, gpointer user)
{
    App *a = user;
    load_css();
    GtkWidget *win = adw_application_window_new(gapp);
    a->win = GTK_WINDOW(win);
    gtk_window_set_title(GTK_WINDOW(win), "NFC PM-Pro");
    gtk_window_set_default_size(GTK_WINDOW(win), 880, 600);

    GtkWidget *toolbar = adw_toolbar_view_new();
    GtkWidget *header = adw_header_bar_new();
    a->status_pill = gtk_label_new("Not connected");
    gtk_widget_add_css_class(a->status_pill, "pill");
    gtk_widget_add_css_class(a->status_pill, "bad");
    adw_header_bar_pack_start(ADW_HEADER_BAR(header), a->status_pill);

    GtkWidget *stack = adw_view_stack_new();
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_device(a),
        "device", "Device", "preferences-system-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_read(a),
        "read", "Read", "view-reveal-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_write(a),
        "write", "Write / Clone", "document-edit-symbolic");
    adw_view_stack_add_titled_with_icon(ADW_VIEW_STACK(stack), page_crack(a),
        "crack", "Crack", "dialog-password-symbolic");
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

    settings_load(a);   /* restore mute / key / window size / .keys files */
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
