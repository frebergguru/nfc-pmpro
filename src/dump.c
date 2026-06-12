#include "dump.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pmpro_dump_init(pmpro_dump *d)
{
    memset(d, 0, sizeof *d);
    snprintf(d->card_type, sizeof d->card_type, "unknown");
}

bool pmpro_dump_add_block(pmpro_dump *d, const char *hex)
{
    if (d->n_blocks >= PMPRO_MAX_BLOCKS)
        return false;
    snprintf(d->blocks[d->n_blocks], PMPRO_LINE, "%s", hex);
    d->n_blocks++;
    return true;
}

bool pmpro_dump_add_key(pmpro_dump *d, const char *hex)
{
    if (d->n_keys >= PMPRO_MAX_KEYS)
        return false;
    snprintf(d->keys[d->n_keys], PMPRO_LINE, "%s", hex);
    d->n_keys++;
    return true;
}

bool pmpro_dump_set_block(pmpro_dump *d, int idx, const char *hex)
{
    if (idx < 0 || idx >= d->n_blocks)
        return false;
    unsigned char tmp[64];
    int nb = pmpro_parse_hex(hex, tmp, sizeof tmp);
    if (nb <= 0)
        return false;
    char norm[PMPRO_LINE];
    pmpro_hex(tmp, (size_t)nb, norm, sizeof norm);
    snprintf(d->blocks[idx], PMPRO_LINE, "%s", norm);
    return true;
}

int pmpro_dump_diff(const pmpro_dump *a, const pmpro_dump *b, char *out, size_t cap)
{
    size_t pos = 0;
    int diffs = 0;
    if (cap) out[0] = '\0';
    #define APP(...) do { if (pos < cap) pos += (size_t)snprintf(out + pos, cap - pos, __VA_ARGS__); } while (0)
    if (strcmp(a->card_type, b->card_type)) { APP("type:  %s | %s\n", a->card_type, b->card_type); diffs++; }
    if (strcmp(a->frequency, b->frequency)) { APP("freq:  %s | %s\n", a->frequency, b->frequency); diffs++; }
    if (strcmp(a->uid, b->uid))             { APP("uid:   %s | %s\n", a->uid, b->uid); diffs++; }
    int n = a->n_blocks > b->n_blocks ? a->n_blocks : b->n_blocks;
    for (int i = 0; i < n; i++) {
        const char *ba = i < a->n_blocks ? a->blocks[i] : "(none)";
        const char *bb = i < b->n_blocks ? b->blocks[i] : "(none)";
        if (strcmp(ba, bb)) {
            diffs++;
            APP("block %d:\n  A: %s\n  B: %s\n", i, ba, bb);
        }
    }
    if (diffs == 0)
        APP("identical (%d blocks, uid %s)\n", a->n_blocks, a->uid);
    #undef APP
    return diffs;
}

bool pmpro_dump_save(const pmpro_dump *d, const char *path, char *err, size_t n)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        snprintf(err, n, "cannot write %s", path);
        return false;
    }
    fprintf(f, "# pmpro-dump v1\n");
    fprintf(f, "type: %s\n", d->card_type);
    fprintf(f, "freq: %s\n", d->frequency);
    fprintf(f, "uid: %s\n", d->uid);
    if (d->meta[0])
        fprintf(f, "meta: %s\n", d->meta);
    for (int i = 0; i < d->n_blocks; ++i)
        fprintf(f, "block: %s\n", d->blocks[i]);
    for (int i = 0; i < d->n_keys; ++i)
        fprintf(f, "key: %s\n", d->keys[i]);
    fclose(f);
    return true;
}

bool pmpro_dump_save_mfd(const pmpro_dump *d, const char *path, char *err, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        snprintf(err, n, "cannot write %s", path);
        return false;
    }
    /* each entry is one sector (sectors 0..31 = 64 bytes, 4K sectors = 256);
     * parse its hex, zero-pad short/missing data, write contiguously. */
    size_t total = 0;
    for (int i = 0; i < d->n_blocks; i++) {
        int secsize = i < 32 ? 64 : 256;
        unsigned char raw[256];
        memset(raw, 0, sizeof raw);
        pmpro_parse_hex(d->blocks[i], raw, (size_t)secsize);
        fwrite(raw, 1, (size_t)secsize, f);
        total += (size_t)secsize;
    }
    /* pad up to a standard card size so the result is a valid .mfd */
    size_t target = total <= 1024 ? 1024 : 4096;
    unsigned char z[64] = {0};
    while (total < target) {
        size_t c = target - total < sizeof z ? target - total : sizeof z;
        fwrite(z, 1, c, f);
        total += c;
    }
    fclose(f);
    if (err && n) err[0] = '\0';
    return true;
}

static int has_ext(const char *path, const char *ext)
{
    size_t lp = strlen(path), le = strlen(ext);
    if (lp < le) return 0;
    const char *p = path + lp - le;
    for (size_t i = 0; i < le; i++) {
        char a = p[i], b = ext[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

bool pmpro_dump_save_auto(const pmpro_dump *d, const char *path, char *err, size_t n)
{
    if (has_ext(path, ".mfd") || has_ext(path, ".bin") || has_ext(path, ".dump"))
        return pmpro_dump_save_mfd(d, path, err, n);
    return pmpro_dump_save(d, path, err, n);
}

static void rstrip(char *s)
{
    size_t len = strlen(s);
    while (len && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                   s[len - 1] == ' '))
        s[--len] = '\0';
}

static void dump_load_text(pmpro_dump *d, FILE *f)
{
    pmpro_dump_init(d);
    char line[512];
    while (fgets(line, sizeof line, f)) {
        rstrip(line);
        if (line[0] == '#' || line[0] == '\0')
            continue;
        char *val = strchr(line, ':');
        if (!val)
            continue;
        *val++ = '\0';
        while (*val == ' ')
            val++;
        if (strcmp(line, "type") == 0)
            snprintf(d->card_type, sizeof d->card_type, "%s", val);
        else if (strcmp(line, "freq") == 0)
            snprintf(d->frequency, sizeof d->frequency, "%s", val);
        else if (strcmp(line, "uid") == 0)
            snprintf(d->uid, sizeof d->uid, "%s", val);
        else if (strcmp(line, "meta") == 0)
            snprintf(d->meta, sizeof d->meta, "%s", val);
        else if (strcmp(line, "block") == 0)
            pmpro_dump_add_block(d, val);
        else if (strcmp(line, "key") == 0)
            pmpro_dump_add_key(d, val);
    }
}

/* Raw Mifare Classic dump (.mfd): contiguous 16-byte blocks. Stored one
 * 64-byte sector per block entry to match the read/clone buffer (sectors 0..31
 * are 4 blocks; 4K sectors 32+ are 16 blocks). */
static bool dump_load_mfd(pmpro_dump *d, const uint8_t *raw, size_t n)
{
    if (n < 64 || n % 16)
        return false;
    pmpro_dump_init(d);
    snprintf(d->card_type, sizeof d->card_type, "Mifare Classic %dK",
             n > 1024 ? 4 : 1);
    snprintf(d->frequency, sizeof d->frequency, "13.56MHz");
    pmpro_hex(raw, 4, d->uid, sizeof d->uid);     /* UID from block 0 */
    int total = (int)(n / 16);
    int blk = 0, sec = 0;
    while (blk < total) {
        int bib = sec < 32 ? 4 : 16;              /* blocks in this sector */
        if (blk + bib > total) bib = total - blk;
        char h[PMPRO_LINE];
        pmpro_hex(raw + blk * 16, (size_t)bib * 16, h, sizeof h);
        if (!pmpro_dump_add_block(d, h))
            break;
        blk += bib;
        sec++;
    }
    return d->n_blocks > 0;
}

bool pmpro_dump_load(pmpro_dump *d, const char *path, char *err, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, n, "cannot read %s", path);
        return false;
    }
    unsigned char head[2] = {0, 0};
    size_t hn = fread(head, 1, sizeof head, f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    /* our text dumps start with "# "; otherwise a known Mifare size is raw .mfd */
    int is_text = (hn >= 2 && head[0] == '#' && head[1] == ' ');
    int is_mfd = !is_text && (sz == 320 || sz == 1024 || sz == 2048 || sz == 4096);

    bool ok = true;
    if (is_mfd) {
        uint8_t *buf = malloc((size_t)sz);
        if (!buf) { fclose(f); snprintf(err, n, "out of memory"); return false; }
        ok = fread(buf, 1, (size_t)sz, f) == (size_t)sz && dump_load_mfd(d, buf, (size_t)sz);
        free(buf);
        if (!ok) snprintf(err, n, "not a recognizable Mifare dump (%ld bytes)", sz);
    } else {
        dump_load_text(d, f);
        if (d->n_blocks == 0 && d->uid[0] == '\0') {
            snprintf(err, n, "%s is not a valid .pmdump or .mfd dump", path);
            ok = false;
        }
    }
    fclose(f);
    if (ok && err && n) err[0] = '\0';
    return ok;
}
