#include "dump.h"

#include <stdio.h>
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

static void rstrip(char *s)
{
    size_t len = strlen(s);
    while (len && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                   s[len - 1] == ' '))
        s[--len] = '\0';
}

bool pmpro_dump_load(pmpro_dump *d, const char *path, char *err, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, n, "cannot read %s", path);
        return false;
    }
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
    fclose(f);
    return true;
}
