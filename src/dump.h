/* dump.h — captured-card model with save/load.
 *
 * A simple, human-readable line format keeps us dependency-free (no json-glib):
 *
 *   # pmpro-dump v1
 *   type: EM4100
 *   freq: 125kHz
 *   uid: 12 34 56 78
 *   meta: <free text>
 *   block: <hex>        (repeated, in order)
 *   key:   <hex>        (repeated)
 */
#ifndef PMPRO_DUMP_H
#define PMPRO_DUMP_H

#include <stdbool.h>
#include <stddef.h>

#define PMPRO_MAX_BLOCKS 256
#define PMPRO_MAX_KEYS 64
#define PMPRO_LINE 128

typedef struct {
    char card_type[32];
    char frequency[16];
    char uid[128];
    char meta[256];
    char blocks[PMPRO_MAX_BLOCKS][PMPRO_LINE];
    int n_blocks;
    char keys[PMPRO_MAX_KEYS][PMPRO_LINE];
    int n_keys;
} pmpro_dump;

void pmpro_dump_init(pmpro_dump *d);
bool pmpro_dump_add_block(pmpro_dump *d, const char *hex);
bool pmpro_dump_add_key(pmpro_dump *d, const char *hex);

/* Replace block `idx` (0-based, must already exist) with `hex` (re-normalised to
 * lowercase space-separated). Returns false on a bad index or unparseable hex. */
bool pmpro_dump_set_block(pmpro_dump *d, int idx, const char *hex);

/* Write a human-readable diff of `a` vs `b` (uid/type/freq + per-block) into
 * `out` (size cap). Returns the number of differing fields/blocks (0 if equal). */
int pmpro_dump_diff(const pmpro_dump *a, const pmpro_dump *b, char *out, size_t cap);

/* Returns true on success; on failure fills err (size n). */
bool pmpro_dump_save(const pmpro_dump *d, const char *path, char *err, size_t n);
bool pmpro_dump_load(pmpro_dump *d, const char *path, char *err, size_t n);

#endif /* PMPRO_DUMP_H */
