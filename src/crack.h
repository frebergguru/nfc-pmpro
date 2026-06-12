/* crack.h — Mifare key-recovery for the PM-Pro: dictionary (cmd 13),
 * darkside collection (cmd 15) + crapto1 solver, all confirmed via cmd 13. */
#ifndef PMPRO_CRACK_H
#define PMPRO_CRACK_H

#include "hidraw.h"
#include <stdint.h>
#include <stddef.h>

/* Test up to `n` candidate keys against `block` (type 0=A,1=B) via cmd 13.
 * If one authenticates, copies it to found[6] and returns 1; else 0. */
int furui_check_keys(pmpro_dev *dev, uint8_t block, uint8_t type,
                     const uint8_t (*keys)[6], int n, uint8_t found[6]);

/* Built-in dictionary attack on `block`. Returns 1 + found[6] on success. */
int furui_dict_attack(pmpro_dev *dev, uint8_t block, uint8_t type, uint8_t found[6]);

/* Collect darkside nonce data (cmd 10 + cmd 15) for `block`/`type` into `out`.
 * Returns the collected payload length (0/short => card not vulnerable). */
size_t furui_collect_darkside(pmpro_dev *dev, uint8_t block, uint8_t type,
                              uint8_t *out, size_t cap);

/* Full darkside: collect, run the crapto1 solver, then CONFIRM candidates with
 * cmd 13 so only a real key is returned. Returns 1 + found[6] on success, 0
 * otherwise. `status` (size scap) gets a human-readable outcome. */
int furui_darkside(pmpro_dev *dev, uint8_t block, uint8_t type, uint8_t found[6],
                   char *status, size_t scap);

#endif /* PMPRO_CRACK_H */
