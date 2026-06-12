/* hardnested_glue.h — bridge the vendored mfoc-hardnested solver to the PM-Pro.
 * Collection uses device cmd 0x30; the offline solve is the vendored library. */
#ifndef PMPRO_HARDNESTED_GLUE_H
#define PMPRO_HARDNESTED_GLUE_H

#include "hidraw.h"
#include <stdint.h>

/* Recover the key for (trgBlock,trgType) using a known foothold key for
 * (knownBlock,knownType). type: 0=key A, 1=key B. Returns 1 + found[6] on
 * success. `log` (size lcap) gets a human-readable outcome.
 *
 * NOTE: the cmd-0x30 nonce record layout is parsed best-effort; validate /
 * adjust against a real darkside-vulnerable card (set PMPRO_HN_DEBUG=1 to dump
 * the raw collected bytes). The offline solver itself is the upstream
 * mfoc-hardnested code. */
int furui_hardnested(pmpro_dev *dev, uint8_t knownBlock, uint8_t knownType,
                     const uint8_t knownKey[6], uint8_t trgBlock, uint8_t trgType,
                     uint8_t found[6], char *log, size_t lcap);

#endif
