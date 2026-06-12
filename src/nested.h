/* nested.h — Mifare nested key recovery (cmd 14 collection + crapto1). */
#ifndef PMPRO_NESTED_H
#define PMPRO_NESTED_H

#include "hidraw.h"
#include <stdint.h>
#include <stddef.h>

/* Recover the key for target (tblock,ttype) using a known foothold key for
 * (fblock,ftype). type: 0=key A, 1=key B. Returns 1 + found[6] on success.
 * `log` (size lcap) gets a human-readable outcome. */
int furui_nested(pmpro_dev *dev, uint8_t fblock, uint8_t ftype, const uint8_t fkey[6],
                 uint8_t tblock, uint8_t ttype, uint8_t found[6], char *log, size_t lcap);

/* Nested with an automatic foothold: scans sectors for a known/default key,
 * then nested-attacks (tblock,ttype). Returns 1 + found[6] on success. */
int furui_nested_auto(pmpro_dev *dev, uint8_t tblock, uint8_t ttype,
                      uint8_t found[6], char *log, size_t lcap);

/* Autopwn: dictionary + nested across every sector, read the whole card, and
 * write a raw .mfd dump (with recovered keys in the trailers). `prog` (optional)
 * gets progress messages. Returns 1 if any sector was keyed/dumped. */
int furui_autopwn(pmpro_dev *dev, const char *mfd_path,
                  void (*prog)(const char *msg, void *u), void *u,
                  char *log, size_t lcap);

#endif
