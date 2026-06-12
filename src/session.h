/* session.h — high-level PM-Pro session: connect handshake + command exec. */
#ifndef PMPRO_SESSION_H
#define PMPRO_SESSION_H

#include "hidraw.h"
#include <stddef.h>
#include <stdint.h>

#define FURUI_MAXMSG 8192

/* Execute one command: frame+encrypt `payload`, send, read the (possibly
 * multi-report) response, decrypt it. On success returns the framed length and
 * copies the decrypted plaintext ([len][payload][crc]) into `resp` (cap bytes).
 * Returns the framed length (>0) or 0 on failure. */
size_t furui_exec(pmpro_dev *dev, const uint8_t *payload, size_t len,
                  uint8_t *resp, size_t cap, int timeout_ms);

/* Connect: cmd06 (identify) -> cmd01 two-step handshake -> cmd06.
 * Returns 1 on success. */
int furui_connect(pmpro_dev *dev);

/* Beep the device (type/count, e.g. 0x01/0x02 success). Returns 1 on ack. */
int furui_beep(pmpro_dev *dev, uint8_t type, uint8_t count);

/* Turn on the device's "find/scan" indicator (cmd 0F). Returns 1 on ack. */
int furui_openfind(pmpro_dev *dev);

/* Read an HID prox card (cmd 29). Copies the decrypted payload to out (cap),
 * returns its length (0 if no card). */
size_t furui_read_hid(pmpro_dev *dev, uint8_t *out, size_t cap);

/* Write an HID prox card (cmd 2E) from a 12-byte card id. Returns 1 on ack. */
int furui_write_hid(pmpro_dev *dev, const uint8_t cardid[12]);

/* Format a Mifare sector (cmd 16): reset its data/trailer using key A/B.
 * flag: 1=A,2=B,3=both. Returns 1 on ack. */
int furui_format_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                        const uint8_t keyA[6], const uint8_t keyB[6]);

/* A detected 13.56 MHz card. */
typedef struct {
    int present;
    uint8_t uid[10];
    int uid_len;
    uint8_t tail[8];   /* ATQA/SAK/type bytes following the UID */
    int tail_len;
} furui_hf_card;

/* Read the HF card on the reader (cmd 21). Returns 1 if a card is present. */
int furui_read_hf(pmpro_dev *dev, furui_hf_card *card);

/* Activate the HF card (cmd 10). Returns 1 on ack. */
int furui_activate(pmpro_dev *dev);

/* Read one Mifare sector (cmd 17) with key A and/or B. flag: 1=A,2=B,3=both.
 * Copies the decrypted response payload into `out` (cap), returns payload len. */
size_t furui_read_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                         const uint8_t keyA[6], const uint8_t keyB[6],
                         uint8_t *out, size_t cap);

/* Write one Mifare sector (cmd 18) with key A and/or B. `data`/`datalen` is the
 * sector content to write (typically 64 bytes = 4 blocks). Returns 1 on ack. */
int furui_write_sector(pmpro_dev *dev, uint8_t sector, uint8_t flag,
                       const uint8_t keyA[6], const uint8_t keyB[6],
                       const uint8_t *data, size_t datalen);

/* Clone: for sectors 0..n-1, read with srcKeyA (A) and write with dstKeyA.
 * Writes the number of sectors successfully cloned to *done. Returns 1 if all
 * attempted sectors were read+written. (Source must be readable with the key;
 * target must be a UID-changeable/magic blank using the dst key.) */
int furui_clone(pmpro_dev *dev, int sectors, const uint8_t srcKeyA[6],
                const uint8_t dstKeyA[6], int *done,
                void (*progress)(int sector, int ok, void *u), void *u);

#endif /* PMPRO_SESSION_H */
