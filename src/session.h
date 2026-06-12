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

/* What furui_identify() found on the reader. */
typedef enum { FURUI_TAG_NONE, FURUI_TAG_HF, FURUI_TAG_LF, FURUI_TAG_HID } furui_tag_kind;

typedef struct {
    furui_tag_kind kind;
    furui_hf_card  hf;           /* valid when kind == FURUI_TAG_HF */
    uint16_t       atqa;         /* HF */
    uint8_t        sak;          /* HF */
    const char    *type;         /* human-readable type label (static string) */
    int            sectors;      /* HF: Mifare Classic sector count, else 0 */
    int            magic_gen1a;  /* HF: 1 if the cmd 1D backdoor read answered (UID0/gen1a magic) */
    uint8_t        data[64];     /* raw id bytes when kind == LF / HID */
    size_t         data_len;
} furui_tag_id;

/* Auto-detect whatever tag is on the reader: probe HF (cmd 21), then 125 kHz LF
 * (cmd 28), then HID prox (cmd 29); fill `out` with the first hit and name its
 * type. For HF also flags gen1a/UID0 magic via the cmd 1D backdoor read. Does no
 * key cracking or sector reads. Returns the detected kind (NONE if empty). */
furui_tag_kind furui_identify(pmpro_dev *dev, furui_tag_id *out);

/* Result of furui_magic_test(). */
typedef enum {
    FURUI_MAGIC_NOCARD,   /* no HF card on the reader */
    FURUI_MAGIC_NONE,     /* genuine card — block 0 is read-only */
    FURUI_MAGIC_GEN1A,    /* gen1a — answers the cmd 1D backdoor */
    FURUI_MAGIC_GEN2,     /* gen2/CUID — block 0 writable via normal auth */
    FURUI_MAGIC_UNKNOWN   /* couldn't run the gen2 probe (sector 0 key unknown) */
} furui_magic_kind;

/* Probe whether the HF card is a UID-changeable "magic" card. First tries the
 * gen1a backdoor (cmd 1D). If that fails, runs a gen2/CUID probe: flip one
 * manufacturer byte of block 0, write it (default key), read back to see if it
 * stuck (a genuine card rejects the block-0 write), then restore block 0.
 * **This WRITES to block 0** (restored afterwards) — caller should confirm.
 * `detail` (cap) gets a short human note. */
furui_magic_kind furui_magic_test(pmpro_dev *dev, char *detail, size_t cap);

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
