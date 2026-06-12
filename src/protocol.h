/* protocol.h — framing helpers + card decoders for the PM-Pro.
 *
 * The command framing is being reverse-engineered against live hardware
 * (64-byte vendor HID reports). Helpers here are protocol-independent: hex
 * formatting, checksum candidates, and card decoders that work once we have
 * the raw card bytes.
 */
#ifndef PMPRO_PROTOCOL_H
#define PMPRO_PROTOCOL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Format `data` as space-separated hex into `out` (size n). Returns out. */
char *pmpro_hex(const unsigned char *data, size_t len, char *out, size_t n);

/* Printable-ASCII preview ('.' for non-printable) into out (size n). */
char *pmpro_ascii(const unsigned char *data, size_t len, char *out, size_t n);

/* Parse a hex string ("01 a2 ff" or "01a2ff") into buf (size n).
 * Returns number of bytes parsed, or -1 on malformed input. */
int pmpro_parse_hex(const char *text, unsigned char *buf, size_t n);

uint8_t pmpro_xor(const unsigned char *data, size_t len);
uint8_t pmpro_sum(const unsigned char *data, size_t len);

/* EM4100/EM4200: decode the 5 ID bytes (customer + 4 id bytes) into the common
 * renderings. Fills the provided buffers (each >= 32). Returns true if len>=5. */
typedef struct {
    uint8_t customer;       /* customer/version id */
    uint32_t card_number;   /* 32-bit card number */
    char hex[16];           /* "cc xx xx xx xx" */
    char fob_text[16];      /* "00008,12345" style printed on fobs */
} em4100_info;

bool pmpro_decode_em4100(const unsigned char *id_bytes, size_t len,
                         em4100_info *out);

/* ISO14443A UID rendering (4/7/10 bytes). */
typedef struct {
    char uid[40];           /* hex */
    int uid_len;
} uid_info;

void pmpro_decode_uid(const unsigned char *uid, size_t len, uid_info *out);

#endif /* PMPRO_PROTOCOL_H */
