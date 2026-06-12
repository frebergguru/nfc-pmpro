/* furui.h — FURUI PM-Pro "talk" protocol: RC4 cipher + CRC16 + framing.
 *
 * Clean-room description of the device's wire format, determined by observing
 * the protocol for interoperability (see PROTOCOL.md). The wire format is:
 *
 *   plaintext = [len_LE(2)] [payload...] [CRC16/CCITT_LE(2)]   (len = total)
 *   ciphertext = RC4(plaintext padded to 64), key = deviceKey + 8 const bytes
 *   transport  = 64-byte HID reports, each prefixed with a 0x00 report id
 *
 * RC4 is symmetric, so the same routine encrypts and decrypts.
 */
#ifndef PMPRO_FURUI_H
#define PMPRO_FURUI_H

#include <stddef.h>
#include <stdint.h>

/* Device key (deviceKey = "0xB6,0x69,0x8A,0x37") + the 8 constant bytes the
 * KSA appends. The effective RC4 key is these 12 bytes. */
#define FURUI_DEVKEY_LEN 4
extern const uint8_t FURUI_DEVKEY[FURUI_DEVKEY_LEN];

/* RC4 KSA: build a 256-byte sbox from key (the 8 constant bytes are appended
 * internally, exactly as FuruiTalkInit does). */
void furui_rc4_init(const uint8_t *key, int keylen, uint8_t sbox[256]);

/* RC4 PRGA in place (encrypt == decrypt). Consumes/mutates sbox. */
void furui_rc4_crypt(uint8_t sbox[256], uint8_t *data, int len);

/* CRC-16/CCITT (poly 0x1021), bitwise, matching PM_Pro's CRC16(initcrc,...). */
uint16_t furui_crc16(uint16_t initcrc, const uint8_t *data, size_t len);

/* Build [len][payload][crc] into out (out must hold len+4). Returns total len. */
size_t furui_frame(const uint8_t *payload, size_t len, uint8_t *out);

/* Convenience: frame `payload`, zero-pad to 64, RC4-encrypt -> out64 (64 bytes).
 * Returns 1 on success (payload must be <= 60 bytes so framed <= 64). */
int furui_build_report(const uint8_t *payload, size_t len, uint8_t out64[64]);

/* Decrypt a received 64-byte report in place and return the framed length
 * (from the first two plaintext bytes). */
uint16_t furui_decrypt_report(uint8_t buf[64]);

/* General (any length): frame `payload`, zero-pad up to a multiple of 64, then
 * RC4-encrypt the whole thing into `out`. Returns the ciphertext length (a
 * multiple of 64). `out` must hold at least roundup64(len+4) bytes. */
size_t furui_pack(const uint8_t *payload, size_t len, uint8_t *out);

/* Decrypt `total` received ciphertext bytes in place (one continuous RC4
 * stream over the whole buffer). Returns the framed length from bytes[0:2]. */
uint16_t furui_unpack(uint8_t *buf, size_t total);

#endif /* PMPRO_FURUI_H */
