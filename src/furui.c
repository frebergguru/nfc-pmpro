#include "furui.h"
#include <string.h>

const uint8_t FURUI_DEVKEY[FURUI_DEVKEY_LEN] = {0xB6, 0x69, 0x8A, 0x37};

/* The 8 bytes FuruiTalkInit appends after the device key. */
static const uint8_t KSA_TAIL[8] = {64, 163, 121, 132, 155, 245, 109, 22};

void furui_rc4_init(const uint8_t *key, int keylen, uint8_t sbox[256])
{
    uint8_t k[16];
    if (keylen < 0) keylen = 0;
    if (keylen > 8) keylen = 8;       /* k[] holds keylen + 8 const bytes */
    int b = keylen + 8;               /* extended key length */
    for (int i = 0; i < keylen; i++)
        k[i] = key[i];
    for (int i = 0; i < 8; i++)
        k[keylen + i] = KSA_TAIL[i];

    for (int i = 0; i < 256; i++)
        sbox[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + sbox[i] + k[i % b]) & 0xFF;
        uint8_t t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
    }
}

void furui_rc4_crypt(uint8_t sbox[256], uint8_t *data, int len)
{
    int i = 0, j = 0;
    for (int n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + sbox[i]) & 0xFF;
        uint8_t t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
        int kk = (sbox[i] + sbox[j]) & 0xFF;
        data[n] ^= sbox[kk];
    }
}

uint16_t furui_crc16(uint16_t initcrc, const uint8_t *data, size_t len)
{
    uint32_t crc = initcrc;
    for (size_t n = 0; n < len; n++) {
        for (uint8_t bit = 0x80; bit != 0; bit >>= 1) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
            if (data[n] & bit)
                crc ^= 0x1021;
        }
    }
    return (uint16_t)(crc & 0xFFFF);
}

size_t furui_frame(const uint8_t *payload, size_t len, uint8_t *out)
{
    size_t total = len + 4;           /* 2 len + payload + 2 crc */
    out[0] = (uint8_t)(total & 0xFF); /* length, little-endian */
    out[1] = (uint8_t)((total >> 8) & 0xFF);
    memcpy(out + 2, payload, len);
    uint16_t crc = furui_crc16(0, out, len + 2);  /* over [len][payload] */
    out[len + 2] = (uint8_t)(crc & 0xFF);
    out[len + 3] = (uint8_t)((crc >> 8) & 0xFF);
    return total;
}

uint16_t furui_decrypt_report(uint8_t buf[64])
{
    uint8_t sbox[256];
    furui_rc4_init(FURUI_DEVKEY, FURUI_DEVKEY_LEN, sbox);
    furui_rc4_crypt(sbox, buf, 64);
    return (uint16_t)(buf[0] | (buf[1] << 8));
}

size_t furui_pack(const uint8_t *payload, size_t len, uint8_t *out)
{
    size_t framed = len + 4;
    size_t padded = (framed + 63) & ~(size_t)63;   /* round up to 64 */
    memset(out, 0, padded);
    furui_frame(payload, len, out);
    uint8_t sbox[256];
    furui_rc4_init(FURUI_DEVKEY, FURUI_DEVKEY_LEN, sbox);
    furui_rc4_crypt(sbox, out, (int)padded);
    return padded;
}

uint16_t furui_unpack(uint8_t *buf, size_t total)
{
    uint8_t sbox[256];
    furui_rc4_init(FURUI_DEVKEY, FURUI_DEVKEY_LEN, sbox);
    furui_rc4_crypt(sbox, buf, (int)total);
    return (uint16_t)(buf[0] | (buf[1] << 8));
}
