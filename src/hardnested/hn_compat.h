/* hn_compat.h — minimal shims so the vendored mfoc-hardnested solver builds
 * without libnfc/mfoc. Nonce collection is supplied by the PM-Pro via the
 * hardnested_pmpro_collect hook instead of nfc_initiator_* / mf_enhanced_auth. */
#ifndef HN_COMPAT_H
#define HN_COMPAT_H

#include <stdint.h>
#include <stdbool.h>

/* Mifare auth key-type selectors (were libnfc mifare_cmd values). */
#ifndef MC_AUTH_A
#define MC_AUTH_A 0x60
#endif
#ifndef MC_AUTH_B
#define MC_AUTH_B 0x61
#endif

/* PM-Pro nonce source. Set by the app before calling mfnestedhard().
 * Collects encrypted nonces for the target (trgBlockNo/trgKeyType) using the
 * known foothold key for blockNo/keyType, calling feed() once per nonce, and
 * returns the card UID via *cuid_out. Returns the number of nonces fed (0 ends
 * acquisition). */
typedef void (*hn_feed_fn)(uint32_t nonce_enc, uint8_t par_enc);
extern int (*hardnested_pmpro_collect)(uint8_t blockNo, uint8_t keyType,
                                       const uint8_t *key, uint8_t trgBlockNo,
                                       uint8_t trgKeyType, hn_feed_fn feed,
                                       uint32_t *cuid_out);

/* Set by the brute-force core when the target key is recovered. */
extern volatile uint64_t hardnested_recovered_key;
extern volatile int hardnested_recovered;

#endif
