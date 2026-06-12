/* crypto1.h — NXP Crypto-1 cipher + key-recovery primitives.
 *
 * Faithful to the solver inside FuRuiTake's native DLL, which is itself a port
 * of the public-domain `crapto1` library (identical filter constants
 * 0xEC57E80A / 0x1e458 / 0xd938 / 0x6c9c0 / 0x3c8b0 / 0xf22c0, parity 0x6996).
 * Used here to recover Mifare Classic sector keys from nonces the PM-Pro
 * collects (nested attack, cmd 14; darkside, cmd 15).
 */
#ifndef PMPRO_CRYPTO1_H
#define PMPRO_CRYPTO1_H

#include <stdint.h>

typedef struct { uint32_t odd, even; } Crypto1State;

/* Crypto-1 filter function. */
uint32_t cr1_filter(uint32_t x);

/* Initialise state from a 48-bit key. */
void cr1_init(Crypto1State *s, uint64_t key);

/* Clock the cipher one bit / one word; `in` is fed in (encrypted or 0),
 * `enc` selects whether feedback uses the ciphertext. Returns keystream. */
uint8_t  cr1_bit(Crypto1State *s, uint8_t in, int enc);
uint32_t cr1_word(Crypto1State *s, uint32_t in, int enc);

/* Recover the 48-bit key from a recovered state (rollback). */
uint64_t cr1_state_to_key(const Crypto1State *s);

/* Roll the cipher backwards one bit / one word. */
uint8_t  cr1_rollback_bit(Crypto1State *s, uint32_t in, int fb);
uint32_t cr1_rollback_word(Crypto1State *s, uint32_t in, int fb);

/* Nested-attack recovery: given uid, the tag nonce nt, and 32 bits of keystream
 * ks observed (from a second authentication whose nt is known), return a
 * malloc'd, 0-terminated list of candidate 48-bit keys. *count gets the size. */
uint64_t *cr1_lfsr_recovery32(uint32_t ks2, uint32_t in, uint32_t *count);

/* Mifare 32-bit nonce PRNG: advance `x` by `n` steps. */
uint32_t cr1_prng_successor(uint32_t x, uint32_t n);

/* LFSR distance (in PRNG steps) between two tag nonces; used to estimate the
 * card's auth timing in the nested attack. Returns -1 on allocation failure. */
int cr1_nonce_distance(uint32_t from, uint32_t to);

#endif /* PMPRO_CRYPTO1_H */
