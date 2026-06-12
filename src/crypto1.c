/* crypto1.c — NXP Crypto-1 cipher + Crypto-1 LFSR key recovery.
 *
 * The cipher (cr1_init/bit/word/filter/state_to_key/rollback) is a clean C
 * implementation matching the solver inside FuRuiTake's native DLL.
 *
 * The key-recovery part (update_contribution, extend_table, recover,
 * bucket_sort_intersect, cr1_lfsr_recovery32) is a faithful port of the
 * public-domain/GPL `crapto1` library by bla <blapost@gmail.com> and the
 * Proxmark3 contributors (common/crapto1/crapto1.c + common/bucketsort.c).
 * That code is GPLv3; this file therefore carries the GPLv3 terms for those
 * portions. The PM-Pro's native solver is itself a port of the same algorithm.
 */
#include "crypto1.h"
#include <stdlib.h>
#include <string.h>

#define LF_POLY_ODD  0x29CE5Cu
#define LF_POLY_EVEN 0x870804u
#define BIT(x, n)   ((uint32_t)((x) >> (n)) & 1)
#define BEBIT(x, n) BIT(x, (n) ^ 24)

static inline uint32_t evenparity32(uint32_t x) { return (uint32_t)__builtin_parity(x); }
#define even32(x) evenparity32(x)

/* ----------------------------- cipher ---------------------------------- */

uint32_t cr1_filter(uint32_t x)
{
    uint32_t f;
    f  = 0xf22c0u >> (x       & 0xf) & 16;
    f |= 0x6c9c0u >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0u >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458u >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938u >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80Au, f);
}

void cr1_init(Crypto1State *s, uint64_t key)
{
    s->odd = s->even = 0;
    for (int i = 47; i > 0; i -= 2) {
        s->odd  = s->odd  << 1 | BIT(key, (i - 1) ^ 7);
        s->even = s->even << 1 | BIT(key, i ^ 7);
    }
}

uint8_t cr1_bit(Crypto1State *s, uint8_t in, int enc)
{
    uint32_t feedin, t;
    uint8_t ret = (uint8_t)cr1_filter(s->odd);
    feedin  = ret & (uint32_t)(!!enc);
    feedin ^= (uint32_t)(!!in);
    feedin ^= LF_POLY_ODD  & s->odd;
    feedin ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | evenparity32(feedin);
    t = s->odd; s->odd = s->even; s->even = t;
    return ret;
}

uint32_t cr1_word(Crypto1State *s, uint32_t in, int enc)
{
    uint32_t ret = 0;
    for (int i = 0; i < 32; i++)
        ret |= (uint32_t)cr1_bit(s, (uint8_t)BEBIT(in, i), enc) << (24 ^ i);
    return ret;
}

uint64_t cr1_state_to_key(const Crypto1State *s)
{
    uint64_t lfsr = 0;
    for (int i = 23; i >= 0; --i) {
        lfsr = lfsr << 1 | BIT(s->odd, i ^ 3);
        lfsr = lfsr << 1 | BIT(s->even, i ^ 3);
    }
    return lfsr;
}

uint8_t cr1_rollback_bit(Crypto1State *s, uint32_t in, int fb)
{
    int out;
    uint8_t ret;
    uint32_t t;
    s->odd &= 0xffffff;
    t = s->odd; s->odd = s->even; s->even = t;
    out = s->even & 1;
    out ^= LF_POLY_EVEN & (s->even >>= 1);
    out ^= LF_POLY_ODD & s->odd;
    out ^= (uint32_t)(!!in);
    out ^= (ret = (uint8_t)cr1_filter(s->odd)) & (uint32_t)(!!fb);
    s->even |= evenparity32((uint32_t)out) << 23;
    return ret;
}

uint32_t cr1_rollback_word(Crypto1State *s, uint32_t in, int fb)
{
    uint32_t ret = 0;
    for (int i = 31; i >= 0; --i)
        ret |= (uint32_t)cr1_rollback_bit(s, BEBIT(in, i), fb) << (24 ^ i);
    return ret;
}

/* -------------------- PRNG / nonce helpers (crapto1, GPL) -------------- */

uint32_t cr1_prng_successor(uint32_t x, uint32_t n)
{
    x = (x >> 8 & 0xff00ffu) | (x & 0xff00ffu) << 8;   /* byte-swap */
    x = x >> 16 | x << 16;
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    x = (x >> 8 & 0xff00ffu) | (x & 0xff00ffu) << 8;   /* byte-swap back */
    return x >> 16 | x << 16;
}

int cr1_nonce_distance(uint32_t from, uint32_t to)
{
    static uint16_t *dist = NULL;          /* one-time 128 KB cache */
    if (!dist) {
        dist = calloc(1u << 16, sizeof *dist);
        if (!dist) return -1;
        uint16_t x = 1;
        for (uint16_t i = 1; i; ++i) {
            dist[(x & 0xff) << 8 | x >> 8] = i;
            x = (uint16_t)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
        }
    }
    return (65535 + dist[to >> 16] - dist[from >> 16]) % 65535;
}

/* -------------------- key recovery (crapto1, GPL) ---------------------- */

typedef struct { uint32_t *head, *bp; } bucket_t;
typedef bucket_t bucket_array_t[2][0x100];
typedef struct {
    struct { uint32_t *head, *tail; } bi[2][0x100];
    uint32_t numbuckets;
} bucket_info_t;

static void bucket_sort_intersect(uint32_t *estart, uint32_t *estop,
                                  uint32_t *ostart, uint32_t *ostop,
                                  bucket_info_t *info, bucket_array_t bucket)
{
    uint32_t *p1, *p2, *start[2], *stop[2];
    start[0] = estart; stop[0] = estop; start[1] = ostart; stop[1] = ostop;

    for (uint32_t i = 0; i < 2; i++)
        for (uint32_t j = 0; j <= 0xff; j++)
            bucket[i][j].bp = bucket[i][j].head;

    for (uint32_t i = 0; i < 2; i++)
        for (p1 = start[i]; p1 <= stop[i]; p1++) {
            uint32_t bi = (*p1 & 0xff000000) >> 24;
            *(bucket[i][bi].bp++) = *p1;
        }

    for (uint32_t i = 0; i < 2; i++) {
        p1 = start[i];
        uint32_t nb = 0;
        for (uint32_t j = 0; j <= 0xff; j++) {
            if (bucket[0][j].bp != bucket[0][j].head &&
                bucket[1][j].bp != bucket[1][j].head) {
                info->bi[i][nb].head = p1;
                for (p2 = bucket[i][j].head; p2 < bucket[i][j].bp; *p1++ = *p2++)
                    ;
                info->bi[i][nb].tail = p1 - 1;
                nb++;
            }
        }
        info->numbuckets = nb;
    }
}

static inline void update_contribution(uint32_t *item, uint32_t m1, uint32_t m2)
{
    uint32_t p = *item >> 25;
    p = p << 1 | even32(*item & m1);
    p = p << 1 | even32(*item & m2);
    *item = p << 24 | (*item & 0xffffff);
}

static inline void extend_table(uint32_t *tbl, uint32_t **end, int bit,
                                int m1, int m2, uint32_t in)
{
    uint8_t tf;
    in <<= 24;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        tf = (uint8_t)cr1_filter(*tbl);
        if (tf ^ cr1_filter(*tbl | 1)) {
            *tbl |= tf ^ (uint32_t)bit;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else if (tf == (uint8_t)bit) {
            *++*end = tbl[1];
            tbl[1] = tbl[0] | 1;
            update_contribution(tbl, m1, m2);
            *tbl++ ^= in;
            update_contribution(tbl, m1, m2);
            *tbl ^= in;
        } else {
            *tbl-- = *(*end)--;
        }
    }
}

static inline void extend_table_simple(uint32_t *tbl, uint32_t **end, int bit)
{
    uint8_t tf;
    for (*tbl <<= 1; tbl <= *end; *++tbl <<= 1) {
        tf = (uint8_t)cr1_filter(*tbl);
        if (tf ^ cr1_filter(*tbl | 1)) {
            *tbl |= tf ^ (uint32_t)bit;
        } else if (tf == (uint8_t)bit) {
            *++*end = *++tbl;
            *tbl = tbl[-1] | 1;
        } else {
            *tbl-- = *(*end)--;
        }
    }
}

static Crypto1State *recover(uint32_t *o_head, uint32_t *o_tail, uint32_t oks,
                            uint32_t *e_head, uint32_t *e_tail, uint32_t eks,
                            int rem, Crypto1State *sl, uint32_t in,
                            bucket_array_t bucket)
{
    bucket_info_t info;

    if (rem == -1) {
        for (uint32_t *e = e_head; e <= e_tail; ++e) {
            *e = *e << 1 ^ even32(*e & LF_POLY_EVEN) ^ (uint32_t)(!!(in & 4));
            for (uint32_t *o = o_head; o <= o_tail; ++o, ++sl) {
                sl->even = *o;
                sl->odd = *e ^ even32(*o & LF_POLY_ODD);
                sl[1].odd = sl[1].even = 0;
            }
        }
        return sl;
    }

    for (uint32_t i = 0; i < 4 && rem--; i++) {
        oks >>= 1; eks >>= 1; in >>= 2;
        extend_table(o_head, &o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
        if (o_head > o_tail) return sl;
        extend_table(e_head, &e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
        if (e_head > e_tail) return sl;
    }

    bucket_sort_intersect(e_head, e_tail, o_head, o_tail, &info, bucket);

    for (int i = (int)info.numbuckets - 1; i >= 0; i--)
        sl = recover(info.bi[1][i].head, info.bi[1][i].tail, oks,
                     info.bi[0][i].head, info.bi[0][i].tail, eks,
                     rem, sl, in, bucket);
    return sl;
}

uint64_t *cr1_lfsr_recovery32(uint32_t ks2, uint32_t in, uint32_t *count)
{
    Crypto1State *statelist = NULL;
    uint32_t *odd_head = 0, *odd_tail = 0, oks = 0;
    uint32_t *even_head = 0, *even_tail = 0, eks = 0;
    bucket_array_t bucket;
    memset(bucket, 0, sizeof bucket);
    uint64_t *keys = NULL;
    int i;
    if (count) *count = 0;

    for (i = 31; i >= 0; i -= 2) oks = oks << 1 | BEBIT(ks2, i);
    for (i = 30; i >= 0; i -= 2) eks = eks << 1 | BEBIT(ks2, i);

    odd_head  = odd_tail  = calloc(1, sizeof(uint32_t) << 21);
    even_head = even_tail = calloc(1, sizeof(uint32_t) << 21);
    statelist = calloc(1, sizeof(Crypto1State) << 18);
    if (!odd_tail-- || !even_tail-- || !statelist) goto out;
    statelist->odd = statelist->even = 0;

    for (i = 0; i < 2; i++)
        for (uint32_t j = 0; j <= 0xff; j++) {
            bucket[i][j].head = calloc(1, sizeof(uint32_t) << 14);
            if (!bucket[i][j].head) goto out;
        }

    uint8_t oks1 = oks & 1, eks1 = eks & 1;
    for (i = 1 << 20; i >= 0; --i) {
        uint8_t tf = (uint8_t)cr1_filter((uint32_t)i);
        if (tf == oks1) *++odd_tail = (uint32_t)i;
        if (tf == eks1) *++even_tail = (uint32_t)i;
    }
    for (i = 0; i < 4; i++) {
        extend_table_simple(odd_head,  &odd_tail,  (int)((oks >>= 1) & 1));
        extend_table_simple(even_head, &even_tail, (int)((eks >>= 1) & 1));
    }

    in = (in >> 16 & 0xff) | (in << 16) | (in & 0xff00);
    Crypto1State *send = recover(odd_head, odd_tail, oks, even_head, even_tail,
                                 eks, 11, statelist, in << 1, bucket);

    uint32_t n = (uint32_t)(send - statelist);
    keys = malloc(sizeof(uint64_t) * (n + 1));
    if (keys) {
        for (uint32_t k = 0; k < n; k++)
            keys[k] = cr1_state_to_key(&statelist[k]);
        if (count) *count = n;
    }

out:
    for (i = 0; i < 2; i++)
        for (uint32_t j = 0; j <= 0xff; j++)
            free(bucket[i][j].head);
    free(odd_head);
    free(even_head);
    free(statelist);
    return keys;
}
