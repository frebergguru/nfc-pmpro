#include "crypto1.h"
#include <stdio.h>
#include <stdlib.h>
int main(void){
    uint64_t K = 0xa0b1c2d3e4f5ULL;
    uint32_t V = 0x6f8a1c3d;            /* data fed during the 32 clocks (uid^nt) */
    Crypto1State s; cr1_init(&s, K);
    uint32_t ks = cr1_word(&s, V, 0);   /* 32 keystream bits */
    printf("key=%012llx  fed=%08x  ks=%08x\n", (unsigned long long)K, V, ks);

    uint32_t n=0;
    uint64_t *cands = cr1_lfsr_recovery32(ks, V, &n);
    printf("candidates: %u\n", n);
    int direct=0, viaroll=0;
    for (uint32_t i=0;i<n;i++){
        if (cands[i]==K) direct=1;
        Crypto1State cs; cr1_init(&cs, cands[i]);
        cr1_rollback_word(&cs, V, 0);
        if (cr1_state_to_key(&cs)==K) viaroll=1;
    }
    printf("K found directly: %s   via rollback: %s\n", direct?"YES":"no", viaroll?"YES":"no");
    free(cands);
    printf("\n%s\n", (direct||viaroll)?"*** RECOVERY SELF-TEST PASS ***":"recovery FAILED");
    return !(direct||viaroll);
}
