#include "crypto1.h"
#include <stdio.h>
int main(void){
    /* invariant: key -> state -> key round-trips */
    uint64_t keys[] = {0xFFFFFFFFFFFFULL, 0xa0a1a2a3a4a5ULL, 0x000000000001ULL, 0x123456789abcULL};
    int pass = 1;
    for (int i=0;i<4;i++){
        Crypto1State s; cr1_init(&s, keys[i]);
        uint64_t back = cr1_state_to_key(&s);
        printf("key %012llx -> state(odd=%06x even=%06x) -> %012llx  %s\n",
               (unsigned long long)keys[i], s.odd, s.even, (unsigned long long)back,
               back==keys[i]?"OK":"FAIL");
        if (back!=keys[i]) pass=0;
    }
    /* keystream determinism: same key+uid+nt give same ks */
    Crypto1State a,b; cr1_init(&a,0xa0a1a2a3a4a5ULL); cr1_init(&b,0xa0a1a2a3a4a5ULL);
    uint32_t ksa = cr1_word(&a, 0xcafebabe, 0);
    uint32_t ksb = cr1_word(&b, 0xcafebabe, 0);
    printf("keystream determinism: %08x == %08x  %s\n", ksa, ksb, ksa==ksb?"OK":"FAIL");
    if (ksa!=ksb) pass=0;
    printf("filter(0)=%u filter(0xffffffff)=%u\n", cr1_filter(0), cr1_filter(0xffffffff));
    printf("\n%s\n", pass?"ALL CIPHER SELF-TESTS PASS":"FAILURES");
    return !pass;
}
