#include "macbundle.h"
#include <stdlib.h>
#include <string.h>

bool pmpro_bundle_contents(const char *exe, char *out, size_t n)
{
    static const char mid[] = ".app/Contents/MacOS/";
    const char *slash = strrchr(exe, '/');
    if (!slash || slash[1] == '\0') return false;            /* need a file name */
    size_t dirlen = (size_t)(slash - exe) + 1;               /* incl. trailing '/' */
    size_t ml = sizeof mid - 1;
    if (dirlen < ml || strncmp(exe + dirlen - ml, mid, ml) != 0) return false;
    size_t clen = dirlen - strlen("/MacOS/");                /* ".../X.app/Contents" */
    if (clen + 1 > n) return false;
    memcpy(out, exe, clen);
    out[clen] = '\0';
    return true;
}

char *pmpro_expand_bundle_token(const char *src, const char *contents)
{
    static const char tok[] = "@BUNDLE@";
    size_t tl = sizeof tok - 1, cl = strlen(contents), count = 0;
    for (const char *p = src; (p = strstr(p, tok)); p += tl) count++;
    char *out = malloc(strlen(src) + count * (cl > tl ? cl - tl : 0) + 1);
    if (!out) return NULL;
    char *w = out;
    for (const char *p = src;;) {
        const char *q = strstr(p, tok);
        if (!q) { strcpy(w, p); break; }
        memcpy(w, p, (size_t)(q - p)); w += q - p;
        memcpy(w, contents, cl); w += cl;
        p = q + tl;
    }
    return out;
}
