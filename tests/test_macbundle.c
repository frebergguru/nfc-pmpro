#include "macbundle.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char out[512];
    assert(pmpro_bundle_contents("/Applications/pmpro.app/Contents/MacOS/pmpro", out, sizeof out));
    assert(strcmp(out, "/Applications/pmpro.app/Contents") == 0);
    /* spaces in the path */
    assert(pmpro_bundle_contents("/Applications/My Tools/pmpro.app/Contents/MacOS/pmpro", out, sizeof out));
    assert(strcmp(out, "/Applications/My Tools/pmpro.app/Contents") == 0);
    /* translocated path */
    assert(pmpro_bundle_contents("/private/var/folders/x/AppTranslocation/ABC/d/pmpro.app/Contents/MacOS/pmpro", out, sizeof out));
    /* not a bundle */
    assert(!pmpro_bundle_contents("/Users/me/nfc-pmpro/build-gui/pmpro", out, sizeof out));
    assert(!pmpro_bundle_contents("/opt/Contents/MacOS/pmpro", out, sizeof out));          /* no .app */
    assert(!pmpro_bundle_contents("/x/pmpro.app/Contents/MacOS/sub/pmpro", out, sizeof out)); /* nested */
    assert(!pmpro_bundle_contents("/x/pmpro.app/Contents/MacOS/", out, sizeof out));      /* no name */
    /* too small output buffer */
    char tiny[8];
    assert(!pmpro_bundle_contents("/Applications/pmpro.app/Contents/MacOS/pmpro", tiny, sizeof tiny));

    char *e = pmpro_expand_bundle_token("\"@BUNDLE@/Frameworks/a.so\"\n\"@BUNDLE@/b.so\"\n", "/A B/p.app/Contents");
    assert(e && strcmp(e, "\"/A B/p.app/Contents/Frameworks/a.so\"\n\"/A B/p.app/Contents/b.so\"\n") == 0);
    free(e);
    e = pmpro_expand_bundle_token("no token", "/x");
    assert(e && strcmp(e, "no token") == 0);
    free(e);
    printf("test_macbundle: OK\n");
    return 0;
}
