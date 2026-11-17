/* macbundle.h — pure helpers for running pmpro from a macOS .app bundle. */
#ifndef PMPRO_MACBUNDLE_H
#define PMPRO_MACBUNDLE_H
#include <stdbool.h>
#include <stddef.h>
/* If exe is "<dir>.app/Contents/MacOS/<name>", write "<dir>.app/Contents" to out. */
bool pmpro_bundle_contents(const char *exe, char *out, size_t n);
/* malloc'd copy of src with every "@BUNDLE@" replaced by contents (NULL on OOM). */
char *pmpro_expand_bundle_token(const char *src, const char *contents);
#endif
