/* hidraw.h — transport for the FURUI NFC PM-Pro (FR-RATEL, USB 1629:1831).
 *
 * The device exposes a vendor HID interface (Usage Page 0xFF00) with a single
 * 64-byte Output report (host->device) and 64-byte Input report (device->host),
 * no report IDs. On Linux this is reachable directly through /dev/hidrawN with
 * plain read()/write() — no libusb/hidapi needed.
 */
#ifndef PMPRO_HIDRAW_H
#define PMPRO_HIDRAW_H

#include <stddef.h>
#include <stdbool.h>

#define PMPRO_VID 0x1629
#define PMPRO_PID 0x1831
#define PMPRO_REPORT_LEN 64

typedef struct {
    int fd;             /* -1 when closed */
    char path[64];      /* e.g. /dev/hidraw2 */
    char err[256];      /* last error message */
} pmpro_dev;

/* Find the device node by USB VID:PID. Returns true and fills `path` (size n),
 * or false if not present. Reads world-readable sysfs; no special perms. */
bool pmpro_find(char *path, size_t n);

/* Open the device. Returns true on success. On failure d->err is set and
 * d->fd == -1. Auto-discovers the node if path is NULL. */
bool pmpro_open(pmpro_dev *d, const char *path);

void pmpro_close(pmpro_dev *d);

/* Send one output report. `data`/`len` are padded/truncated to 64 bytes; the
 * required leading report-id byte (0x00) is added internally. Returns true on
 * success. */
bool pmpro_write(pmpro_dev *d, const unsigned char *data, size_t len);

/* Read one input report (up to 64 bytes) into `buf` (>=64). Waits up to
 * timeout_ms. Returns bytes read, 0 on timeout, -1 on error. */
int pmpro_read(pmpro_dev *d, unsigned char *buf, int timeout_ms);

#endif /* PMPRO_HIDRAW_H */
