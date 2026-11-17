/* hidraw.h — transport for the FURUI NFC PM-Pro (FR-RATEL, USB 1629:1831).
 *
 * The device exposes a vendor HID interface (Usage Page 0xFF00) with a single
 * 64-byte Output report (host->device) and 64-byte Input report (device->host),
 * no report IDs. No libusb/hidapi is needed: the Linux backend uses
 * /dev/hidrawN with plain read()/write(); the macOS backend uses the system
 * IOKit HID framework.
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
    char path[64];      /* device identifier, e.g. /dev/hidraw2 on Linux */
    char err[256];      /* last error message */
    void *backend;      /* platform-private; NULL on Linux */
} pmpro_dev;

/* Find the device by USB VID:PID (sysfs on Linux, IOHIDManager on macOS).
 * Returns true and fills `path` (size n) with a human-readable device
 * identifier, or false if not present. */
bool pmpro_find(char *path, size_t n);

/* Open the device. Returns true on success. On failure d->err is set and
 * d->fd == -1. Auto-discovers the node if path is NULL. */
bool pmpro_open(pmpro_dev *d, const char *path);

void pmpro_close(pmpro_dev *d);

/* True if the device is no longer usable: never opened/closed, or unplugged
 * (macOS: IOKit removal callback fired; Linux: node vanished). Callers should
 * pmpro_close() and reopen. */
bool pmpro_is_gone(const pmpro_dev *d);

/* Send one output report. `data`/`len` are padded/truncated to 64 bytes; the
 * unnumbered report-id (0x00) is handled internally (prepended to the write
 * on Linux, passed separately to the HID API on macOS). Returns true on
 * success. */
bool pmpro_write(pmpro_dev *d, const unsigned char *data, size_t len);

/* Read one input report (up to 64 bytes) into `buf` (>=64). Waits up to
 * timeout_ms. Returns bytes read, 0 on timeout, -1 on error. */
int pmpro_read(pmpro_dev *d, unsigned char *buf, int timeout_ms);

/* Zero-fill dst (PMPRO_REPORT_LEN bytes), copy min(len,64) bytes from src.
 * Returns bytes copied. src may be NULL only when len==0. Pure; no I/O. */
size_t pmpro_fill_report(unsigned char dst[64], const unsigned char *src, size_t len);

#endif /* PMPRO_HIDRAW_H */
