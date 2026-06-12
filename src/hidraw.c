#include "hidraw.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Match a hidraw device's uevent against our VID:PID.
 * The HID_ID line looks like: HID_ID=0003:00001629:00001831 */
static bool uevent_matches(const char *uevent_path)
{
    FILE *f = fopen(uevent_path, "r");
    if (!f)
        return false;

    char want[32];
    snprintf(want, sizeof want, "%08X:%08X", PMPRO_VID, PMPRO_PID);

    char line[256];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "HID_ID=", 7) == 0) {
            /* case-insensitive search for the VID:PID tail */
            for (char *p = line; *p; ++p) {
                char a = *p;
                if (a >= 'a' && a <= 'f')
                    *p = a - 32; /* upper-case hex */
            }
            if (strstr(line, want))
                found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

bool pmpro_find(char *path, size_t n)
{
    DIR *d = opendir("/sys/class/hidraw");
    if (!d)
        return false;

    bool found = false;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "hidraw", 6) != 0)
            continue;
        char uevent[512];
        snprintf(uevent, sizeof uevent,
                 "/sys/class/hidraw/%s/device/uevent", e->d_name);
        if (uevent_matches(uevent)) {
            snprintf(path, n, "/dev/%s", e->d_name);
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

bool pmpro_open(pmpro_dev *d, const char *path)
{
    d->fd = -1;
    d->err[0] = '\0';
    d->path[0] = '\0';

    if (path) {
        snprintf(d->path, sizeof d->path, "%s", path);
    } else if (!pmpro_find(d->path, sizeof d->path)) {
        snprintf(d->err, sizeof d->err,
                 "PM-Pro (1629:1831) not found — is it plugged in?");
        return false;
    }

    int fd = open(d->path, O_RDWR);
    if (fd < 0) {
        snprintf(d->err, sizeof d->err, "open %s: %s%s", d->path,
                 strerror(errno),
                 errno == EACCES
                     ? "  (install tools/99-pmpro.rules, then replug)"
                     : "");
        return false;
    }
    d->fd = fd;
    return true;
}

void pmpro_close(pmpro_dev *d)
{
    if (d->fd >= 0)
        close(d->fd);
    d->fd = -1;
}

bool pmpro_write(pmpro_dev *d, const unsigned char *data, size_t len)
{
    if (d->fd < 0) {
        snprintf(d->err, sizeof d->err, "write: device not open");
        return false;
    }
    /* leading report-id byte (0x00, unnumbered) + 64 data bytes */
    unsigned char buf[1 + PMPRO_REPORT_LEN];
    memset(buf, 0, sizeof buf);
    if (len > PMPRO_REPORT_LEN)
        len = PMPRO_REPORT_LEN;
    memcpy(buf + 1, data, len);

    ssize_t w = write(d->fd, buf, sizeof buf);
    if (w < 0) {
        snprintf(d->err, sizeof d->err, "write %s: %s", d->path,
                 strerror(errno));
        return false;
    }
    return true;
}

int pmpro_read(pmpro_dev *d, unsigned char *buf, int timeout_ms)
{
    if (d->fd < 0)
        return -1;

    struct pollfd pfd = {.fd = d->fd, .events = POLLIN};
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr < 0)
        return errno == EINTR ? 0 : -1;
    if (pr == 0)
        return 0; /* timeout */

    ssize_t r = read(d->fd, buf, PMPRO_REPORT_LEN);
    if (r < 0)
        return errno == EAGAIN ? 0 : -1;
    return (int)r;
}
