/* hidraw_macos.c — macOS IOHIDManager transport for the FURUI PM-Pro.
 *
 * One I/O thread runs a CFRunLoop on which the device is scheduled; the
 * input-report callback pushes each 64-byte report into a FIFO ring that
 * pmpro_read() pops under a mutex/condvar. Output goes through
 * IOHIDDeviceSetReport (report id 0, no prefix byte). */
#include "hidraw.h"
#include <IOKit/hid/IOHIDManager.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RINGN 64   /* input report ring capacity (reports) */

struct backend {
    IOHIDManagerRef mgr;
    IOHIDDeviceRef  dev;
    pthread_t       io_thread;
    CFRunLoopRef    rl;              /* I/O thread's run loop (set by thread) */
    pthread_mutex_t m;
    pthread_cond_t  cv;              /* new report, removal or stop */
    pthread_cond_t  rl_ready;        /* signalled once rl is set */
    unsigned char   ring[RINGN][PMPRO_REPORT_LEN];
    int             head, tail, count;
    bool            removed;         /* device went away (guarded by m) */
    bool            stop;            /* close requested (guarded by m) */
    unsigned char   inbuf[PMPRO_REPORT_LEN];
};

static CFDictionaryRef match_dict(void)
{
    int vid = PMPRO_VID, pid = PMPRO_PID, page = 0xFF00;
    CFNumberRef v = CFNumberCreate(NULL, kCFNumberIntType, &vid);
    CFNumberRef p = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    CFNumberRef u = CFNumberCreate(NULL, kCFNumberIntType, &page);
    const void *keys[] = { CFSTR(kIOHIDVendorIDKey), CFSTR(kIOHIDProductIDKey),
                           CFSTR(kIOHIDPrimaryUsagePageKey) };
    const void *vals[] = { v, p, u };
    CFDictionaryRef d = CFDictionaryCreate(NULL, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (v) CFRelease(v);
    if (p) CFRelease(p);
    if (u) CFRelease(u);
    return d;
}

/* Create a manager restricted to the PM-Pro vendor interface. */
static IOHIDManagerRef make_manager(void)
{
    IOHIDManagerRef mgr = IOHIDManagerCreate(NULL, kIOHIDOptionsTypeNone);
    if (!mgr) return NULL;
    CFDictionaryRef md = match_dict();
    if (!md) { CFRelease(mgr); return NULL; }
    IOHIDManagerSetDeviceMatching(mgr, md);
    CFRelease(md);
    return mgr;
}

/* Return a retained reference to the first matching device, or NULL. */
static IOHIDDeviceRef first_device(IOHIDManagerRef mgr)
{
    CFSetRef set = IOHIDManagerCopyDevices(mgr);
    if (!set) return NULL;
    IOHIDDeviceRef dev = NULL;
    CFIndex n = CFSetGetCount(set);
    if (n > 0) {
        const void **vals = malloc((size_t)n * sizeof *vals);
        if (vals) {
            CFSetGetValues(set, vals);          /* array sized for all members */
            dev = (IOHIDDeviceRef)vals[0];
            CFRetain(dev);
            free(vals);
        }
    }
    CFRelease(set);
    return dev;
}

bool pmpro_find(char *path, size_t n)
{
    IOHIDManagerRef mgr = make_manager();
    if (!mgr) return false;
    bool found = false;
    if (IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone) == kIOReturnSuccess) {
        IOHIDDeviceRef dev = first_device(mgr);
        if (dev) {
            found = true;
            CFRelease(dev);
        }
        IOHIDManagerClose(mgr, kIOHIDOptionsTypeNone);
    }
    if (found && path && n)
        snprintf(path, n, "FURUI PM-Pro (%04X:%04X)", PMPRO_VID, PMPRO_PID);
    CFRelease(mgr);
    return found;
}

/* input-report callback: runs on the I/O thread's run loop */
static void input_cb(void *ctx, IOReturn res, void *sender,
                     IOHIDReportType type, uint32_t rid,
                     uint8_t *report, CFIndex len)
{
    (void)sender; (void)type; (void)rid;
    struct backend *be = ctx;
    if (res != kIOReturnSuccess || len <= 0) return;
    pthread_mutex_lock(&be->m);
    if (be->count < RINGN) {
        size_t c = (size_t)len < PMPRO_REPORT_LEN ? (size_t)len : PMPRO_REPORT_LEN;
        memset(be->ring[be->tail], 0, PMPRO_REPORT_LEN);
        memcpy(be->ring[be->tail], report, c);
        be->tail = (be->tail + 1) % RINGN;
        be->count++;
        pthread_cond_signal(&be->cv);
    } /* else: drop — ring full; session resyncs on next command */
    pthread_mutex_unlock(&be->m);
}

static void removal_cb(void *ctx, IOReturn res, void *sender)
{
    (void)res; (void)sender;
    struct backend *be = ctx;
    pthread_mutex_lock(&be->m);
    be->removed = true;
    pthread_cond_broadcast(&be->cv);
    pthread_mutex_unlock(&be->m);
}

static void *io_main(void *arg)
{
    struct backend *be = arg;
    CFRunLoopRef rl = CFRunLoopGetCurrent();
    IOHIDDeviceScheduleWithRunLoop(be->dev, rl, kCFRunLoopDefaultMode);

    pthread_mutex_lock(&be->m);
    be->rl = rl;
    pthread_cond_signal(&be->rl_ready);
    bool stop = be->stop;
    pthread_mutex_unlock(&be->m);

    while (!stop) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, true);
        pthread_mutex_lock(&be->m);
        stop = be->stop;
        pthread_mutex_unlock(&be->m);
    }
    IOHIDDeviceUnscheduleFromRunLoop(be->dev, rl, kCFRunLoopDefaultMode);
    return NULL;
}

static const char *denied_hint(IOReturn r)
{
    return (r == kIOReturnNotPermitted || r == kIOReturnNotPrivileged)
        ? " — HID access denied; you may need to grant this app Input "
          "Monitoring in System Settings > Privacy & Security, then retry"
        : "";
}

bool pmpro_open(pmpro_dev *d, const char *path)
{
    (void)path;                      /* macOS matches by VID:PID, not a node path */
    d->fd = -1; d->err[0] = '\0'; d->backend = NULL;
    snprintf(d->path, sizeof d->path, "FURUI PM-Pro (%04X:%04X)",
             PMPRO_VID, PMPRO_PID);

    IOHIDManagerRef mgr = make_manager();
    if (!mgr) {
        snprintf(d->err, sizeof d->err, "IOHIDManagerCreate failed");
        return false;
    }

    IOReturn r = IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone);
    if (r != kIOReturnSuccess) {
        snprintf(d->err, sizeof d->err,
                 "IOHIDManagerOpen failed (IOReturn 0x%x)%s", (unsigned)r,
                 denied_hint(r));
        CFRelease(mgr);
        return false;
    }

    IOHIDDeviceRef dev = first_device(mgr);
    if (!dev) {
        snprintf(d->err, sizeof d->err,
                 "PM-Pro (%04X:%04X) not found — is it plugged in?",
                 PMPRO_VID, PMPRO_PID);
        IOHIDManagerClose(mgr, kIOHIDOptionsTypeNone);
        CFRelease(mgr);
        return false;
    }

    r = IOHIDDeviceOpen(dev, kIOHIDOptionsTypeNone);
    if (r != kIOReturnSuccess) {
        snprintf(d->err, sizeof d->err,
                 "IOHIDDeviceOpen failed (IOReturn 0x%x)%s", (unsigned)r,
                 denied_hint(r));
        CFRelease(dev);
        IOHIDManagerClose(mgr, kIOHIDOptionsTypeNone);
        CFRelease(mgr);
        return false;
    }

    struct backend *be = calloc(1, sizeof *be);
    if (!be) {
        snprintf(d->err, sizeof d->err, "out of memory");
        goto fail_close;
    }
    be->mgr = mgr; be->dev = dev;
    pthread_mutex_init(&be->m, NULL);
    pthread_cond_init(&be->cv, NULL);
    pthread_cond_init(&be->rl_ready, NULL);

    IOHIDDeviceRegisterInputReportCallback(dev, be->inbuf, PMPRO_REPORT_LEN,
                                           input_cb, be);
    IOHIDDeviceRegisterRemovalCallback(dev, removal_cb, be);

    if (pthread_create(&be->io_thread, NULL, io_main, be) != 0) {
        snprintf(d->err, sizeof d->err, "pthread_create failed");
        IOHIDDeviceRegisterInputReportCallback(dev, be->inbuf,
                                               PMPRO_REPORT_LEN, NULL, NULL);
        IOHIDDeviceRegisterRemovalCallback(dev, NULL, NULL);
        pthread_cond_destroy(&be->cv);
        pthread_cond_destroy(&be->rl_ready);
        pthread_mutex_destroy(&be->m);
        free(be);
        goto fail_close;
    }
    /* wait for the I/O thread to publish its run loop */
    pthread_mutex_lock(&be->m);
    while (!be->rl) pthread_cond_wait(&be->rl_ready, &be->m);
    pthread_mutex_unlock(&be->m);

    d->backend = be;
    d->fd = 0;                        /* open sentinel for consumers */
    return true;

fail_close:
    IOHIDDeviceClose(dev, kIOHIDOptionsTypeNone);
    CFRelease(dev);
    IOHIDManagerClose(mgr, kIOHIDOptionsTypeNone);
    CFRelease(mgr);
    return false;
}

bool pmpro_is_gone(const pmpro_dev *d)
{
    struct backend *be = d->backend;
    if (!be) return true;
    pthread_mutex_lock(&be->m);
    bool gone = be->removed;
    pthread_mutex_unlock(&be->m);
    return gone;
}

void pmpro_close(pmpro_dev *d)
{
    struct backend *be = d->backend;
    d->fd = -1;
    d->backend = NULL;
    if (!be) return;

    pthread_mutex_lock(&be->m);
    be->stop = true;
    pthread_cond_broadcast(&be->cv);   /* wake any blocked reader */
    pthread_mutex_unlock(&be->m);
    CFRunLoopStop(be->rl);
    pthread_join(be->io_thread, NULL);

    /* thread gone: no callback can fire now; detach them before teardown */
    IOHIDDeviceRegisterInputReportCallback(be->dev, be->inbuf,
                                           PMPRO_REPORT_LEN, NULL, NULL);
    IOHIDDeviceRegisterRemovalCallback(be->dev, NULL, NULL);
    IOHIDDeviceClose(be->dev, kIOHIDOptionsTypeNone);
    CFRelease(be->dev);
    IOHIDManagerClose(be->mgr, kIOHIDOptionsTypeNone);
    CFRelease(be->mgr);
    pthread_cond_destroy(&be->cv);
    pthread_cond_destroy(&be->rl_ready);
    pthread_mutex_destroy(&be->m);
    free(be);
}

bool pmpro_write(pmpro_dev *d, const unsigned char *data, size_t len)
{
    struct backend *be = d->backend;
    if (!be) {
        snprintf(d->err, sizeof d->err, "write: device not open");
        return false;
    }
    pthread_mutex_lock(&be->m);
    bool gone = be->removed;
    pthread_mutex_unlock(&be->m);
    if (gone) {
        snprintf(d->err, sizeof d->err, "write: device removed");
        return false;
    }

    unsigned char buf[PMPRO_REPORT_LEN];
    pmpro_fill_report(buf, data, len);      /* 64 bytes, NO report-id prefix */

    IOReturn r = IOHIDDeviceSetReport(be->dev, kIOHIDReportTypeOutput,
                                      0 /*reportID*/, buf, sizeof buf);
    if (r != kIOReturnSuccess) {
        snprintf(d->err, sizeof d->err, "SetReport failed (IOReturn 0x%x)",
                 (unsigned)r);
        return false;
    }
    return true;
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int pmpro_read(pmpro_dev *d, unsigned char *buf, int timeout_ms)
{
    struct backend *be = d->backend;
    if (!be) return -1;

    /* timeout_ms < 0: wait forever (poll(-1) semantics); 0: non-blocking poll */
    bool infinite = timeout_ms < 0;
    long long deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    int ret;

    pthread_mutex_lock(&be->m);
    while (be->count == 0 && !be->removed && !be->stop) {
        if (infinite) {
            int rc = pthread_cond_wait(&be->cv, &be->m);
            if (rc != 0) { ret = -1; goto out; }
            continue;
        }
        long long left = deadline - now_ms();
        if (left <= 0) { ret = 0; goto out; }          /* timeout (or poll) */
        struct timespec rel = {
            .tv_sec  = (time_t)(left / 1000),
            .tv_nsec = (long)(left % 1000) * 1000000L,
        };
        int rc = pthread_cond_timedwait_relative_np(&be->cv, &be->m, &rel);
        if (rc != 0 && rc != ETIMEDOUT) { ret = -1; goto out; }
    }
    if (be->count == 0) {           /* removal/stop with nothing queued */
        ret = (be->removed || be->stop) ? -1 : 0;
        goto out;
    }
    memcpy(buf, be->ring[be->head], PMPRO_REPORT_LEN);
    be->head = (be->head + 1) % RINGN;
    be->count--;
    ret = PMPRO_REPORT_LEN;
out:
    pthread_mutex_unlock(&be->m);
    return ret;
}
