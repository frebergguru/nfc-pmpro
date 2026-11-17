# macOS notes

The device transport (`src/hidraw_macos.c`) uses IOKit `IOHIDManager` instead of
Linux `/dev/hidraw`. The public API in `src/hidraw.h` is the same on both.

## Build

```sh
brew install cmake ninja xz
cmake -G Ninja -S . -B build -DPMPRO_GUI=OFF
ninja -C build pmctl pmprobe
```

The CLI needs no pkg-config: liblzma is found through CMake's `FindLibLZMA`.
The GUI (`-DPMPRO_GUI=ON`) additionally needs `pkg-config gtk4 libadwaita`.

## Install as an app

Build a self-contained, drag-to-install app (Apple Silicon):

    brew install cmake ninja pkg-config gtk4 libadwaita librsvg adwaita-icon-theme   # build machine only
    cmake -G Ninja -S . -B build-gui -DPMPRO_GUI=ON
    ninja -C build-gui macos-dmg      # → build-gui/pmpro-<version>-arm64.dmg

Open the DMG and drag **NFC PM-Pro** to Applications. The app bundles its own
GTK4/libadwaita, so the target Mac needs no Homebrew (verified on the build Mac:
the bundle loads no Homebrew libraries). The app also bundles the Adwaita
symbolic icons its tabs and buttons use. `pmctl` is included at
`"/Applications/NFC PM-Pro.app/Contents/MacOS/pmctl"`.

The app is ad-hoc signed, not notarized: on another Mac the first launch needs
right-click → **Open** (or `xattr -dr com.apple.quarantine "/Applications/NFC PM-Pro.app"`).
arm64 only. The minimum macOS is that of the bundled Homebrew libraries — see
`LSMinimumSystemVersion` in the app's Info.plist (26.0 when built on macOS 26).

Because the app is ad-hoc signed, if Connect fails with an access error, enable
NFC PM-Pro under System Settings → Privacy & Security → Input Monitoring, and
re-grant it after installing a rebuilt app (ad-hoc grants are tied to the build).

## Architecture

- `pmpro_open` creates an `IOHIDManager`, matches the device, opens it, and
  starts one I/O thread. That thread runs a CoreFoundation run loop so the
  input-report callback can fire.
- The callback pushes each 64-byte input report into a FIFO ring (64 slots)
  guarded by a mutex and condition variable. Order and report boundaries are
  preserved; reports are never coalesced.
- `pmpro_read` pops exactly one report per call, waiting up to `timeout_ms`.
  It returns the byte count on success, `0` on timeout, and `-1` on error or
  device removal (so a timeout is never reported as an error). `timeout_ms == 0`
  is a non-blocking poll and a negative value waits indefinitely (like
  `poll(-1)`), still waking on removal or close. Queued reports are drained
  before removal is reported.
- `pmpro_write` sends one 64-byte output report with `IOHIDDeviceSetReport`.

### Why no report-id byte

The device uses no HID report IDs. On Linux, a `write()` to `/dev/hidrawN` must
start with a report-id byte (`0x00`), which the Linux backend prepends. On macOS,
the report ID is a separate argument to `IOHIDDeviceSetReport` (passed as `0`),
and input callbacks deliver the payload without a leading ID. The macOS backend
therefore sends and receives exactly 64 bytes with no prefix.

### Interface matching

The device is matched by VID:PID and Usage Page `0xFF00` (the vendor interface
documented in `hidraw.h`), so a keyboard or other HID interface on the same
device is never selected. If several matches exist, one is chosen.

## Input Monitoring (TCC)

macOS gates keyboard/mouse-class HID input behind the *Input Monitoring*
permission. Verified on macOS 26 / Apple Silicon: this vendor-page device
opened from Terminal with **no** grant and no prompt. If the open fails with
`kIOReturnNotPermitted`/`kIOReturnNotPrivileged`, the error message says you
*may* need Input Monitoring. Note that inside a sandboxed process `IOHIDManagerOpen` returns `0xe00002e2`
(`kIOReturnNotPermitted`): that is the sandbox, not TCC, and granting Input
Monitoring does not fix it. If it is a real TCC denial:

1. Enable your terminal (or the `pmctl` binary) in **System Settings → Privacy
   & Security → Input Monitoring**.
2. Restart the terminal and retry.

To reset the decision: `tccutil reset ListenEvent`.

### Codesigning

TCC identifies a binary by its code signature. An unsigned (or ad-hoc-signed)
binary that is rebuilt gets a new identity, so a grant given to the old build may
need to be given again. Granting the terminal app avoids this for CLI use.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `IOReturn 0xe00002e2` (`kIOReturnNotPermitted`) | Either Input Monitoring is not granted (grant it, restart the terminal), or the process runs inside a sandbox, which blocks HID open regardless of TCC — run outside the sandbox. |
| `IOReturn 0xe00002c1` (`kIOReturnNotPrivileged`) | Also mapped to the Input Monitoring message. Same fix; check no other app holds the device exclusively. |
| "PM-Pro (VID:PID) not found — is it plugged in?" | Reader not attached, or no interface with Usage Page `0xFF00`. Check `system_profiler SPUSBDataType` for `1629:1831`; try another cable/port. |
| Reads keep timing out (`0`) | Normal when no card is present or the device is silent; `connect` should still succeed. Persistent timeouts after a command: re-seat the reader. |
| `pmpro_read` returns `-1` | Device removed or an I/O error. The command fails within ~0.1 s; replug and the next command works. |

## Apple Silicon / non-x86

The hardnested attack's SSE2/AVX cores are x86-only. On Apple Silicon and other
non-x86 targets the build uses the portable NOSIMD cores (`X86_SIMD` is not
defined). It works, but hardnested is slower there than on x86 with AVX.

## Status

- Verified: the CLI builds on macOS (arm64) and the offline tests pass.
- Verified on hardware (macOS 26, Apple Silicon): `pmctl connect` (handshake
  ~0.5 s), `identify`, `readid`, `readic`; an EM4100 LF card reads correctly;
  no-tag timeouts return without hanging; unplugging mid-command fails the
  command within ~0.1 s and the next command after replug works.
- Multi-report replies: a MIFARE Classic 1K reads all 16 full 64-byte sectors
  (`readkey`, `dumphf`) — reports arrive in order with intact boundaries.
- Verified on macOS 26 / Apple Silicon: the GTK GUI builds and runs (build tree
  and packaged app), connects to the reader and reads cards, and reopens the
  device after an unplug. Prerequisites: `brew install pkg-config gtk4 libadwaita
  librsvg adwaita-icon-theme`.
- Verified: `NFC PM-Pro.app` installed from the DMG into /Applications and launched
  from Launchpad works — tab icons render, it connects and reads cards.
