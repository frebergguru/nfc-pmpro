# NFC PM-Pro — open companion app

An independent Linux companion/replacement for the **FURUI NFC PM-Pro** (`FR-RATEL`,
USB `1629:1831`) RFID reader/writer/copier — built in C with a GTK4/libadwaita GUI,
talking to the device over its native (reverse-engineered) HID protocol. No vendor
software, no Wine needed at runtime.

## What works (all verified on real hardware unless noted)
- **Connect** — identify + RC4 handshake.
- **Read HF** (13.56 MHz, ISO14443A) — UID/type, and a per-sector dump with a
  chosen key.
- **Read / Write / Clone Mifare sectors** — read sectors with a key, write a
  sector, and clone a buffered card to a blank (auto-restoring the trailer key).
- **Read / Write LF** (125 kHz, EM4100/T5577/EM4305) and **HID prox** (read/write).
  LF reads decode the EM4100 customer/card number + fob text.
- **Save / Load dump** — save a read card to a `.pmdump`, or load one back into
  the buffer to write to a blank.
- **Crack** — four Mifare key attacks, plus whole-card autopwn:
  - **Dictionary** (cmd 13) — tries common/default keys; returns the one that
    authenticates. *(verified live)*
  - **Nested** (cmd 14) — the classic mfoc attack: with one known/default
    sector key (auto-found via the dictionary) it recovers the rest via
    Crypto-1 + nonce-distance, confirmed on-card. **Verified: cracked a real
    fob's 7 unknown sector keys, ~10–30 s each.**
  - **Darkside** (cmd 15) — collect + Crypto-1 solve + on-card confirm; for
    cards vulnerable to the parity-leak (hardened cards are reported as such).
  - **Hardnested** — the full **mfoc-hardnested** solver ported to pure C
    (AVX512/AVX2/SSE2/NOSIMD, 16-thread, ~5 G keys/s), fed by the device's
    nonce collection (cmd 0x30); auto-finds a foothold via the dictionary, like
    mfoc. *(solver runs; end-to-end needs a hardened card with a foothold key)*
  - **Autopwn → .mfd** — dictionary + nested across every sector, then reads the
    whole card and writes a raw **`.mfd`** dump (recovered keys in the trailers),
    loadable by standard Mifare tools. *(verified: full 1K fob dumped, 16/16
    sectors keyed and read)*
- **Format** a sector, **beep** (with a mute toggle), **LED/openfind**, **save
  dumps**, raw **console** (send a payload; see the decrypted reply).

The protocol (RC4 + CRC-16/CCITT + framing, full command table) is documented in
[PROTOCOL.md](PROTOCOL.md). It was recovered from the official `PM_Pro.exe`
(decompiled with ilspycmd) and verified against the live device.

> Not ported (by choice): firmware update (bricking risk), hotel-card presets, and
> agreements for other device models. The Crypto-1 cipher + solver have self-tests
> (`ctest`).

## Build
Needs `gtk4`, `libadwaita`, a C compiler, CMake/Ninja. The device I/O is pure
`/dev/hidraw` — no libusb/hidapi.
```sh
cmake -G Ninja -S . -B build && ninja -C build
./build/pmpro           # GUI
./build/pmctl connect   # CLI: connect+beep
./build/pmctl readic    # CLI: read a 13.56 MHz card
```

## Device access (one-time)
The HID node is root-only by default. Install the udev rule:
```sh
sudo cp tools/99-pmpro.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules && sudo udevadm trigger
# then unplug/replug the device
```

## Layout
- `src/furui.[ch]` — RC4 cipher, CRC16, packet framing.
- `src/session.[ch]` — connect handshake, command exec (multi-report send/recv + decrypt).
- `src/hidraw.[ch]` — dependency-free hidraw transport (auto-discovers the device).
- `src/app.c` — GTK4/libadwaita GUI.
- `src/pmctl.c` — CLI. `src/probe.c` — low-level RE probe.
- `tools/` — `extract_costura.py` (pull DLLs from the .NET exe), `parse_usbmon.py`,
  Ghidra decompile script.

## Responsible use
This device and app read/write/clone RFID/NFC cards and include Mifare key-recovery.
Use **only** on cards and systems you own or are explicitly authorized to test
(your own access cards, hotel/office administration you manage, security research
with permission). Cloning credentials you don't own may be illegal.

## License
`src/crypto1.c` ports **crapto1** (bla <blapost@gmail.com> & Proxmark3
contributors) and `src/hardnested/` vendors the **mfoc-hardnested** solver
(piwi/Proxmark3 + nfc-tools) — both **GPL** — so this project as a whole is
distributed under **GPLv3**. The vendored solver is decoupled from libnfc; nonce
collection comes from the PM-Pro (cmd 0x30) via `src/hardnested_glue.c`.

See **[LICENSE](LICENSE)** for the full GPLv3 text, **[NOTICE](NOTICE)** for
third-party attribution and provenance (all other `src/` code is original, written
from `PROTOCOL.md` — no decompiled vendor code is included), and
**[DISCLAIMER](DISCLAIMER)** for intended/authorized use.
