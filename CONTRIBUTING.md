# Contributing

Thanks for your interest in the open NFC PM-Pro companion app. This is a small C
project; the notes below should get you productive quickly.

## Scope & responsible use

This app reads, writes, and clones RFID/NFC cards and includes Mifare Crypto-1 key
recovery. Contributions must keep the project aimed at **legitimate, authorized
use** — your own cards, systems you administer, or security research with
permission. See [DISCLAIMER](DISCLAIMER). Please don't send patches whose only
purpose is to make unauthorized cloning easier (e.g. presets for specific
real-world access systems).

Deliberately **out of scope** (don't add these): firmware update (bricking risk),
hotel-card presets, and agreements for other FURUI device models. Irreversible
operations (e.g. Mifare Lock) are intentionally omitted.

## Building & testing

See [README.md](README.md#build) for the dependency packages. Then:

```sh
cmake -G Ninja -S . -B build && ninja -C build
ctest --test-dir build --output-on-failure
```

`ctest` runs the Crypto-1 cipher, key-recovery, dump/protocol, and NDEF self-tests.
**Keep it green** — any change to `src/crypto1.c`, `src/nested.c`, `src/dump.c`, or
`src/ndef.c` should pass the existing tests, and new protocol/parsing logic should
come with a test in `tests/`.

A clean build is warning-free; please don't introduce new compiler warnings.

## Testing against hardware

Most logic can be exercised without the device, but protocol-facing changes should
be verified against a real FR-RATEL where possible. `./build/pmctl` is the quickest
way to do that — `pmctl connect`, `pmctl identify`, `pmctl readic`, `pmctl rawcmd
<hex>`, etc. The **Console** tab does the same from the GUI. When you verify a
change on-device, say so in the PR (which card/UID, what you observed).

If you touch the wire protocol, update [PROTOCOL.md](PROTOCOL.md) to match.

## Code style

- C, matching the surrounding code: 4-space indent, lower_snake_case, `furui_` /
  `cr1_` / `pmpro_` prefixes per module.
- The layers are deliberate — keep transport (`hidraw`), framing/cipher (`furui`),
  session/commands (`session`), and UI (`app` / `pmctl`) separated. New device
  commands go through `furui_exec` / the `session` layer, not raw `hidraw` writes.
- No new runtime dependencies without discussion; device I/O stays on `/dev/hidraw`
  (no libusb/hidapi).

## Licensing

The project is **GPLv3** (because `src/crypto1.c` is crapto1-derived and
`src/hardnested/` vendors mfoc-hardnested). By contributing you agree your changes
are licensed under GPLv3. All original `src/` code is written from `PROTOCOL.md` —
**do not paste decompiled vendor code** into the tree. See [NOTICE](NOTICE) for
third-party provenance.

## Pull requests

- One logical change per PR; keep the working tree clean (build output and card
  dumps — `*.mfd` / `*.pmdump` — are gitignored).
- Describe what you changed, why, and how you tested it (including on-device).
