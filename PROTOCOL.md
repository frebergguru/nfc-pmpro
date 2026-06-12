# FURUI NFC PM-Pro — USB Protocol (reverse-engineered)

Device: **FR-RATEL**, USB **VID 0x1629 / PID 0x1831**. Reverse-engineered from the
official `PM_Pro.exe` (.NET, Costura-packed): assemblies `FuRuiTalkHelper`
(cipher) and `DeviceAgreement` (`FrratelAgreement*`), cross-checked live.

## Transport
- USB **HID**, vendor usage page `0xFF00`. Interface 0, 64-byte interrupt reports
  (`EP 0x01 OUT`, `EP 0x81 IN`), no report IDs. On Linux: `/dev/hidrawN`.
- Each report on the wire is `[0x00 report-id][64 payload bytes]` (65 bytes written).
- Interface 1 is USB mass-storage (ships the installer); ignore for protocol.

## Packet framing (`addPackLengthAndCRC`)
Plaintext packet, before encryption:
```
[len_lo][len_hi] [payload ...] [crc_lo][crc_hi]
```
- `len` = **total packet length** including the 2 length and 2 CRC bytes, little-endian.
- `crc` = **CRC-16/CCITT** (poly `0x1021`, init `0x0000`, MSB-first, no final xor),
  computed over `[len_lo][len_hi][payload]`, stored little-endian.
- The framed packet is zero-padded to a multiple of 64 bytes, then encrypted.

## Encryption — RC4 (`FuruiTalkInit` / `FuruiTalkEncDec`)
Plain **RC4**, symmetric (encrypt == decrypt), applied over the whole padded packet.
- Key = `deviceKey` (4 bytes `B6 69 8A 37`) **+ 8 constant bytes** `40 A3 79 84 9B F5 6D 16`
  → effective 12-byte key. KSA mixes `key[i % 12]`.
- Multi-report responses: read all reports first, then RC4-decrypt the concatenated
  ciphertext as one continuous stream. (To learn the length, decrypt a copy of the
  first report; `len` is plaintext bytes [0:2].)

## Response convention
Decrypted response = `[len][code][...]`. **`payload[0]` (== decrypted byte[2]) is the
status/echoed-code; `0x01` means ACK/success.** `0x00` typically means "no card".

## Commands (FR-RATEL family, `FrratelAgreement<code>`)
Payloads below are the plaintext **before** framing+encryption.

| code | operation            | payload (plaintext)                              | notes |
|------|----------------------|--------------------------------------------------|-------|
| `06` | identify / find      | `06`                                             | ack only |
| `01` | handshake (2-step)   | `01 01 00 14 0F 04 90 14 00 00`                  | ver=1, packsize=5120(LE), `0F 04`, pcRandom=5264(LE). Resp: [4:6]=device packsize, [8:12]=pcRandom echo (5264), [12:16]=device random. Step 2: `01` + device-random(LE 4) |
| `09` | beep                 | `09 <type> <count>` (default `09 01 02`)         | audible |
| `0F` | open find / LED      | `0F`                                             | |
| `21` | read HF (ISO14443A)  | `21`                                             | resp data = UID + ATQA(2) + a trailing `00`, e.g. `fb be 05 9f 04 00 00` (ATQA `0004`). **The trailing byte is NOT the SAK** — the real SAK is block 0 byte 5 (read it with cmd `17`). 7-byte-UID cards come back as cascade level 1 only (`88`+3 UID bytes), so the device never reports their full UID/SAK |
| `28` | read LF ID (EM4100)  | `28 <Auto> <Frequency>` (e.g. `28 01 00`)        | resp [2]=0 when no LF card. Only reads programmed EM-family IDs; a **blank T5577 reads as no-card**. T5577 is only ever *written* (cmd `2D`), never read specially |
| `29` | read HID prox        | `29`                                             | |
| `2D` | write LF ID          | `2D <Freq> <CardID×4> <PlantID>`                 | T5577/EM4305 |
| `2E` | write HID prox       | `2E <CardID×12>`                                 | |
| `10` | activate HF card     | `10`                                             | precedes sector ops |
| `13` | check keys (auth)    | `13 <block> <type> <count> <key×6…>`             | tries the key list; resp payload = the key that authenticated (dictionary attack + verifier) |
| `14` | nested collect       | `14 <fBlock> <fType> <fKey×6> <tBlock> <tType> <DevRandom×4>` (after cmd `10`) | foothold→target nonces: header(uid…) + 15 foothold pairs + 8 target `nt(4) NtEnc(4) par(3)` records. Nonces **little-endian**; the cipher authuid is **big-endian**. Intermittent — retry |
| `15` | darkside collect     | `15 <attBlock> <attType>`                        | resp payload = uid + nonce records (3 bytes only on hardened cards) |
| `16` | format sector        | `16 <sector> <flag> <keyA×6> <keyB×6>`           | flag 1=A,2=B,3=both. Resets the sector (zeros data, keys→default `FF`). **Works on sector 0** — the firmware skips the read-only block 0, so this is the only way to reset sector 0's trailer |
| `17` | read sector          | `17 <sector> <flag> <keyA×6> <keyB×6>`           | resp = `[len][01][status][pad][256 sector bytes]`; **status `0f`=auth OK, `00`=auth fail**. Device returns a fixed 256-byte payload (1K sector = first 64 real + zero pad) |
| `18` | write sector         | `18 <sector> <flag> <keyA×6> <keyB×6> <data×64>` | full 64-byte sector (3 blocks + trailer). **The device ACKs even when the card rejects a block** — verify by read-back. A trailer write needs a key with write rights (often Key B); a whole-sector write to **sector 0 is rejected** (block 0 read-only) — use cmd `16` |
| `1C` | write blank block    | `1C <block> <data×16>`                           | gen1a backdoor block write (no auth); pairs with `1D` |
| `1D` | read blank block     | `1D <block>`                                     | magic/gen1a backdoor read (no auth). **Intermittent** — the device only answers it ~half the time, so retry (the OEM retries too); success = resp `[2]==1` with the real block, failure = a fixed `…14…20…` stub with `[2]==0` |
| `1E`/`1F` | write IC / finalize | `1E <cardData…>` (CardType = `cardData[6]`) then `1F <cardType> <locking> <scroll>` | whole-card (magic) write — the OEM's only magic path; there is **no read-only "is this magic?" command**. gen1a is found via `1D`; gen2/CUID is read-identical to a real card and only shows up by writing block 0 |
| `30` | hardnested collect   | `30 <ckBlock><ckType><ckKey×6><atBlock><atType><atCount><isFirst><DevRandom×4>` | encrypted-nonce stream feeding the hardnested solver |
| `26` | init detect (config) | `26 <Config> <CardID×4> <CardXOR> <ASK> <CardType×2> <CardRandom×4>` | |
| `27` | get detect data      | `27`                                             | resp: [3:5]=count, then `count`×18-byte records |

Connect sequence (official `FindDevice`): **`06` → `01` (two-step) → `06`**.
Mifare sector trailer reads back with **keyA masked to `00`** — restore the key
before re-writing/cloning or the sector becomes inaccessible.

**HF capability is Mifare-Classic-centric.** The whole HF data path is Classic
(auth/sector read-write via `17`/`18`, key recovery via `13`/`14`/`15`/`30`) plus
magic read/write (`1C`/`1D`/`1E`/`1F`) and bare UID/ATQA detection (`21`). There is
**no raw ISO14443 transceive, no GET_VERSION (`0x60`), and no Ultralight/NTAG
page-read** anywhere in the command set — so the Ultralight/NTAG family can't be
split into UL / UL-C / EV1 / NTAG21x (the OEM app has the same limit; it only types
from ATQA+SAK). The `DeviceAgreement` DLL also carries command sets for **sibling
devices** (`Icopy`, `Icopy5`, `OldFrratel`) and "hotel"/T5577 helpers at codes
`0x40`–`0x45`; those return nothing on this PM-Pro (`FR-RATEL`) and are not used.

### Key-recovery ("decode") — the native engine *is* crapto1
The 5 functions in the native DLL `72f1b856-…​.fr` (i386, cdecl) implement Crypto-1
key recovery (`GetDetection/Half/All/FrxStatic/FrxDynamic_Decode_Card_Key`). The
solver is a verbatim port of public **crapto1** (filter constants `0xEC57E80A` /
`0x1e458` / … confirm it), so this project reimplements it cleanly in
`src/crypto1.c` (self-tested) and drives it from cmd 15 nonces, confirming results
via cmd 13. Dual-use; only for cards you own / are authorized to test.

## Verified live
`connect` (06+01+06), `beep` (09), `openfind` (0F), HF read (21 → real UID
`fb be 05 9f …`), LF read/write (28/2D), HID read/write (29/2E), Mifare
read/write/clone (17/18, round-trip + clone match), dictionary attack (13 →
recovered `FF…`), **nested** (14 → cracked a real fob's unknown sector keys, Key A
*and* Key B), darkside collect (15 → "hardened" on a locked card), **format/tag
ops** (16/18 → erase, factory-reset keys→`FF`, set/remove password; trailer writes
fall back to a dict/nested Key B and are confirmed by read-back; sector 0 reset via
cmd `16`). **Identify** (21 + 17 for the real SAK → types Classic 1K/4K/Mini, Plus,
DESFire, Ultralight/NTAG family; auto-probes LF then HID). **Magic test** —
distinguished a genuine Classic 1K from a **gen1a** card (1D backdoor, retried) and
a **gen2/CUID** card (block-0 write-probe: flip a byte, read back, restore), all on
real cards. **Blank T5577 programming** (2D → wrote an EM4100 ID, read it back).
Implemented across `src/{furui,session,crack,nested,crypto1,dump}.c` and driven
from `src/app.c` / `src/pmctl.c`.
