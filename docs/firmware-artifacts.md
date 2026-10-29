# Firmware and binary artefacts

OT challenge sets use two recurring kinds of binary artefact: a **cartridge or
firmware image** that contains a process simulator, and a **legacy 16-bit HMI
binary**. Both reward the same approach: understand the container, map the
regions, then read the data where it lives.

## Game Boy cartridge images (.gb / .gbc)

A Game Boy ROM is a convenient, self-contained way to ship an interactive
"training rig": a plant model with a scan cycle, alarms and a trip condition,
runnable in any emulator. Treat it as firmware.

### Header at 0x0100

| Offset | Field |
|---|---|
| 0x0100-0x0103 | entry point (usually `nop; jp $0150`) |
| 0x0104-0x0133 | Nintendo logo - the boot ROM verifies it byte for byte |
| 0x0134-0x0143 | title (11 bytes + 4-byte manufacturer code on CGB) |
| 0x0143 | CGB flag: 0x80 enhanced, 0xC0 colour-only |
| 0x0147 | **cartridge type** - which mapper (MBC) and whether RAM/battery/RTC |
| 0x0148 | ROM size: `0x01` = 64 KiB / 4 banks, `0x05` = 1 MiB / 64 banks |
| 0x0149 | RAM size (battery-backed save RAM) |
| 0x014D | header checksum - sum rule over 0x0134-0x014C |
| 0x014E-0x014F | global checksum (big-endian, excludes itself) |

A **header checksum mismatch** means someone edited the header; a **global
checksum mismatch with a valid header checksum** means the body was patched -
useful when a challenge ships a "tampered" image.

### Bank layout

ROM is divided into 16 KiB banks. Bank 0 is fixed at `0x0000-0x3FFF`; banks
1..n are switched into `0x4000-0x7FFF` by the memory bank controller (MBC1,
MBC3, MBC5 differ in register layout and maximum size). Practical consequence:
**an address you see in disassembly is not a file offset** - it is
`bank * 0x4000 + (addr - 0x4000)`.

Profile every bank by entropy and string density:

- low entropy, many strings - text tables, menu and alarm text, operator
  prompts (where a "service mode" or key-sequence hint lives);
- low entropy, no strings - graphics tiles, lookup tables;
- high entropy (> 7.2 bits/byte) - compressed or encrypted data, i.e. the
  embedded archive.

`gb-cart-inspect.py` prints the header, flags checksum mismatches, profiles
all banks and scans for container magic bytes - including behind a single-byte
XOR, which is the usual "encryption".

### Save RAM

A cartridge with battery-backed RAM keeps state across resets; an emulator
writes it to a `.sav` file. A rig that issues a token after a completed shift
often keeps progress there, so the `.sav` is worth examining as its own blob.

## Embedded archives

Inside any image, look for:

| Magic | Container |
|---|---|
| `78 01 / 78 5E / 78 9C / 78 DA` | zlib stream |
| `1F 8B 08` | gzip |
| `PK\x03\x04` | zip |
| `BZh` | bzip2 |
| `FD 37 7A 58 5A 00` | xz |
| `28 B5 2F FD` | zstd |

Trying to inflate at every zlib-header offset is cheap and decisive - a
stream that produces a sane length is the real thing. When no magic appears
but a region has high entropy, test single-byte XOR against known magics
before assuming real cryptography.

`blob-carve.py` does the magic scan, the inflate attempts, the entropy profile
and the XOR sweep, and extracts what it finds.

## Legacy 16-bit HMI binaries (.COM / MZ .EXE)

A `.COM` file is a flat real-mode image loaded at `CS:0100h` - no header at
all, so the first byte of the file is the first instruction. An `MZ .EXE` has
a header with initial `CS:IP`, `SS:SP` and a relocation table; data appended
beyond the length implied by the page count is an **overlay**, a classic
hiding place.

What to read:

- **Strings.** Operator prompts, units (`MG/L`, `GPM`, `PSI`), alarm text and
  menu structure describe the process the program controls.
- **Interrupts.** `CD xx` with a preceding `MOV AH, imm8`:
  - INT 21h - DOS file and console services (AH=3F read, 40 write, 3D open);
  - INT 10h - BIOS video, i.e. screen drawing;
  - INT 16h - keyboard;
  - **INT 14h - BIOS serial.** A binary that calls INT 14h is talking to a
    field device over RS-232/485, so it is implementing a protocol
    (Modbus RTU, Allen-Bradley DF1, or a vendor ASCII protocol). That is
    usually the interesting half of the program.
  - Direct port I/O (`IN`/`OUT` to 0x3F8/0x2F8) does the same thing without
    the BIOS.
- **Constants.** Four-byte IEEE-754 values in an engineering range are
  candidate setpoints and trip limits. A limit that sits *just above* a normal
  operating value is the shape of a tampered alarm threshold - "a drop too
  much" is a quantity, and it is usually sitting in the binary as a literal.
- **BCD and fixed-point.** Old HMIs often store engineering values as packed
  BCD or as an integer with an implied decimal place; if the floats look wrong,
  check for `0x1234` meaning 12.34.

`dos-bin-inspect.py` reports all of this, and will disassemble in 16-bit mode
if `capstone` is installed.

## A general method

1. Identify the container (header, magic, size, checksums).
2. Map regions (banks, sections, overlays) and profile them by entropy and
   strings.
3. Read the data where it is - strings and tables answer more questions than
   disassembly does.
4. Only then reverse the code, and only the part that touches the data you
   care about.
