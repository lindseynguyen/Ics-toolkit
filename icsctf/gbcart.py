"""Game Boy cartridge image (.gb/.gbc) inspector.

OT training-rig artefacts sometimes ship a plant simulator as a Game Boy
ROM: the cartridge header tells you the bank layout, and process logic,
operator strings and embedded archives live in the data banks. This module
parses the header, maps banks, and points at the interesting ones.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .carve import entropy, find_magics, high_entropy_regions
from .util import printable

HEADER_OFF = 0x100
BANK_SIZE = 0x4000

CART_TYPES = {
    0x00: "ROM ONLY", 0x01: "MBC1", 0x02: "MBC1+RAM", 0x03: "MBC1+RAM+BATTERY",
    0x05: "MBC2", 0x06: "MBC2+BATTERY", 0x08: "ROM+RAM", 0x09: "ROM+RAM+BATTERY",
    0x0B: "MMM01", 0x0C: "MMM01+RAM", 0x0D: "MMM01+RAM+BATTERY",
    0x0F: "MBC3+TIMER+BATTERY", 0x10: "MBC3+TIMER+RAM+BATTERY", 0x11: "MBC3",
    0x12: "MBC3+RAM", 0x13: "MBC3+RAM+BATTERY", 0x19: "MBC5",
    0x1A: "MBC5+RAM", 0x1B: "MBC5+RAM+BATTERY", 0x1C: "MBC5+RUMBLE",
    0x1D: "MBC5+RUMBLE+RAM", 0x1E: "MBC5+RUMBLE+RAM+BATTERY",
    0x20: "MBC6", 0x22: "MBC7+SENSOR+RUMBLE+RAM+BATTERY",
    0xFC: "POCKET CAMERA", 0xFD: "BANDAI TAMA5", 0xFE: "HuC3",
    0xFF: "HuC1+RAM+BATTERY",
}
ROM_SIZES = {0x00: "32 KiB (2 banks)", 0x01: "64 KiB (4)", 0x02: "128 KiB (8)",
             0x03: "256 KiB (16)", 0x04: "512 KiB (32)", 0x05: "1 MiB (64)",
             0x06: "2 MiB (128)", 0x07: "4 MiB (256)", 0x08: "8 MiB (512)"}
RAM_SIZES = {0x00: "none", 0x01: "2 KiB", 0x02: "8 KiB", 0x03: "32 KiB (4 banks)",
             0x04: "128 KiB (16 banks)", 0x05: "64 KiB (8 banks)"}
NINTENDO_LOGO = bytes([
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
    0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
    0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
    0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E])


@dataclass
class Bank:
    index: int
    offset: int
    size: int
    entropy: float
    strings: int
    note: str = ""


@dataclass
class CartInfo:
    path: str
    size: int
    title: str
    manufacturer: str
    cgb_flag: int
    sgb_flag: int
    cart_type: str
    rom_size: str
    ram_size: str
    destination: str
    licensee: str
    rom_version: int
    header_checksum: int
    header_checksum_calc: int
    global_checksum: int
    global_checksum_calc: int
    logo_ok: bool
    banks: List[Bank] = field(default_factory=list)
    magic_hits: List = field(default_factory=list)
    entropy_regions: List[Tuple[int, int, float]] = field(default_factory=list)

    @property
    def header_ok(self) -> bool:
        return self.header_checksum == self.header_checksum_calc

    @property
    def global_ok(self) -> bool:
        return self.global_checksum == self.global_checksum_calc


def inspect(path: str, string_min: int = 5) -> CartInfo:
    with open(path, "rb") as fh:
        rom = fh.read()
    h = rom[HEADER_OFF:HEADER_OFF + 0x50]
    title_raw = rom[0x134:0x144]
    cgb = rom[0x143] if len(rom) > 0x143 else 0
    if cgb in (0x80, 0xC0):
        title = title_raw[:11].split(b"\x00")[0].decode("latin-1")
        manu = title_raw[11:15].decode("latin-1").strip("\x00")
    else:
        title = title_raw.split(b"\x00")[0].decode("latin-1")
        manu = ""
    hdr_sum = 0
    for b in rom[0x134:0x14D]:
        hdr_sum = (hdr_sum - b - 1) & 0xFF
    gsum = sum(rom) - (rom[0x14E] if len(rom) > 0x14E else 0) - \
        (rom[0x14F] if len(rom) > 0x14F else 0)
    info = CartInfo(
        path=path, size=len(rom), title=title, manufacturer=manu,
        cgb_flag=cgb, sgb_flag=rom[0x146] if len(rom) > 0x146 else 0,
        cart_type=CART_TYPES.get(rom[0x147], f"0x{rom[0x147]:02x}") if len(rom) > 0x147 else "?",
        rom_size=ROM_SIZES.get(rom[0x148], f"0x{rom[0x148]:02x}") if len(rom) > 0x148 else "?",
        ram_size=RAM_SIZES.get(rom[0x149], f"0x{rom[0x149]:02x}") if len(rom) > 0x149 else "?",
        destination="Japan" if len(rom) > 0x14A and rom[0x14A] == 0 else "non-Japan",
        licensee=(f"0x{rom[0x14B]:02x}" if len(rom) > 0x14B else "?"),
        rom_version=rom[0x14C] if len(rom) > 0x14C else 0,
        header_checksum=rom[0x14D] if len(rom) > 0x14D else 0,
        header_checksum_calc=hdr_sum,
        global_checksum=int.from_bytes(rom[0x14E:0x150], "big") if len(rom) > 0x14F else 0,
        global_checksum_calc=gsum & 0xFFFF,
        logo_ok=rom[0x104:0x134] == NINTENDO_LOGO,
    )
    for i in range(0, max(1, (len(rom) + BANK_SIZE - 1) // BANK_SIZE)):
        off = i * BANK_SIZE
        blob = rom[off:off + BANK_SIZE]
        e = round(entropy(blob), 3)
        s = len(printable(blob, string_min))
        note = ""
        if e >= 7.2:
            note = "high entropy - compressed/encrypted?"
        elif s > 40:
            note = "string-heavy - text/UI or data table"
        info.banks.append(Bank(index=i, offset=off, size=len(blob),
                               entropy=e, strings=s, note=note))
    info.magic_hits = [h for h in find_magics(rom) if h.kind not in ("mz-exe", "riff/wav")]
    info.entropy_regions = high_entropy_regions(rom, 512, 7.3)
    return info


def bank_strings(path: str, bank: int, min_len: int = 4) -> List[str]:
    with open(path, "rb") as fh:
        rom = fh.read()
    blob = rom[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
    return printable(blob, min_len)


def dump_bank(path: str, bank: int, out_path: str) -> int:
    with open(path, "rb") as fh:
        rom = fh.read()
    blob = rom[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
    with open(out_path, "wb") as fh:
        fh.write(blob)
    return len(blob)


def rst_and_vectors(path: str) -> Dict[str, str]:
    """Interrupt/RST vector bytes - useful when diffing a patched ROM."""
    with open(path, "rb") as fh:
        rom = fh.read(0x200)
    vec = {}
    for name, off in [("RST00", 0x00), ("RST08", 0x08), ("RST10", 0x10),
                      ("RST18", 0x18), ("RST20", 0x20), ("RST28", 0x28),
                      ("RST30", 0x30), ("RST38", 0x38), ("VBlank", 0x40),
                      ("LCDStat", 0x48), ("Timer", 0x50), ("Serial", 0x58),
                      ("Joypad", 0x60), ("Entry", 0x100)]:
        vec[name] = rom[off:off + 8].hex(" ")
    return vec
