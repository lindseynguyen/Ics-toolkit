"""MS-DOS .COM / MZ .EXE static inspector for legacy HMI and setpoint binaries.

Old operator stations still ship 16-bit utilities (SETPT*.COM style). This
module reports the container type, strings, DOS interrupt usage, candidate
numeric setpoint tables and, if capstone is installed, a 16-bit disassembly
around any offset.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .util import printable

INT21_AH = {
    0x01: "read char w/ echo", 0x02: "write char", 0x08: "read char no echo",
    0x09: "write string ($-terminated)", 0x0A: "buffered input",
    0x19: "get current drive", 0x25: "set interrupt vector",
    0x2A: "get date", 0x2C: "get time", 0x30: "get DOS version",
    0x35: "get interrupt vector", 0x39: "mkdir", 0x3B: "chdir",
    0x3C: "create file", 0x3D: "open file", 0x3E: "close file",
    0x3F: "read file/device", 0x40: "write file/device", 0x41: "delete file",
    0x42: "seek", 0x43: "get/set attributes", 0x44: "ioctl",
    0x47: "get current dir", 0x48: "allocate memory", 0x4B: "exec",
    0x4C: "terminate with code", 0x4E: "find first", 0x4F: "find next",
    0x56: "rename", 0x57: "get/set file date",
}

INTERESTING_INTS = {
    0x10: "BIOS video", 0x13: "BIOS disk", 0x14: "BIOS serial (RS-232)",
    0x16: "BIOS keyboard", 0x17: "BIOS printer", 0x1A: "BIOS clock",
    0x21: "DOS services", 0x33: "mouse", 0x67: "EMS",
}


@dataclass
class Interrupt:
    offset: int
    number: int
    name: str
    ah_hint: str = ""


@dataclass
class BinInfo:
    path: str
    size: int
    kind: str
    load_base: int
    entry: Optional[int] = None
    mz: Dict[str, int] = field(default_factory=dict)
    strings: List[Tuple[int, str]] = field(default_factory=list)
    interrupts: List[Interrupt] = field(default_factory=list)
    int_counts: Dict[str, int] = field(default_factory=dict)
    float_candidates: List[Tuple[int, float]] = field(default_factory=list)
    serial_io: bool = False
    overlay_offset: Optional[int] = None


def _strings_with_offsets(data: bytes, min_len: int) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((start, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((start, cur.decode("ascii")))
    return out


def inspect(path: str, min_str: int = 4) -> BinInfo:
    with open(path, "rb") as fh:
        data = fh.read()
    info = BinInfo(path=path, size=len(data), kind="raw", load_base=0x100)
    if data[:2] in (b"MZ", b"ZM"):
        info.kind = "MZ .EXE"
        (sig, extra, pages, relocs, hdr_para, minalloc, maxalloc, ss, sp,
         csum, ip, cs, reloc_off, overlay) = struct.unpack_from("<14H", data, 0)
        info.mz = {"pages": pages, "bytes_in_last_page": extra,
                   "relocations": relocs, "header_paragraphs": hdr_para,
                   "initial_ss": ss, "initial_sp": sp, "initial_ip": ip,
                   "initial_cs": cs, "reloc_table": reloc_off,
                   "overlay_number": overlay}
        info.load_base = hdr_para * 16
        info.entry = info.load_base + cs * 16 + ip
        exe_len = (pages - 1) * 512 + (extra or 512)
        if 0 < exe_len < len(data):
            info.overlay_offset = exe_len
        if len(data) > 0x3C + 4:
            lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 < lfanew < len(data) - 4 and data[lfanew:lfanew + 2] in (b"PE", b"NE", b"LE"):
                info.kind = f"MZ + {data[lfanew:lfanew+2].decode()} stub"
    elif path.lower().endswith(".com"):
        info.kind = ".COM (flat 16-bit, loaded at CS:0100h)"
        info.entry = 0x100
    info.strings = _strings_with_offsets(data, min_str)

    # INT scan: CD imm8
    counts: Dict[str, int] = {}
    for m in re.finditer(rb"\xcd(.)", data, re.S):
        off = m.start()
        num = m.group(1)[0]
        name = INTERESTING_INTS.get(num, f"int {num:#02x}")
        hint = ""
        # look back for MOV AH, imm8 (B4 xx) within 8 bytes
        back = data[max(0, off - 8):off]
        mh = None
        for mm in re.finditer(rb"\xb4(.)", back, re.S):
            mh = mm.group(1)[0]
        if num == 0x21 and mh is not None:
            hint = INT21_AH.get(mh, f"AH={mh:#02x}")
        info.interrupts.append(Interrupt(offset=off, number=num, name=name, ah_hint=hint))
        counts[name] = counts.get(name, 0) + 1
        if num == 0x14:
            info.serial_io = True
    info.int_counts = counts

    # plausible IEEE-754 setpoints (engineering range, little endian)
    for off in range(0, max(0, len(data) - 4)):
        v = struct.unpack_from("<f", data, off)[0]
        if v == v and abs(v) > 1e-4 and abs(v) < 1e5:
            frac = abs(v) % 1
            if frac == 0 or round(frac, 3) in (0.1, 0.2, 0.25, 0.5, 0.75, 0.9):
                info.float_candidates.append((off, round(v, 4)))
        if len(info.float_candidates) > 400:
            break
    return info


def disassemble(path: str, offset: int = 0, length: int = 160,
                base: int = 0x100) -> List[str]:
    """16-bit disassembly via capstone when available."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    except Exception:
        return ["capstone not installed - pip install capstone for disassembly"]
    with open(path, "rb") as fh:
        data = fh.read()
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out = []
    for ins in md.disasm(data[offset:offset + length], base + offset):
        out.append(f"{ins.address:04x}  {ins.bytes.hex():<14} {ins.mnemonic} {ins.op_str}")
    return out or ["(no instructions decoded)"]


def ascii_screens(info: BinInfo, min_len: int = 20) -> List[Tuple[int, str]]:
    """Long strings that look like HMI screen text or prompts."""
    keys = ("press", "enter", "setpoint", "alarm", "pump", "valve", "flow",
            "level", "tank", "psi", "gpm", "mode", "manual", "auto", "error",
            "ok", "warn", "limit", "min", "max", "scada", "hmi")
    out = []
    for off, s in info.strings:
        low = s.lower()
        if len(s) >= min_len or any(k in low for k in keys):
            out.append((off, s))
    return out
