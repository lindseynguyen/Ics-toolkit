"""General forensic helpers: identification, hashing, strings, byte diffing
and decoding.

These are the everyday commands - `file`, `md5sum`, `strings`, `xxd`, `diff`,
`base64 -d` - with the parts that matter for OT artefacts built in and with
output a newcomer can act on: offsets you can jump to, strings classified by
what they are, and a diff that tells you *where* two firmware builds differ.
"""
from __future__ import annotations

import binascii
import base64
import codecs
import gzip
import hashlib
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .carve import entropy, find_magics

# ---------------------------------------------------------------------------
# identification and hashing
# ---------------------------------------------------------------------------
FILE_SIGNATURES: List[Tuple[bytes, int, str]] = [
    (b"\xd4\xc3\xb2\xa1", 0, "libpcap capture (little-endian)"),
    (b"\xa1\xb2\xc3\xd4", 0, "libpcap capture (big-endian)"),
    (b"\x4d\x3c\xb2\xa1", 0, "libpcap capture, nanosecond timestamps"),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng capture"),
    (b"\x7fELF", 0, "ELF executable or shared object"),
    (b"MZ", 0, "DOS/Windows executable (MZ)"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"GIF8", 0, "GIF image"),
    (b"%PDF-", 0, "PDF document"),
    (b"PK\x03\x04", 0, "ZIP archive (also .docx/.xlsx/.jar/.apk)"),
    (b"\x1f\x8b\x08", 0, "gzip stream"),
    (b"BZh", 0, "bzip2 archive"),
    (b"\xfd7zXZ\x00", 0, "xz archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"SQLite format 3\x00", 0, "SQLite database"),
    (b"Evt", 0, "Windows event log fragment"),
    (b"ElfFile\x00", 0, "Windows EVTX event log"),
    (b"regf", 0, "Windows registry hive"),
    (b"\xce\xed\x66\x66", 0x104, "Game Boy cartridge image"),
    (b"\x00\x00\x01\x00", 0, "Windows icon"),
    (b"ustar", 257, "tar archive"),
    (b"-----BEGIN", 0, "PEM certificate or key"),
    (b"<?xml", 0, "XML document"),
    (b"{", 0, "possibly JSON"),
]

TEXT_HINTS = [
    (re.compile(rb"^\s*(#!\s*/\S+)"), "script with a shebang"),
    (re.compile(rb"(?m)^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s"), "syslog-style log"),
    (re.compile(rb"(?m)^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"), "ISO-timestamped log"),
    (re.compile(rb"(?m)^#\d{9,11}\s*$"), "shell history with HISTTIMEFORMAT timestamps"),
    (re.compile(rb"(?m)^[^,\n]{1,40}(,[^,\n]{0,60}){2,}$"), "delimited text (CSV-like)"),
]


@dataclass
class FileReport:
    path: str
    size: int
    kind: str
    hashes: Dict[str, str] = field(default_factory=dict)
    entropy: float = 0.0
    entropy_note: str = ""
    signatures: List[str] = field(default_factory=list)
    containers: List[str] = field(default_factory=list)
    text_hints: List[str] = field(default_factory=list)
    printable_ratio: float = 0.0
    preview: str = ""
    strings_total: int = 0
    interesting: Dict[str, List[str]] = field(default_factory=dict)


def hashes(path: str, chunk: int = 1 << 20) -> Dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            for h in (md5, sha1, sha256):
                h.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()}


def entropy_note(value: float) -> str:
    if value < 1.5:
        return "very low - mostly padding or repeated bytes"
    if value < 5.0:
        return "low - plain text, tables or sparse binary"
    if value < 6.5:
        return "medium - ordinary code and data"
    if value < 7.2:
        return "high - packed, or dense binary"
    return "very high - compressed or encrypted"


def identify(path: str, sample: int = 1 << 20) -> FileReport:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(sample)
    rep = FileReport(path=path, size=size, kind="unknown data")
    for magic, off, name in FILE_SIGNATURES:
        if head[off:off + len(magic)] == magic:
            rep.signatures.append(f"{name} (magic at offset 0x{off:x})")
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127)
    rep.printable_ratio = printable / len(head) if head else 0.0
    rep.entropy = round(entropy(head), 3)
    rep.entropy_note = entropy_note(rep.entropy)

    if rep.signatures:
        rep.kind = rep.signatures[0].split(" (")[0]
    elif rep.printable_ratio > 0.92:
        rep.kind = "text"
        for rx, label in TEXT_HINTS:
            if rx.search(head[:65536]):
                rep.text_hints.append(label)
        if rep.text_hints:
            rep.kind = rep.text_hints[0]
    elif size and size % 16384 == 0 and size <= 8 * 1024 * 1024:
        rep.kind = "binary image, size is a whole number of 16 KiB banks " \
                   "(firmware or cartridge-like)"
    else:
        rep.kind = "binary data of an unrecognised type"

    rep.hashes = hashes(path)
    for hit in find_magics(head)[:40]:
        if hit.offset == 0:
            continue
        rep.containers.append(f"0x{hit.offset:06x}  {hit.kind}"
                              + (f"  ({hit.note})" if hit.note else ""))
    found = extract_strings(head, min_len=6)
    rep.strings_total = len(found)
    rep.interesting = classify_strings(found)
    rep.preview = "\n".join(s.text for s in found[:12])
    return rep


# ---------------------------------------------------------------------------
# strings
# ---------------------------------------------------------------------------
@dataclass
class Str:
    offset: int
    text: str
    encoding: str          # ascii | utf-16le | utf-16be


STRING_CLASSES: List[Tuple[str, re.Pattern]] = [
    ("urls", re.compile(r"\b(?:https?|ftp|tftp|smb|opc\.tcp)://[\w\-./:%?#=&@+~]+")),
    ("ip addresses", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")),
    ("hostnames", re.compile(r"\b[a-z0-9][a-z0-9-]{1,30}\.(?:local|lan|corp|vn|com|net|org|io)\b", re.I)),
    ("file paths", re.compile(r"(?:[A-Za-z]:\\[\\\w\-. ]{3,}|/(?:usr|etc|var|home|tmp|opt|mnt|proc)/[\w\-./]{2,})")),
    ("email addresses", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("commands", re.compile(r"\b(?:cmd\.exe|powershell|/bin/(?:ba)?sh|wget|curl|nc|ncat|python[23]?|systemctl|schtasks|reg\s+add)\b", re.I)),
    ("credential-like", re.compile(r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token|credential)\b\s*[:=]?\s*\S{0,40}")),
    ("ot vocabulary", re.compile(r"(?i)\b(?:setpoint|set-point|alarm|trip|interlock|plc|hmi|scada|rtu|modbus|bacnet|dnp3|profinet|opc|tag|pump|valve|dose|flow|level|pressure|psi|gpm|mg/l)\b")),
    ("siemens block names", re.compile(r"\b(?:OB|FB|FC|DB|SDB|SFC|SFB)\s?\d{1,5}\b")),
    ("base64 blobs", re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")),
    ("flag-like", re.compile(r"\b[A-Z][A-Z0-9_]{2,15}\{[^}]{3,80}\}")),
    ("version strings", re.compile(r"(?i)\bv?\d+\.\d+(?:\.\d+)?(?:[-_][a-z0-9]+)?\b")),
]


def extract_strings(data: bytes, min_len: int = 4,
                    encodings: Iterable[str] = ("ascii", "utf-16le")) -> List[Str]:
    out: List[Str] = []
    if "ascii" in encodings:
        cur = bytearray()
        start = 0
        for i, b in enumerate(data):
            if 32 <= b < 127:
                if not cur:
                    start = i
                cur.append(b)
            else:
                if len(cur) >= min_len:
                    out.append(Str(start, cur.decode("ascii"), "ascii"))
                cur = bytearray()
        if len(cur) >= min_len:
            out.append(Str(start, cur.decode("ascii"), "ascii"))
    for enc, step in (("utf-16le", 0), ("utf-16be", 1)):
        if enc not in encodings:
            continue
        cur = []
        start = 0
        for i in range(step, len(data) - 1, 2):
            lo, hi = (data[i], data[i + 1]) if enc == "utf-16le" else (data[i + 1], data[i])
            if hi == 0 and 32 <= lo < 127:
                if not cur:
                    start = i
                cur.append(chr(lo))
            else:
                if len(cur) >= min_len:
                    out.append(Str(start, "".join(cur), enc))
                cur = []
        if len(cur) >= min_len:
            out.append(Str(start, "".join(cur), enc))
    out.sort(key=lambda s: s.offset)
    return out


def classify_strings(found: Iterable[Str]) -> Dict[str, List[str]]:
    buckets: Dict[str, List[str]] = {}
    for s in found:
        for name, rx in STRING_CLASSES:
            if name == "version strings":
                continue                       # too noisy for the summary
            m = rx.search(s.text)
            if m:
                buckets.setdefault(name, [])
                value = m.group(0).strip()
                if value not in buckets[name] and len(buckets[name]) < 40:
                    buckets[name].append(value)
    return buckets


# ---------------------------------------------------------------------------
# hex view
# ---------------------------------------------------------------------------
def hexdump(data: bytes, base: int = 0, width: int = 16,
            highlight: Optional[Tuple[int, int]] = None) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = []
        for i, b in enumerate(chunk):
            cell = f"{b:02x}"
            if highlight and highlight[0] <= base + off + i < highlight[1]:
                cell = f"[{cell}]"
            hx.append(cell)
        hexpart = " ".join(hx)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart:<{width * 3 + 2}}  |{asc}|")
    return "\n".join(lines)


def find_all(data: bytes, needle: bytes, limit: int = 200) -> List[int]:
    out, start = [], 0
    while len(out) < limit:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def parse_needle(value: str, as_hex: bool = False) -> bytes:
    if as_hex or re.fullmatch(r"(?:0x)?[0-9a-fA-F\s]{2,}", value or "") and \
            len(value.replace(" ", "").replace("0x", "")) % 2 == 0 and as_hex:
        return bytes.fromhex(value.replace("0x", "").replace(" ", ""))
    return value.encode("latin-1")


# ---------------------------------------------------------------------------
# binary diff
# ---------------------------------------------------------------------------
@dataclass
class DiffRegion:
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


def diff_regions(a: bytes, b: bytes, merge_gap: int = 16) -> List[DiffRegion]:
    """Byte ranges where two blobs differ, merging runs that are close."""
    regions: List[DiffRegion] = []
    n = min(len(a), len(b))
    start: Optional[int] = None
    for i in range(n):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            if regions and start - regions[-1].end <= merge_gap:
                regions[-1].end = i
            else:
                regions.append(DiffRegion(start, i))
            start = None
    if start is not None:
        regions.append(DiffRegion(start, n))
    if len(a) != len(b):
        regions.append(DiffRegion(n, max(len(a), len(b))))
    return regions


def interpret_region(a: bytes, b: bytes, r: DiffRegion) -> str:
    """Guess what changed in a region - text, a float, an integer."""
    ba, bb = a[r.start:r.end], b[r.start:r.end]
    pa = all(32 <= x < 127 or x in (0, 9, 10, 13) for x in ba) if ba else False
    pb = all(32 <= x < 127 or x in (0, 9, 10, 13) for x in bb) if bb else False
    if pa and pb and r.length >= 3:
        sa = ba.decode("latin-1").strip("\x00").strip()
        sb = bb.decode("latin-1").strip("\x00").strip()
        return f"text: {sa!r} -> {sb!r}"
    if r.length == 4 and len(ba) == 4 and len(bb) == 4:
        try:
            fa, fb = struct.unpack("<f", ba)[0], struct.unpack("<f", bb)[0]

            def fmt(x: float) -> str:
                if x != x:
                    return "not-a-number"
                if abs(x) > 1e9:
                    return "out of engineering range"
                return f"{x:.6g}"

            sane = [x for x in (fa, fb) if x == x and abs(x) < 1e9]
            if sane:
                ia, ib = struct.unpack("<i", ba)[0], struct.unpack("<i", bb)[0]
                return (f"4 bytes: float {fmt(fa)} -> {fmt(fb)} "
                        f"(as int32: {ia} -> {ib})")
        except struct.error:
            pass
    if r.length <= 4:
        # a float or int rarely changes in all four bytes, so widen the window
        # to the enclosing aligned word before giving up on interpreting it
        base = r.start - (r.start % 4)
        wa, wb = a[base:base + 4], b[base:base + 4]
        if len(wa) == 4 and len(wb) == 4:
            try:
                fa, fb = struct.unpack("<f", wa)[0], struct.unpack("<f", wb)[0]
                ok = [x for x in (fa, fb) if x == x and 1e-6 < abs(x) < 1e6]
                if len(ok) == 2:
                    return (f"{r.length} byte(s) inside the 4-byte value at "
                            f"0x{base:08x}: float {fa:.6g} -> {fb:.6g}")
            except struct.error:
                pass
            ia, ib = struct.unpack("<H", a[base:base + 2])[0], \
                struct.unpack("<H", b[base:base + 2])[0]
            if r.length <= 2 and ia != ib:
                return (f"{r.length} byte(s): {ba.hex()} -> {bb.hex()} "
                        f"(as uint16 at 0x{base:08x}: {ia} -> {ib})")
        return f"{r.length} byte(s): {ba.hex()} -> {bb.hex()}"
    return f"{r.length} bytes changed"


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------
def _score(data: bytes) -> float:
    """How much this looks like meaningful text."""
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    words = len(re.findall(rb"[A-Za-z]{3,}", data))
    return good / len(data) + min(words / max(1, len(data) / 12), 1.0)


def try_decoders(data: bytes, xor_keys: bool = True) -> List[Tuple[str, bytes, float]]:
    """Every decoding that produces something more readable than the input."""
    results: List[Tuple[str, bytes, float]] = []
    base_score = _score(data)

    def add(name: str, out: Optional[bytes]) -> None:
        if out and len(out) > 1:
            s = _score(out)
            if s > base_score + 0.05:
                results.append((name, out, round(s, 3)))

    text = data.strip()
    try:
        add("base64", base64.b64decode(text + b"=" * (-len(text) % 4), validate=False))
    except Exception:
        pass
    try:
        add("base32", base64.b32decode(text + b"=" * (-len(text) % 8), casefold=True))
    except Exception:
        pass
    try:
        add("url-safe base64", base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4)))
    except Exception:
        pass
    try:
        compact = re.sub(rb"[^0-9a-fA-F]", b"", text)
        if len(compact) >= 4 and len(compact) % 2 == 0:
            add("hex", binascii.unhexlify(compact))
    except Exception:
        pass
    try:
        add("gzip", gzip.decompress(data))
    except Exception:
        pass
    for wbits, name in ((15, "zlib"), (-15, "raw deflate")):
        try:
            add(name, zlib.decompressobj(wbits).decompress(data))
        except Exception:
            pass
    try:
        add("rot13", codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1"))
    except Exception:
        pass
    try:
        from urllib.parse import unquote_to_bytes
        add("url-encoded", unquote_to_bytes(data.decode("latin-1")))
    except Exception:
        pass
    try:
        add("utf-16le text", data.decode("utf-16-le", "strict").encode("utf-8"))
    except Exception:
        pass
    if xor_keys:
        best: List[Tuple[str, bytes, float]] = []
        for key in range(1, 256):
            out = bytes(b ^ key for b in data)
            s = _score(out)
            if s > base_score + 0.35:
                best.append((f"xor 0x{key:02x}", out, round(s, 3)))
        best.sort(key=lambda t: -t[2])
        results += best[:3]
    results.sort(key=lambda t: -t[2])
    return results


def nested_decode(data: bytes, depth: int = 3) -> List[Tuple[str, bytes]]:
    """Follow a chain of encodings, for example base64 of a gzip stream."""
    chain: List[Tuple[str, bytes]] = []
    current = data
    for _ in range(depth):
        res = try_decoders(current, xor_keys=False)
        if not res:
            break
        name, out, _score_ = res[0]
        chain.append((name, out))
        current = out
    return chain
