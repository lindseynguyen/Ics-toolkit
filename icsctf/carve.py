"""Blob / archive carving and entropy profiling for binary OT artefacts.

Firmware dumps, cartridge images and HMI binaries routinely hide a payload
inside a larger container. This module finds it: magic-byte scanning,
decompression attempts, entropy windows and single-byte-XOR magic recovery.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import math
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

MAGICS: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip-empty"),
    (b"\x1f\x8b\x08", "gzip"), (b"BZh9", "bzip2"), (b"BZh1", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"), (b"MSCF", "cab"),
    (b"ustar", "tar (ustar at +257)"),
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"), (b"BM", "bmp"),
    (b"%PDF-", "pdf"), (b"SQLite format 3\x00", "sqlite3"),
    (b"\x7fELF", "elf"), (b"MZ", "mz-exe"),
    (b"\x04\x22\x4d\x18", "lz4-frame"), (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"OggS", "ogg"), (b"RIFF", "riff/wav"),
    (b"\x1a\x45\xdf\xa3", "matroska"),
    (b"-----BEGIN", "pem"),
    (b"CTF{", "flag-like"), (b"FLAG{", "flag-like"),
]

ZLIB_HEADERS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


@dataclass
class Hit:
    offset: int
    kind: str
    note: str = ""
    size: Optional[int] = None


def find_magics(data: bytes) -> List[Hit]:
    hits: List[Hit] = []
    for magic, kind in MAGICS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            if kind == "mz-exe" and i != 0 and data[i:i + 2] == b"MZ":
                # avoid flooding on random "MZ" pairs: require a plausible e_lfanew
                if len(data) < i + 0x40:
                    start = i + 1
                    continue
            hits.append(Hit(offset=i, kind=kind))
            start = i + 1
            if len(hits) > 400:
                return hits
    for hdr in ZLIB_HEADERS:
        start = 0
        while True:
            i = data.find(hdr, start)
            if i < 0:
                break
            try:
                out = zlib.decompressobj().decompress(data[i:])
                if len(out) >= 16:
                    hits.append(Hit(offset=i, kind="zlib", size=len(out),
                                    note=f"inflates to {len(out)} bytes"))
            except zlib.error:
                pass
            start = i + 1
    hits.sort(key=lambda h: h.offset)
    return hits


def try_decompress(data: bytes, offset: int = 0) -> Optional[Tuple[str, bytes]]:
    """Attempt every supported container at `offset`. Returns (kind, bytes)."""
    blob = data[offset:]
    attempts = [
        ("zlib", lambda b: zlib.decompress(b)),
        ("zlib-raw", lambda b: zlib.decompressobj(-15).decompress(b)),
        ("gzip", lambda b: gzip.decompress(b)),
        ("bzip2", lambda b: bz2.decompress(b)),
        ("xz/lzma", lambda b: lzma.decompress(b)),
        ("lzma-alone", lambda b: lzma.decompress(b, format=lzma.FORMAT_ALONE)),
    ]
    for name, fn in attempts:
        try:
            out = fn(blob)
            if out:
                return name, out
        except Exception:
            continue
    try:
        import zipfile
        zf = zipfile.ZipFile(io.BytesIO(blob))
        names = zf.namelist()
        if names:
            return "zip", ("\n".join(names)).encode()
    except Exception:
        pass
    return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def entropy_profile(data: bytes, window: int = 1024) -> List[Tuple[int, float]]:
    return [(off, round(entropy(data[off:off + window]), 3))
            for off in range(0, len(data), window)]


def high_entropy_regions(data: bytes, window: int = 1024,
                         threshold: float = 7.2) -> List[Tuple[int, int, float]]:
    """Merge adjacent high-entropy windows - likely compressed or encrypted."""
    regions: List[Tuple[int, int, float]] = []
    cur_start: Optional[int] = None
    cur_vals: List[float] = []
    for off, e in entropy_profile(data, window):
        if e >= threshold:
            if cur_start is None:
                cur_start = off
            cur_vals.append(e)
        elif cur_start is not None:
            regions.append((cur_start, off, round(sum(cur_vals) / len(cur_vals), 3)))
            cur_start, cur_vals = None, []
    if cur_start is not None:
        regions.append((cur_start, len(data), round(sum(cur_vals) / len(cur_vals), 3)))
    return regions


def xor_magic_scan(data: bytes, max_hits: int = 20) -> List[Dict[str, object]]:
    """Find containers hidden behind a single-byte XOR (very common in CTFs)."""
    out: List[Dict[str, object]] = []
    targets = [(b"PK\x03\x04", "zip"), (b"\x1f\x8b\x08", "gzip"),
               (b"\x89PNG", "png"), (b"%PDF", "pdf"), (b"BZh", "bzip2"),
               (b"CTF{", "flag"), (b"FLAG{", "flag")]
    for key in range(1, 256):
        for magic, kind in targets:
            pat = bytes(b ^ key for b in magic)
            i = data.find(pat)
            if i >= 0:
                out.append({"xor_key": key, "kind": kind, "offset": i})
                if len(out) >= max_hits:
                    return out
    return out


def repeating_xor_guess(data: bytes, keylen: int) -> bytes:
    """Per-position most-common byte XOR 0x20 - a crude key recovery for text."""
    key = bytearray()
    for i in range(keylen):
        col = data[i::keylen]
        if not col:
            key.append(0)
            continue
        counts: Dict[int, int] = {}
        for b in col:
            counts[b] = counts.get(b, 0) + 1
        common = max(counts, key=lambda k: counts[k])
        key.append(common ^ 0x20)
    return bytes(key)


def carve_to(data: bytes, offset: int, path: str, length: Optional[int] = None) -> int:
    blob = data[offset:offset + length] if length else data[offset:]
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)
