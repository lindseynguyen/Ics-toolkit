"""Small shared helpers: time formatting, hex dumps, table printing."""
from __future__ import annotations

import datetime as _dt
import struct
from typing import Iterable, List, Optional, Sequence


def ts(epoch: float, iso: bool = True) -> str:
    if not epoch:
        return "-"
    d = _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if iso else d.strftime("%H:%M:%S.%f")[:-3]


def hexdump(data: bytes, limit: int = 256, indent: str = "    ") -> str:
    out: List[str] = []
    data = data[:limit]
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{indent}{off:04x}  {hx:<47}  {asc}")
    return "\n".join(out)


def printable(data: bytes, min_len: int = 4) -> List[str]:
    """ASCII strings in a blob (the classic `strings` behaviour)."""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "replace"))
    return out


def f32(data: bytes, big: bool = True) -> Optional[float]:
    if len(data) < 4:
        return None
    return struct.unpack(">f" if big else "<f", data[:4])[0]


def f64(data: bytes, big: bool = True) -> Optional[float]:
    if len(data) < 8:
        return None
    return struct.unpack(">d" if big else "<d", data[:8])[0]


def regs_to_float(hi: int, lo: int, word_swap: bool = False) -> float:
    """Two Modbus holding registers -> IEEE-754 single. word_swap=True for CDAB."""
    a, b = (lo, hi) if word_swap else (hi, lo)
    return struct.unpack(">f", struct.pack(">HH", a, b))[0]


def table(rows: Sequence[Sequence[object]], headers: Sequence[str]) -> str:
    srows = [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in srows:
        for i, c in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], len(c))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * w for w in widths)
    body = "\n".join("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in srows)
    return f"{line}\n{sep}\n{body}" if srows else f"{line}\n{sep}\n(none)"


def section(title: str) -> str:
    return f"\n== {title} " + "=" * max(0, 72 - len(title))


def pct(n: int, total: int) -> str:
    return f"{(100.0 * n / total):.1f}%" if total else "-"


def uniq(seq: Iterable) -> List:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
