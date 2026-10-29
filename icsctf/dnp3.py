"""DNP3 (IEEE 1815) decoder: link layer de-stuffing, transport assembly and
application-layer function codes / object headers.

Enough to answer "who issued a direct-operate", "which points were written",
"was a cold restart or unsolicited-disable sent".
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

DNP3_PORT = 20000
START = b"\x05\x64"

APP_FUNCS = {
    0: "confirm", 1: "read", 2: "write", 3: "select", 4: "operate",
    5: "direct-operate", 6: "direct-operate-no-ack", 7: "immediate-freeze",
    9: "freeze-clear", 11: "freeze-at-time", 13: "cold-restart",
    14: "warm-restart", 15: "initialize-data", 16: "initialize-application",
    17: "start-application", 18: "stop-application", 19: "save-configuration",
    20: "enable-unsolicited", 21: "disable-unsolicited", 22: "assign-class",
    23: "delay-measurement", 24: "record-current-time", 25: "open-file",
    26: "close-file", 27: "delete-file", 28: "get-file-info",
    29: "authenticate-file", 30: "abort-file", 31: "activate-config",
    32: "authentication-request", 33: "authentication-error",
    129: "response", 130: "unsolicited-response", 131: "authentication-response",
}

LINK_FUNCS = {0: "reset-link-states", 1: "reset-user-process",
              2: "test-link-states", 3: "unconfirmed-user-data",
              4: "unconfirmed-user-data", 9: "request-link-status",
              11: "link-status", 14: "not-supported", 15: "not-supported"}

GROUPS = {
    1: "binary input", 2: "binary input event", 3: "double-bit input",
    10: "binary output", 11: "binary output event", 12: "binary output command (CROB)",
    20: "counter", 21: "frozen counter", 22: "counter event",
    30: "analog input", 32: "analog input event", 34: "analog input deadband",
    40: "analog output status", 41: "analog output command",
    50: "time and date", 51: "time and date CTO", 52: "time delay",
    60: "class objects", 70: "file transfer", 80: "internal indications",
    110: "octet string", 120: "authentication",
}

CROB_OPS = {0: "NUL", 1: "PULSE_ON", 2: "PULSE_OFF", 3: "LATCH_ON",
            4: "LATCH_OFF", 65: "CLOSE pulse-on", 129: "TRIP pulse-on"}

IIN_BITS = [
    "all-stations", "class1-events", "class2-events", "class3-events",
    "need-time", "local-control", "device-trouble", "device-restart",
    "func-not-supported", "object-unknown", "parameter-error",
    "event-buffer-overflow", "already-executing", "config-corrupt",
    "reserved2", "reserved1",
]


@dataclass
class Dnp3Msg:
    frame: int
    ts: float
    src: str
    dst: str
    link_src: int
    link_dst: int
    link_func: str
    app_func: Optional[str] = None
    seq: Optional[int] = None
    iin: List[str] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    detail: str = ""
    raw: bytes = b""

    def summary(self) -> str:
        bits = [f"{self.link_src}->{self.link_dst}", self.link_func]
        if self.app_func:
            bits.append(self.app_func)
        if self.iin:
            bits.append("IIN:" + ",".join(self.iin))
        if self.objects:
            bits.append("; ".join(self.objects[:5]))
        if self.detail:
            bits.append(self.detail)
        return " ".join(bits)


def _destuff(body: bytes) -> bytes:
    """Strip the per-16-byte CRCs from a DNP3 link-layer frame body."""
    out = bytearray()
    i = 0
    while i < len(body):
        chunk = body[i:i + 18]          # 16 data octets + 2 CRC octets
        if len(chunk) <= 2:
            break
        out += chunk[:-2]
        i += 18
    return bytes(out)


def _parse_objects(buf: bytes) -> List[str]:
    """Walk application-layer object headers.

    Handles the index-prefix codes as well as the range specifiers, which is
    what makes CROB (g12v1, qualifier 0x17 / 0x28) decode at the right offset.
    """
    out: List[str] = []
    i = 0
    guard = 0
    while i + 3 <= len(buf) and guard < 24:
        guard += 1
        grp, var, qual = buf[i], buf[i + 1], buf[i + 2]
        i += 3
        name = GROUPS.get(grp, f"group {grp}")
        prefix = (qual >> 4) & 0x07
        rng = qual & 0x0F
        start = stop = None
        count = None
        if rng == 0x00 and i + 2 <= len(buf):
            start, stop = buf[i], buf[i + 1]
            i += 2
        elif rng == 0x01 and i + 4 <= len(buf):
            start, stop = struct.unpack_from("<HH", buf, i)
            i += 4
        elif rng == 0x02 and i + 8 <= len(buf):
            start, stop = struct.unpack_from("<II", buf, i)
            i += 8
        elif rng == 0x06:
            pass                                 # all objects, no range field
        elif rng == 0x07 and i + 1 <= len(buf):
            count = buf[i]
            i += 1
        elif rng == 0x08 and i + 2 <= len(buf):
            count = struct.unpack_from("<H", buf, i)[0]
            i += 2
        elif rng == 0x09 and i + 4 <= len(buf):
            count = struct.unpack_from("<I", buf, i)[0]
            i += 4
        if count is None:
            count = 0 if start is None else (stop - start + 1)
        span = ("all" if start is None and not count
                else f"count {count}" if start is None
                else f"{start}" if start == stop else f"{start}-{stop}")
        desc = f"g{grp}v{var} ({name}) {span}"
        psz = {0: 0, 1: 1, 2: 2, 3: 4}.get(prefix, 0)
        details: List[str] = []
        for _ in range(max(0, count) if count else 0):
            idx = None
            if psz:
                if i + psz > len(buf):
                    break
                idx = int.from_bytes(buf[i:i + psz], "little")
                i += psz
            if grp == 12 and var == 1 and i + 11 <= len(buf):
                op, cnt = buf[i], buf[i + 1]
                on_t, off_t = struct.unpack_from("<II", buf, i + 2)
                status = buf[i + 10]
                i += 11
                details.append(f"idx {idx if idx is not None else '?'} "
                               f"op={CROB_OPS.get(op, hex(op))} count={cnt} "
                               f"on={on_t}ms off={off_t}ms status={status}")
            elif grp == 41 and var in (1, 2, 3, 4) and i + 1 < len(buf):
                sz = {1: 4, 2: 2, 3: 4, 4: 8}[var]
                if i + sz + 1 > len(buf):
                    break
                raw = buf[i:i + sz]
                if var == 1:
                    val: Any = struct.unpack("<i", raw)[0]
                elif var == 2:
                    val = struct.unpack("<h", raw)[0]
                elif var == 3:
                    val = round(struct.unpack("<f", raw)[0], 6)
                else:
                    val = round(struct.unpack("<d", raw)[0], 6)
                status = buf[i + sz]
                i += sz + 1
                details.append(f"idx {idx if idx is not None else '?'} "
                               f"value={val} status={status}")
            else:
                break
        if details:
            desc += " [" + " | ".join(details) + "]"
        out.append(desc)
        if psz == 0 and not details and rng in (0x06,):
            break
    return out


def extract(packets, port: int = DNP3_PORT) -> List[Dnp3Msg]:
    out: List[Dnp3Msg] = []
    for p in packets:
        if p.proto not in ("tcp", "udp") or not p.payload:
            continue
        if p.sport != port and p.dport != port:
            continue
        buf = p.payload
        off = 0
        while True:
            idx = buf.find(START, off)
            if idx < 0 or idx + 10 > len(buf):
                break
            ln = buf[idx + 2]
            ctrl = buf[idx + 3]
            ldst, lsrc = struct.unpack_from("<HH", buf, idx + 4)
            total = 10 + ((ln - 5) + (ln - 5 + 15) // 16 * 2) if ln >= 5 else 10
            frame = buf[idx:idx + total]
            off = idx + max(total, 10)
            m = Dnp3Msg(frame=p.index, ts=p.ts, src=p.src or "", dst=p.dst or "",
                        link_src=lsrc, link_dst=ldst,
                        link_func=LINK_FUNCS.get(ctrl & 0x0F, f"lf-{ctrl & 0x0F}"),
                        raw=frame)
            body = _destuff(frame[10:])
            if body:
                # transport header
                th = body[0]
                m.detail = f"TH fir={bool(th & 0x40)} fin={bool(th & 0x80)} seq={th & 0x3F}"
                app = body[1:]
                if len(app) >= 2:
                    actrl, fn = app[0], app[1]
                    m.seq = actrl & 0x0F
                    m.app_func = APP_FUNCS.get(fn, f"func-{fn}")
                    rest = app[2:]
                    if fn in (129, 130) and len(rest) >= 2:
                        iin = struct.unpack_from("<H", rest, 0)[0]
                        m.iin = [IIN_BITS[b] for b in range(16) if iin & (1 << b)]
                        rest = rest[2:]
                    m.objects = _parse_objects(rest)
            out.append(m)
    return out
