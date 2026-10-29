"""Modbus/TCP decoder with request/response pairing and process-value decoding.

Built for questions of the form "which register blocks were scanned", "which
coils were forced", "what value was written" - i.e. Collection and Impair
Process Control style challenges.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MODBUS_PORT = 502

FUNCTIONS = {
    1: "read-coils", 2: "read-discrete-inputs", 3: "read-holding-registers",
    4: "read-input-registers", 5: "write-single-coil", 6: "write-single-register",
    7: "read-exception-status", 8: "diagnostics", 11: "get-comm-event-counter",
    12: "get-comm-event-log", 15: "write-multiple-coils",
    16: "write-multiple-registers", 17: "report-server-id",
    20: "read-file-record", 21: "write-file-record",
    22: "mask-write-register", 23: "read-write-multiple-registers",
    24: "read-fifo-queue", 43: "encapsulated-interface-transport",
}

EXCEPTIONS = {
    1: "illegal-function", 2: "illegal-data-address", 3: "illegal-data-value",
    4: "server-device-failure", 5: "acknowledge", 6: "server-device-busy",
    8: "memory-parity-error", 10: "gateway-path-unavailable",
    11: "gateway-target-no-response",
}

# Conventional Modbus data-model prefixes, handy when reporting addresses
TABLE_PREFIX = {1: "coil ", 2: "din ", 3: "hreg ", 4: "ireg ", 5: "coil ",
                6: "hreg ", 15: "coil ", 16: "hreg ", 22: "hreg ", 23: "hreg "}


@dataclass
class ModbusMsg:
    frame: int
    ts: float
    src: str
    dst: str
    tid: int
    unit: int
    func: int
    name: str
    is_response: bool
    addr: Optional[int] = None
    count: Optional[int] = None
    values: List[int] = field(default_factory=list)
    bits: List[int] = field(default_factory=list)
    exception: Optional[str] = None
    raw: bytes = b""

    def ref(self) -> str:
        if self.addr is None:
            return "-"
        pref = TABLE_PREFIX.get(self.func, "")
        n = self.count or 1
        end = self.addr + n - 1
        span = f"{self.addr}" if n == 1 else f"{self.addr}-{end}"
        return f"{pref}{span}"

    def summary(self) -> str:
        bits = [f"uid {self.unit}", self.name, "resp" if self.is_response else "req"]
        if self.addr is not None:
            bits.append(self.ref())
        if self.values:
            shown = ",".join(str(v) for v in self.values[:8])
            bits.append(f"values[{len(self.values)}]={shown}{'...' if len(self.values) > 8 else ''}")
        if self.bits:
            bits.append("bits=" + "".join(str(b) for b in self.bits[:24]))
        if self.exception:
            bits.append(f"EXCEPTION {self.exception}")
        return " ".join(bits)


def _bits_from(data: bytes, count: int) -> List[int]:
    out = []
    for i in range(count):
        byte = data[i // 8] if i // 8 < len(data) else 0
        out.append((byte >> (i % 8)) & 1)
    return out


def _parse_pdu(m: ModbusMsg, pdu: bytes) -> None:
    if not pdu:
        return
    func = pdu[0]
    body = pdu[1:]
    if func & 0x80:
        m.func = func & 0x7F
        m.name = FUNCTIONS.get(m.func, f"func-{m.func}")
        m.exception = EXCEPTIONS.get(body[0], f"code-{body[0]}") if body else "unknown"
        return
    m.func = func
    m.name = FUNCTIONS.get(func, f"func-{func}")
    if not m.is_response:
        if func in (1, 2, 3, 4) and len(body) >= 4:
            m.addr, m.count = struct.unpack_from(">HH", body, 0)
        elif func == 5 and len(body) >= 4:
            m.addr = struct.unpack_from(">H", body, 0)[0]
            val = struct.unpack_from(">H", body, 2)[0]
            m.values = [1 if val == 0xFF00 else 0]
            m.count = 1
        elif func == 6 and len(body) >= 4:
            m.addr, val = struct.unpack_from(">HH", body, 0)
            m.values = [val]
            m.count = 1
        elif func == 15 and len(body) >= 5:
            m.addr, m.count = struct.unpack_from(">HH", body, 0)
            nbytes = body[4]
            m.bits = _bits_from(body[5:5 + nbytes], m.count)
        elif func == 16 and len(body) >= 5:
            m.addr, m.count = struct.unpack_from(">HH", body, 0)
            nbytes = body[4]
            regs = body[5:5 + nbytes]
            m.values = [struct.unpack_from(">H", regs, i)[0] for i in range(0, len(regs) - 1, 2)]
        elif func == 22 and len(body) >= 6:
            m.addr, andm, orm = struct.unpack_from(">HHH", body, 0)
            m.values = [andm, orm]
        elif func == 23 and len(body) >= 8:
            r_addr, r_cnt, w_addr, w_cnt = struct.unpack_from(">HHHH", body, 0)
            m.addr, m.count = r_addr, r_cnt
            m.values = [w_addr, w_cnt]
    else:
        if func in (1, 2) and body:
            nbytes = body[0]
            m.bits = _bits_from(body[1:1 + nbytes], nbytes * 8)
        elif func in (3, 4, 23) and body:
            nbytes = body[0]
            regs = body[1:1 + nbytes]
            m.values = [struct.unpack_from(">H", regs, i)[0] for i in range(0, len(regs) - 1, 2)]
        elif func in (5, 6) and len(body) >= 4:
            m.addr, val = struct.unpack_from(">HH", body, 0)
            m.values = [1 if (func == 5 and val == 0xFF00) else val]
        elif func in (15, 16) and len(body) >= 4:
            m.addr, m.count = struct.unpack_from(">HH", body, 0)


def extract(packets, port: int = MODBUS_PORT) -> List[ModbusMsg]:
    out: List[ModbusMsg] = []
    for p in packets:
        if p.proto != "tcp" or not p.payload:
            continue
        if p.sport != port and p.dport != port:
            continue
        is_resp = (p.sport == port)
        buf = p.payload
        off = 0
        while off + 8 <= len(buf):
            tid, pid, length, unit = struct.unpack_from(">HHHB", buf, off)
            if pid != 0 or length < 2 or length > 253 + 2:
                off += 1
                continue
            pdu = buf[off + 7:off + 6 + length]
            m = ModbusMsg(frame=p.index, ts=p.ts, src=p.src or "", dst=p.dst or "",
                          tid=tid, unit=unit, func=0, name="?", is_response=is_resp,
                          raw=pdu)
            _parse_pdu(m, pdu)
            out.append(m)
            off += 6 + length
    return out


def pair(msgs: List[ModbusMsg]) -> List[Tuple[ModbusMsg, Optional[ModbusMsg]]]:
    """Pair requests with the response carrying the same transaction id."""
    pend: Dict[Tuple[str, str, int, int], ModbusMsg] = {}
    pairs: List[Tuple[ModbusMsg, Optional[ModbusMsg]]] = []
    index: Dict[int, int] = {}
    for m in msgs:
        if not m.is_response:
            key = (m.src, m.dst, m.tid, m.unit)
            pend[key] = m
            pairs.append((m, None))
            index[id(m)] = len(pairs) - 1
        else:
            key = (m.dst, m.src, m.tid, m.unit)
            req = pend.pop(key, None)
            if req is not None and id(req) in index:
                i = index[id(req)]
                pairs[i] = (req, m)
    return pairs


def register_map(msgs: List[ModbusMsg]) -> Dict[Tuple[int, int], Dict[str, Any]]:
    """(unit, address) -> observed reads/writes and last value seen."""
    out: Dict[Tuple[int, int], Dict[str, Any]] = {}
    for m in msgs:
        if m.addr is None:
            continue
        n = m.count or 1
        for i in range(n):
            key = (m.unit, m.addr + i)
            e = out.setdefault(key, {"reads": 0, "writes": 0, "last": None, "func": m.name})
            if m.func in (5, 6, 15, 16, 22):
                e["writes"] += 1
                if m.values and i < len(m.values):
                    e["last"] = m.values[i]
                elif m.bits and i < len(m.bits):
                    e["last"] = m.bits[i]
            else:
                e["reads"] += 1
                if m.is_response and m.values and i < len(m.values):
                    e["last"] = m.values[i]
                elif m.is_response and m.bits and i < len(m.bits):
                    e["last"] = m.bits[i]
    return out


def scan_candidates(msgs: List[ModbusMsg], min_units: int = 4) -> Dict[str, Dict[str, Any]]:
    """Hosts that touch many unit ids or many function codes look like scanners."""
    agg: Dict[str, Dict[str, Any]] = {}
    for m in msgs:
        if m.is_response:
            continue
        e = agg.setdefault(m.src, {"units": set(), "funcs": set(), "reqs": 0,
                                    "exceptions": 0, "targets": set()})
        e["units"].add(m.unit)
        e["funcs"].add(m.name)
        e["reqs"] += 1
        e["targets"].add(m.dst)
    for m in msgs:
        if m.is_response and m.exception and m.dst in agg:
            agg[m.dst]["exceptions"] += 1
    return {k: v for k, v in agg.items()
            if len(v["units"]) >= min_units or len(v["funcs"]) >= min_units
            or v["exceptions"] > 0}
