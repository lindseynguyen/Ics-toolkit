"""S7comm / ISO-on-TCP (RFC1006) decoder for Siemens S7-300/400 traffic.

Decodes the layers an analyst actually needs during an ICS intrusion review:
  TPKT -> COTP -> S7 header -> job/ack parameters
and surfaces the hostile operations: Read/Write Var (with IEEE-754 values),
SZL diagnostic reads (fingerprinting), block upload/download (logic changes)
and PLC Control / PLC Stop (CPU STOP).

S7comm-plus (S7-1200/1500, protocol id 0x72) is recognised and classified at
the opcode/function level; its payload is proprietary and only summarised.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ISO_TSAP_PORT = 102

ROSCTR = {0x01: "job", 0x02: "ack", 0x03: "ack-data", 0x07: "userdata"}

FUNCTIONS = {
    0x00: "cpu-services", 0x04: "read-var", 0x05: "write-var",
    0xF0: "setup-communication",
    0x1A: "request-download", 0x1B: "download-block", 0x1C: "download-ended",
    0x1D: "start-upload", 0x1E: "upload", 0x1F: "end-upload",
    0x28: "plc-control", 0x29: "plc-stop",
}

AREAS = {
    0x03: "S7-200-sys", 0x1C: "counter-S7-200", 0x1D: "timer-S7-200",
    0x80: "P (peripheral IO)", 0x81: "I (inputs)", 0x82: "Q (outputs)",
    0x83: "M (flags/merkers)", 0x84: "DB (data block)", 0x85: "DI (instance DB)",
    0x86: "L (local data)", 0x87: "V (prev local)",
    0x1E: "counter", 0x1F: "timer",
}

TRANSPORT_SIZE = {
    0x00: "null", 0x03: "bit", 0x04: "byte/word/dword", 0x05: "integer",
    0x06: "dint", 0x07: "real", 0x09: "octet-string", 0x0A: "string",
}

RETURN_CODES = {
    0x00: "n/a (request)", 0x01: "hardware-fault", 0x03: "access-denied",
    0x05: "invalid-address", 0x06: "data-type-not-supported",
    0x07: "data-type-inconsistent", 0x0A: "object-does-not-exist",
    0xFF: "success",
}

# Two-character ASCII block type codes used in S7 block filenames
BLOCK_TYPES = {
    "08": "OB", "09": "CMOD", "0A": "DB", "0B": "SDB", "0C": "FC",
    "0D": "SFC", "0E": "FB", "0F": "SFB", "10": "SDBS",
}

# Frequently abused SZL (System Status List) identifiers
SZL_IDS = {
    0x0011: "module identification (order number / CPU type)",
    0x001C: "component identification (plant/module name, serial)",
    0x0012: "CPU characteristics",
    0x0013: "memory areas",
    0x0014: "system areas",
    0x0019: "LED status",
    0x0024: "CPU operating-mode transitions",
    0x0074: "LED status (single)",
    0x0091: "module status information",
    0x0092: "rack / station status",
    0x0094: "rack / station status (expanded)",
    0x00A0: "diagnostic buffer entries",
    0x0132: "communication status data",
    0x0232: "CPU protection level / password status",
    0x0424: "mode-transition cause (STOP cause)",
}

USERDATA_GROUPS = {
    0x00: "mode-transition", 0x01: "programmer-commands", 0x02: "cyclic-services",
    0x03: "block-functions", 0x04: "cpu-functions", 0x05: "security",
    0x06: "pbc-bsend/brcv", 0x07: "time-functions", 0x0F: "ncprg",
}
CPU_SUBFUNCS = {0x01: "read-szl", 0x02: "msg-service", 0x03: "diagnostic-message",
                0x11: "alarm-ack", 0x13: "alarm-init"}
SEC_SUBFUNCS = {0x01: "plc-password-login", 0x02: "plc-password-logout"}


@dataclass
class S7Item:
    area: str
    db: int
    byte_addr: int
    bit_addr: int
    count: int
    transport: str
    value_raw: bytes = b""
    value: Any = None
    rc: Optional[str] = None

    def tag(self) -> str:
        if self.area.startswith("DB"):
            return f"DB{self.db}.DBX{self.byte_addr}.{self.bit_addr}"
        letter = self.area.split()[0]
        return f"{letter}{self.byte_addr}.{self.bit_addr}"


@dataclass
class S7Msg:
    frame: int
    ts: float
    src: str
    dst: str
    proto: str = "s7comm"
    rosctr: str = "-"
    pduref: int = 0
    function: Optional[str] = None
    error: Optional[str] = None
    items: List[S7Item] = field(default_factory=list)
    szl_id: Optional[int] = None
    szl_index: Optional[int] = None
    block: Optional[str] = None
    filename: Optional[str] = None
    service: Optional[str] = None
    group: Optional[str] = None
    subfunc: Optional[str] = None
    detail: str = ""
    raw: bytes = b""

    def summary(self) -> str:
        bits = [self.proto, self.rosctr, self.function or self.subfunc or ""]
        if self.szl_id is not None:
            bits.append(f"SZL-ID 0x{self.szl_id:04x} ({SZL_IDS.get(self.szl_id, 'unknown')})")
        if self.block:
            bits.append(f"block {self.block}")
        if self.service:
            bits.append(f"service {self.service!r}")
        for it in self.items:
            v = f"={it.value}" if it.value is not None else ""
            bits.append(f"{it.tag()}[{it.count} {it.transport}]{v}")
        if self.error:
            bits.append(f"[{self.error}]")
        if self.detail:
            bits.append(self.detail)
        return " ".join(b for b in bits if b)


def _tpkt_pdus(stream: bytes):
    """Yield COTP payloads from a reassembled ISO-on-TCP byte stream."""
    i, n = 0, len(stream)
    while i + 4 <= n:
        if stream[i] != 0x03:
            i += 1
            continue
        ln = struct.unpack_from(">H", stream, i + 2)[0]
        if ln < 7 or i + ln > n:
            break
        tpdu = stream[i + 4:i + ln]
        i += ln
        if not tpdu:
            continue
        li = tpdu[0]
        ptype = tpdu[1] if len(tpdu) > 1 else 0
        payload = tpdu[1 + li:]
        yield ptype, payload


def _decode_items(param: bytes, data: bytes, writing: bool) -> List[S7Item]:
    items: List[S7Item] = []
    if len(param) < 2:
        return items
    count = param[1]
    off = 2
    for _ in range(count):
        if off + 2 > len(param):
            break
        spec, ln = param[off], param[off + 1]
        blk = param[off + 2:off + 2 + ln]
        off += 2 + ln
        if spec != 0x12 or len(blk) < 8:
            continue
        # syntax id blk[0], transport blk[1], count blk[2:4], db blk[4:6],
        # area blk[6], address blk[7:10] (bit address)
        tsize = TRANSPORT_SIZE.get(blk[1], f"0x{blk[1]:02x}")
        cnt = struct.unpack_from(">H", blk, 2)[0]
        db = struct.unpack_from(">H", blk, 4)[0]
        area = AREAS.get(blk[6], f"area-0x{blk[6]:02x}")
        addr = int.from_bytes(blk[7:10], "big") if len(blk) >= 10 else 0
        items.append(S7Item(area=area, db=db, byte_addr=addr >> 3,
                            bit_addr=addr & 0x07, count=cnt, transport=tsize))
    # data part
    doff = 0
    for it in items:
        if doff + 4 > len(data):
            break
        rc = data[doff]
        tsz = data[doff + 1]
        length = struct.unpack_from(">H", data, doff + 2)[0]
        nbytes = length // 8 if tsz in (0x03, 0x04, 0x05, 0x06, 0x07) and tsz != 0x09 else length
        if tsz in (0x09, 0x0A):
            nbytes = length
        raw = data[doff + 4:doff + 4 + nbytes]
        it.rc = RETURN_CODES.get(rc, f"0x{rc:02x}")
        it.value_raw = raw
        it.value = _interpret(raw, it)
        doff += 4 + nbytes + (nbytes % 2)   # fill byte between items
    return items


def _interpret(raw: bytes, it: S7Item) -> Any:
    if not raw:
        return None
    if it.transport == "real" or (len(raw) == 4 and it.count * 4 == len(raw)):
        try:
            return round(struct.unpack(">f", raw[:4])[0], 6)
        except struct.error:
            pass
    if len(raw) == 1:
        return raw[0]
    if len(raw) == 2:
        return struct.unpack(">h", raw)[0]
    if len(raw) == 4:
        return struct.unpack(">i", raw)[0]
    return raw.hex()


def _decode_s7(msg: S7Msg, pdu: bytes) -> None:
    if len(pdu) < 10 or pdu[0] != 0x32:
        return
    msg.rosctr = ROSCTR.get(pdu[1], f"rosctr-{pdu[1]}")
    msg.pduref = struct.unpack_from(">H", pdu, 4)[0]
    plen = struct.unpack_from(">H", pdu, 6)[0]
    dlen = struct.unpack_from(">H", pdu, 8)[0]
    hoff = 10
    if pdu[1] in (0x02, 0x03) and len(pdu) >= 12:
        ec, ecode = pdu[10], pdu[11]
        if ec or ecode:
            msg.error = f"class 0x{ec:02x} code 0x{ecode:02x}"
        hoff = 12
    param = pdu[hoff:hoff + plen]
    data = pdu[hoff + plen:hoff + plen + dlen]
    if not param:
        return
    fn = param[0]
    msg.function = FUNCTIONS.get(fn, f"func-0x{fn:02x}")
    if fn in (0x04, 0x05):
        msg.items = _decode_items(param, data, writing=(fn == 0x05))
    elif fn in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
        txt = bytes(b for b in param[1:] if 32 <= b < 127).decode("ascii", "replace")
        if "_" in txt:
            fname = txt[txt.index("_"):]
            msg.filename = fname
            if len(fname) >= 9:
                bt = BLOCK_TYPES.get(fname[1:3], fname[1:3])
                num = fname[3:8]
                msg.block = f"{bt}{num.lstrip('0') or '0'} (fs {fname[8]})"
    elif fn in (0x28, 0x29):
        txt = bytes(b for b in param[1:] if 32 <= b < 127).decode("ascii", "replace")
        msg.service = txt.strip() or None
        if fn == 0x29:
            msg.detail = "CPU STOP requested"
        elif "P_PROGRAM" in txt:
            msg.detail = "program invocation (restart/hot start)"
    elif fn == 0xF0 and len(param) >= 8:
        pdu_len = struct.unpack_from(">H", param, 6)[0]
        msg.detail = f"negotiated PDU length {pdu_len}"
    # userdata
    if msg.rosctr == "userdata" and len(param) >= 8:
        grp = param[5] & 0x0F if len(param) > 5 else 0
        sub = param[6] if len(param) > 6 else 0
        msg.group = USERDATA_GROUPS.get(grp, f"group-{grp}")
        if grp == 0x04:
            msg.subfunc = CPU_SUBFUNCS.get(sub, f"sub-0x{sub:02x}")
            if sub == 0x01 and len(data) >= 6:
                msg.szl_id = struct.unpack_from(">H", data, 4)[0]
                if len(data) >= 8:
                    msg.szl_index = struct.unpack_from(">H", data, 6)[0]
        elif grp == 0x05:
            msg.subfunc = SEC_SUBFUNCS.get(sub, f"sub-0x{sub:02x}")
            pw = bytes(b for b in data[4:] if 32 <= b < 127)
            if pw:
                msg.detail = f"password-blob {data[4:].hex()}"
        else:
            msg.subfunc = f"sub-0x{sub:02x}"
        msg.function = msg.function or "userdata"


S7PLUS_OPCODES = {0x31: "request", 0x32: "response", 0x33: "notification"}
S7PLUS_FUNCS = {
    0x04BB: "GetMultiVariables", 0x04CA: "SetMultiVariables",
    0x04D4: "SetVariable", 0x04F2: "GetVarSubStreamed",
    0x0542: "SetVarSubStreamed", 0x0586: "CreateObject",
    0x04D8: "DeleteObject", 0x0524: "Explore", 0x0556: "GetLink",
    0x0560: "BeginSequence", 0x0561: "EndSequence", 0x0562: "Invoke",
}


def _decode_s7plus(msg: S7Msg, pdu: bytes) -> None:
    msg.proto = "s7comm-plus"
    if len(pdu) < 6:
        return
    opcode = pdu[2] if len(pdu) > 2 else 0
    msg.rosctr = S7PLUS_OPCODES.get(opcode, f"opcode-0x{opcode:02x}")
    if len(pdu) >= 7:
        fn = struct.unpack_from(">H", pdu, 5)[0]
        msg.function = S7PLUS_FUNCS.get(fn, f"function-0x{fn:04x}")
    msg.detail = f"{len(pdu)} bytes proprietary payload"


def extract(packets, port: int = ISO_TSAP_PORT) -> List[S7Msg]:
    """Decode S7 traffic. Each TCP packet is parsed on its own; that is enough
    for CTF-sized captures and avoids mis-ordering reassembled streams."""
    out: List[S7Msg] = []
    for p in packets:
        if p.proto != "tcp" or not p.payload:
            continue
        if p.sport != port and p.dport != port:
            continue
        for ptype, pdu in _tpkt_pdus(p.payload):
            msg = S7Msg(frame=p.index, ts=p.ts, src=p.src or "", dst=p.dst or "", raw=pdu)
            if ptype == 0xE0:
                msg.proto, msg.rosctr = "cotp", "connect-request"
                msg.detail = "TSAP negotiation"
                out.append(msg)
                continue
            if ptype == 0xD0:
                msg.proto, msg.rosctr = "cotp", "connect-confirm"
                out.append(msg)
                continue
            if not pdu:
                continue
            if pdu[0] == 0x32:
                _decode_s7(msg, pdu)
            elif pdu[0] == 0x72:
                _decode_s7plus(msg, pdu)
            else:
                continue
            out.append(msg)
    return out


def szl_summary(msgs: List[S7Msg]) -> Dict[Tuple[str, int], int]:
    """(source ip, szl id) -> count, for fingerprinting-activity questions."""
    out: Dict[Tuple[str, int], int] = {}
    for m in msgs:
        if m.szl_id is not None and m.rosctr == "userdata":
            key = (m.src, m.szl_id)
            out[key] = out.get(key, 0) + 1
    return out
