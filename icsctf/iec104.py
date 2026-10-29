"""IEC 60870-5-104 decoder: APCI framing, ASDU type ids, IOA map and command
sequencing (select-before-operate), plus float setpoint extraction.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

IEC104_PORT = 2404

TYPE_IDS = {
    1: "M_SP_NA_1 single-point", 2: "M_SP_TA_1 single-point+t",
    3: "M_DP_NA_1 double-point", 5: "M_ST_NA_1 step-position",
    7: "M_BO_NA_1 bitstring32", 9: "M_ME_NA_1 measured normalized",
    11: "M_ME_NB_1 measured scaled", 13: "M_ME_NC_1 measured short-float",
    15: "M_IT_NA_1 integrated totals", 20: "M_PS_NA_1 packed single-point",
    21: "M_ME_ND_1 measured normalized (no quality)",
    30: "M_SP_TB_1 single-point+CP56", 31: "M_DP_TB_1 double-point+CP56",
    32: "M_ST_TB_1 step-position+CP56", 34: "M_ME_TD_1 normalized+CP56",
    35: "M_ME_TE_1 scaled+CP56", 36: "M_ME_TF_1 short-float+CP56",
    37: "M_IT_TB_1 totals+CP56", 38: "M_EP_TD_1 protection event+CP56",
    45: "C_SC_NA_1 single command", 46: "C_DC_NA_1 double command",
    47: "C_RC_NA_1 regulating step command",
    48: "C_SE_NA_1 setpoint normalized", 49: "C_SE_NB_1 setpoint scaled",
    50: "C_SE_NC_1 setpoint short-float", 51: "C_BO_NA_1 bitstring32 command",
    58: "C_SC_TA_1 single command+CP56", 59: "C_DC_TA_1 double command+CP56",
    60: "C_RC_TA_1 regulating step+CP56", 61: "C_SE_TA_1 setpoint norm+CP56",
    62: "C_SE_TB_1 setpoint scaled+CP56", 63: "C_SE_TC_1 setpoint float+CP56",
    70: "M_EI_NA_1 end of initialisation",
    100: "C_IC_NA_1 interrogation command",
    101: "C_CI_NA_1 counter interrogation",
    102: "C_RD_NA_1 read command", 103: "C_CS_NA_1 clock sync",
    104: "C_TS_NA_1 test command", 105: "C_RP_NA_1 reset process",
    106: "C_CD_NA_1 delay acquisition", 107: "C_TS_TA_1 test command+CP56",
    110: "P_ME_NA_1 parameter normalized", 111: "P_ME_NB_1 parameter scaled",
    112: "P_ME_NC_1 parameter short-float", 113: "P_AC_NA_1 parameter activation",
    120: "F_FR_NA_1 file ready", 122: "F_SC_NA_1 call directory/file",
    126: "F_DR_TA_1 directory",
}

COT = {
    1: "periodic/cyclic", 2: "background scan", 3: "spontaneous",
    4: "initialised", 5: "request/requested", 6: "activation",
    7: "activation confirmation", 8: "deactivation",
    9: "deactivation confirmation", 10: "activation termination",
    11: "remote command feedback", 12: "local command feedback",
    13: "file transfer", 20: "interrogated by station",
    21: "interrogated by group 1", 37: "requested by counter general",
    44: "unknown type id", 45: "unknown cause of transmission",
    46: "unknown common address", 47: "unknown IOA",
}

U_FUNCS = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act",
           0x23: "STOPDT con", 0x43: "TESTFR act", 0x83: "TESTFR con"}

QOI = {20: "station interrogation (global)", 21: "group 1", 22: "group 2"}
QU = {0: "no additional definition", 1: "short pulse", 2: "long pulse",
      3: "persistent output"}


@dataclass
class InfoObject:
    ioa: int
    value: Any = None
    quality: Optional[str] = None
    select: Optional[bool] = None
    qualifier: Optional[str] = None

    def __str__(self) -> str:
        s = f"IOA {self.ioa}"
        if self.value is not None:
            s += f" = {self.value}"
        if self.select is not None:
            s += " [SELECT]" if self.select else " [EXECUTE]"
        if self.qualifier:
            s += f" ({self.qualifier})"
        if self.quality:
            s += f" {self.quality}"
        return s


@dataclass
class Iec104Msg:
    frame: int
    ts: float
    src: str
    dst: str
    fmt: str                   # I / S / U
    ufunc: Optional[str] = None
    tx: Optional[int] = None
    rx: Optional[int] = None
    type_id: Optional[int] = None
    type_name: Optional[str] = None
    cot: Optional[str] = None
    negative: bool = False
    test: bool = False
    ca: Optional[int] = None
    sq: bool = False
    objects: List[InfoObject] = field(default_factory=list)
    raw: bytes = b""

    def summary(self) -> str:
        if self.fmt == "U":
            return f"U-format {self.ufunc}"
        if self.fmt == "S":
            return f"S-format ack rx={self.rx}"
        bits = [f"I tx={self.tx} rx={self.rx}", self.type_name or "?",
                f"CA={self.ca}", f"COT={self.cot}"]
        if self.negative:
            bits.append("NEGATIVE-CONFIRM")
        if self.test:
            bits.append("TEST")
        if self.objects:
            bits.append("; ".join(str(o) for o in self.objects[:6]))
            if len(self.objects) > 6:
                bits.append(f"(+{len(self.objects) - 6} more)")
        return " ".join(bits)


def _quality(b: int) -> str:
    flags = []
    if b & 0x01:
        flags.append("OV")
    if b & 0x10:
        flags.append("BL")
    if b & 0x20:
        flags.append("SB")
    if b & 0x40:
        flags.append("NT")
    if b & 0x80:
        flags.append("IV")
    return "/".join(flags)


def _parse_objects(type_id: int, sq: bool, num: int, body: bytes) -> List[InfoObject]:
    objs: List[InfoObject] = []
    off = 0

    def ioa_at(o: int) -> int:
        return int.from_bytes(body[o:o + 3], "little") if o + 3 <= len(body) else 0

    # element size (value+quality+time) per type
    sizes = {1: 1, 3: 1, 5: 2, 7: 5, 9: 3, 11: 3, 13: 5, 15: 5, 21: 2,
             30: 8, 31: 8, 32: 9, 34: 10, 35: 10, 36: 12, 37: 12,
             45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 5,
             58: 8, 59: 8, 60: 8, 61: 10, 62: 10, 63: 12,
             70: 1, 100: 1, 101: 1, 102: 0, 103: 7, 104: 2, 105: 1,
             110: 3, 111: 3, 112: 5, 113: 1}
    esz = sizes.get(type_id, 1)

    base_ioa = None
    for i in range(max(1, num)):
        if sq:
            if i == 0:
                base_ioa = ioa_at(off)
                off += 3
            ioa = (base_ioa or 0) + i
        else:
            ioa = ioa_at(off)
            off += 3
        el = body[off:off + esz]
        off += esz
        o = InfoObject(ioa=ioa)
        if type_id == 1 and el:
            o.value = el[0] & 0x01
            o.quality = _quality(el[0])
        elif type_id == 3 and el:
            o.value = {0: "indeterminate", 1: "OFF", 2: "ON", 3: "indeterminate"}.get(el[0] & 0x03)
            o.quality = _quality(el[0])
        elif type_id in (9, 21, 34) and len(el) >= 2:
            raw = struct.unpack_from("<h", el, 0)[0]
            o.value = round(raw / 32767.0, 6)
            if len(el) >= 3:
                o.quality = _quality(el[2])
        elif type_id in (11, 35) and len(el) >= 2:
            o.value = struct.unpack_from("<h", el, 0)[0]
            if len(el) >= 3:
                o.quality = _quality(el[2])
        elif type_id in (13, 36) and len(el) >= 4:
            o.value = round(struct.unpack_from("<f", el, 0)[0], 6)
            if len(el) >= 5:
                o.quality = _quality(el[4])
        elif type_id in (30,) and el:
            o.value = el[0] & 0x01
            o.quality = _quality(el[0])
        elif type_id in (45, 58) and el:
            sco = el[0]
            o.value = "ON" if sco & 0x01 else "OFF"
            o.select = bool(sco & 0x80)
            o.qualifier = QU.get((sco >> 2) & 0x1F, f"QU {(sco >> 2) & 0x1F}")
        elif type_id in (46, 59) and el:
            dco = el[0]
            o.value = {1: "OFF", 2: "ON"}.get(dco & 0x03, "indeterminate")
            o.select = bool(dco & 0x80)
        elif type_id in (47, 60) and el:
            rco = el[0]
            o.value = {1: "DOWN", 2: "UP"}.get(rco & 0x03, "indeterminate")
            o.select = bool(rco & 0x80)
        elif type_id in (48, 61) and len(el) >= 3:
            o.value = round(struct.unpack_from("<h", el, 0)[0] / 32767.0, 6)
            o.select = bool(el[2] & 0x80)
        elif type_id in (49, 62) and len(el) >= 3:
            o.value = struct.unpack_from("<h", el, 0)[0]
            o.select = bool(el[2] & 0x80)
        elif type_id in (50, 63) and len(el) >= 5:
            o.value = round(struct.unpack_from("<f", el, 0)[0], 6)
            o.select = bool(el[4] & 0x80)
        elif type_id == 100 and el:
            o.value = QOI.get(el[0], f"QOI {el[0]}")
        elif type_id == 105 and el:
            o.value = f"QRP {el[0]}"
        elif el:
            o.value = el.hex()
        objs.append(o)
        if off > len(body):
            break
    return objs


def extract(packets, port: int = IEC104_PORT) -> List[Iec104Msg]:
    out: List[Iec104Msg] = []
    for p in packets:
        if p.proto != "tcp" or not p.payload:
            continue
        if p.sport != port and p.dport != port:
            continue
        buf = p.payload
        off = 0
        while off + 2 <= len(buf):
            if buf[off] != 0x68:
                off += 1
                continue
            ln = buf[off + 1]
            apdu = buf[off + 2:off + 2 + ln]
            off += 2 + ln
            if len(apdu) < 4:
                break
            c1, c2, c3, c4 = apdu[0], apdu[1], apdu[2], apdu[3]
            m = Iec104Msg(frame=p.index, ts=p.ts, src=p.src or "", dst=p.dst or "",
                          fmt="I", raw=apdu)
            if c1 & 0x01 == 0:
                m.fmt = "I"
                m.tx = ((c2 << 8) | c1) >> 1
                m.rx = ((c4 << 8) | c3) >> 1
                asdu = apdu[4:]
                if len(asdu) >= 6:
                    m.type_id = asdu[0]
                    m.type_name = TYPE_IDS.get(asdu[0], f"type-{asdu[0]}")
                    vsq = asdu[1]
                    m.sq = bool(vsq & 0x80)
                    num = vsq & 0x7F
                    cot_b = asdu[2]
                    m.cot = COT.get(cot_b & 0x3F, str(cot_b & 0x3F))
                    m.negative = bool(cot_b & 0x40)
                    m.test = bool(cot_b & 0x80)
                    m.ca = struct.unpack_from("<H", asdu, 4)[0]
                    m.objects = _parse_objects(asdu[0], m.sq, num, asdu[6:])
            elif c1 & 0x03 == 0x01:
                m.fmt = "S"
                m.rx = ((c4 << 8) | c3) >> 1
            else:
                m.fmt = "U"
                m.ufunc = U_FUNCS.get(c1, f"0x{c1:02x}")
            out.append(m)
    return out


COMMAND_TYPES = {45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63,
                 100, 101, 102, 103, 104, 105}


def command_timeline(msgs: List[Iec104Msg]) -> List[Iec104Msg]:
    return [m for m in msgs if m.type_id in COMMAND_TYPES]


def sbo_check(msgs: List[Iec104Msg]) -> List[Dict[str, Any]]:
    """Flag commands executed without a preceding select on the same IOA
    (select-before-operate violations), and selects never executed."""
    selected: Dict[Tuple[int, int], Iec104Msg] = {}
    findings: List[Dict[str, Any]] = []
    for m in msgs:
        if m.type_id not in COMMAND_TYPES or not m.objects:
            continue
        # only the control direction matters: activation requests, not the
        # confirmations the device echoes back
        if m.cot != "activation":
            continue
        for o in m.objects:
            if o.select is None:
                continue
            key = (m.ca or 0, o.ioa)
            if o.select:
                selected[key] = m
            else:
                if key not in selected:
                    findings.append({"frame": m.frame, "ts": m.ts, "ioa": o.ioa,
                                     "ca": m.ca, "issue": "execute without select",
                                     "type": m.type_name})
                else:
                    selected.pop(key, None)
    for key, m in selected.items():
        findings.append({"frame": m.frame, "ts": m.ts, "ioa": key[1], "ca": key[0],
                         "issue": "select never executed", "type": m.type_name})
    return findings
