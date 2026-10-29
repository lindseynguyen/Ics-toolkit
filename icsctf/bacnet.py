"""BACnet/IP (BVLC + NPDU + APDU) decoder focused on incident triage.

Covers what matters when a BMS gets attacked: who talked to whom, which
confirmed services were invoked, DeviceCommunicationControl /
ReinitializeDevice attempts with their password field, WriteProperty targets
and values, and whether each request was acknowledged or rejected.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

BACNET_PORT = 47808  # 0xBAC0

BVLC_FUNCTIONS = {
    0x00: "bvlc-result", 0x01: "write-broadcast-distribution-table",
    0x02: "read-broadcast-distribution-table", 0x03: "read-bdt-ack",
    0x04: "forwarded-npdu", 0x05: "register-foreign-device",
    0x06: "read-foreign-device-table", 0x07: "read-fdt-ack",
    0x08: "delete-fdt-entry", 0x09: "distribute-broadcast-to-network",
    0x0A: "original-unicast-npdu", 0x0B: "original-broadcast-npdu",
    0x0C: "secure-bvll",
}

PDU_TYPES = {
    0: "confirmed-request", 1: "unconfirmed-request", 2: "simple-ack",
    3: "complex-ack", 4: "segment-ack", 5: "error", 6: "reject", 7: "abort",
}

CONFIRMED_SERVICES = {
    0: "acknowledgeAlarm", 1: "confirmedCOVNotification", 2: "confirmedEventNotification",
    3: "getAlarmSummary", 4: "getEnrollmentSummary", 5: "subscribeCOV",
    6: "atomicReadFile", 7: "atomicWriteFile", 8: "addListElement",
    9: "removeListElement", 10: "createObject", 11: "deleteObject",
    12: "readProperty", 13: "readPropertyConditional", 14: "readPropertyMultiple",
    15: "writeProperty", 16: "writePropertyMultiple", 17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer", 19: "confirmedTextMessage", 20: "reinitializeDevice",
    21: "vtOpen", 22: "vtClose", 23: "vtData", 24: "authenticate", 25: "requestKey",
    26: "readRange", 27: "lifeSafetyOperation", 28: "subscribeCOVProperty",
    29: "getEventInformation",
}

UNCONFIRMED_SERVICES = {
    0: "i-Am", 1: "i-Have", 2: "unconfirmedCOVNotification",
    3: "unconfirmedEventNotification", 4: "unconfirmedPrivateTransfer",
    5: "unconfirmedTextMessage", 6: "timeSynchronization", 7: "who-Has",
    8: "who-Is", 9: "utcTimeSynchronization", 10: "writeGroup",
}

OBJECT_TYPES = {
    0: "analog-input", 1: "analog-output", 2: "analog-value", 3: "binary-input",
    4: "binary-output", 5: "binary-value", 6: "calendar", 7: "command",
    8: "device", 9: "event-enrollment", 10: "file", 11: "group", 12: "loop",
    13: "multi-state-input", 14: "multi-state-output", 15: "notification-class",
    16: "program", 17: "schedule", 18: "averaging", 19: "multi-state-value",
    20: "trend-log", 21: "life-safety-point", 22: "life-safety-zone",
    23: "accumulator", 24: "pulse-converter", 25: "event-log", 26: "global-group",
    27: "trend-log-multiple", 28: "load-control", 29: "structured-view",
    30: "access-door", 36: "access-point", 39: "credential-data-input",
    40: "network-security", 41: "bitstring-value", 45: "integer-value",
    56: "network-port",
}

# Wireshark-style short codes used in several CTF answer formats
OBJECT_ABBR = {
    0: "AI", 1: "AO", 2: "AV", 3: "BI", 4: "BO", 5: "BV", 8: "DEV",
    13: "MSI", 14: "MSO", 19: "MSV", 16: "PROG", 17: "SCHED", 30: "DOOR",
}

PROPERTIES = {
    12: "change-of-state-time", 28: "description", 36: "event-state",
    75: "object-identifier", 77: "object-name", 79: "object-type",
    81: "out-of-service", 85: "present-value", 87: "priority-array",
    103: "reliability", 104: "relinquish-default", 107: "segmentation-supported",
    111: "status-flags", 112: "system-status", 117: "units",
    121: "vendor-identifier", 139: "protocol-revision", 155: "database-revision",
    371: "property-list",
}

ERROR_CLASS = {0: "device", 1: "object", 2: "property", 3: "resources",
               4: "security", 5: "services", 6: "vt", 7: "communication"}
ERROR_CODE = {
    7: "inconsistent-parameters", 9: "invalid-data-type", 25: "operational-problem",
    26: "password-failure", 27: "read-access-denied", 28: "security-not-supported",
    29: "service-request-denied", 40: "write-access-denied", 42: "invalid-tag",
    45: "missing-required-parameter", 58: "value-out-of-range",
}
ENABLE_DISABLE = {0: "enable", 1: "disable", 2: "disable-initiation"}
REINIT_STATE = {0: "coldstart", 1: "warmstart", 2: "startbackup", 3: "endbackup",
                4: "startrestore", 5: "endrestore", 6: "abortrestore"}


# ---------------------------------------------------------------------------
# ASN.1-ish tag walker
# ---------------------------------------------------------------------------
@dataclass
class Tag:
    number: int
    context: bool
    opening: bool = False
    closing: bool = False
    data: bytes = b""

    def uint(self) -> int:
        return int.from_bytes(self.data, "big") if self.data else 0

    def text(self) -> str:
        """BACnet CharacterString: first byte is the encoding id."""
        if not self.data:
            return ""
        enc, raw = self.data[0], self.data[1:]
        if enc == 4:   # UCS-2
            return raw.decode("utf-16-be", "replace")
        return raw.decode("utf-8", "replace") if enc == 0 else raw.decode("latin-1", "replace")

    def real(self) -> Optional[float]:
        return struct.unpack(">f", self.data[:4])[0] if len(self.data) >= 4 else None

    def double(self) -> Optional[float]:
        return struct.unpack(">d", self.data[:8])[0] if len(self.data) >= 8 else None

    def objid(self) -> Optional[Tuple[int, int]]:
        if len(self.data) < 4:
            return None
        v = struct.unpack(">I", self.data[:4])[0]
        return (v >> 22) & 0x3FF, v & 0x3FFFFF


def parse_tags(buf: bytes, limit: int = 256) -> List[Tag]:
    """Walk a BACnet tag stream. Robust against truncation."""
    out: List[Tag] = []
    i, n = 0, len(buf)
    while i < n and len(out) < limit:
        b = buf[i]
        i += 1
        num = b >> 4
        context = bool(b & 0x08)
        lvt = b & 0x07
        if num == 0x0F:
            if i >= n:
                break
            num = buf[i]
            i += 1
        if context and lvt == 6:
            out.append(Tag(num, True, opening=True))
            continue
        if context and lvt == 7:
            out.append(Tag(num, True, closing=True))
            continue
        if lvt < 5:
            ln = lvt
        elif lvt == 5:
            if i >= n:
                break
            ln = buf[i]
            i += 1
            if ln == 254:
                ln = struct.unpack_from(">H", buf, i)[0]
                i += 2
            elif ln == 255:
                ln = struct.unpack_from(">I", buf, i)[0]
                i += 4
        else:
            ln = 0
        data = buf[i:i + ln]
        i += ln
        out.append(Tag(num, context, data=data))
    return out


def objid_str(pair: Optional[Tuple[int, int]], abbr: bool = False) -> str:
    if not pair:
        return "?"
    otype, inst = pair
    if abbr:
        return f"{OBJECT_ABBR.get(otype, str(otype))}:{inst}"
    return f"{OBJECT_TYPES.get(otype, 'type-' + str(otype))}:{inst}"


def tag_value(t: Tag) -> Any:
    """Best-effort rendering of an application-tagged value."""
    if t.context:
        return t.data.hex()
    k = t.number
    if k == 0:
        return None
    if k == 1:
        return bool(t.data and t.data[0])
    if k == 2:
        return t.uint()
    if k == 3:
        v = t.uint()
        bits = len(t.data) * 8
        return v - (1 << bits) if v & (1 << (bits - 1)) else v
    if k == 4:
        return t.real()
    if k == 5:
        return t.double()
    if k == 6:
        return t.data.hex()
    if k == 7:
        return t.text()
    if k == 8:
        return "bitstring:" + t.data.hex()
    if k == 9:
        return t.uint()          # enumerated
    if k == 12:
        return objid_str(t.objid())
    return t.data.hex()


# ---------------------------------------------------------------------------
# message model
# ---------------------------------------------------------------------------
@dataclass
class BacnetMsg:
    frame: int
    ts: float
    src: str
    dst: str
    bvlc: str
    pdu_type: str
    service: Optional[str] = None
    invoke_id: Optional[int] = None
    snet: Optional[int] = None
    dnet: Optional[int] = None
    # service specifics
    object_id: Optional[str] = None
    object_abbr: Optional[str] = None
    prop: Optional[str] = None
    value: Any = None
    priority: Optional[int] = None
    password: Optional[str] = None
    enable_disable: Optional[str] = None
    duration: Optional[int] = None
    reinit_state: Optional[str] = None
    error: Optional[str] = None
    tags: List[Tag] = field(default_factory=list)
    raw_apdu: bytes = b""

    def summary(self) -> str:
        bits = [self.service or self.pdu_type]
        if self.object_id:
            bits.append(self.object_id)
        if self.prop:
            bits.append(self.prop)
        if self.value is not None:
            bits.append(f"= {self.value}")
        if self.priority is not None:
            bits.append(f"prio {self.priority}")
        if self.enable_disable:
            bits.append(self.enable_disable)
        if self.reinit_state:
            bits.append(self.reinit_state)
        if self.password is not None:
            bits.append(f"pw={self.password!r}")
        if self.error:
            bits.append(f"[{self.error}]")
        return " ".join(bits)


def _decode_service(msg: BacnetMsg, svc: int, body: bytes) -> None:
    tags = parse_tags(body)
    msg.tags = tags
    name = CONFIRMED_SERVICES.get(svc)
    if name in ("readProperty", "writeProperty"):
        for t in tags:
            if t.context and t.number == 0:
                oid = t.objid()
                msg.object_id = objid_str(oid)
                msg.object_abbr = objid_str(oid, abbr=True)
            elif t.context and t.number == 1:
                p = t.uint()
                msg.prop = PROPERTIES.get(p, f"prop-{p}")
            elif t.context and t.number == 3 and name == "writeProperty":
                msg.priority = t.uint()
        if name == "writeProperty":
            inside = False
            for t in tags:
                if t.context and t.number == 3 and t.opening:
                    inside = True
                    continue
                if t.context and t.number == 3 and t.closing:
                    inside = False
                    continue
                if inside and not t.context:
                    msg.value = tag_value(t)
            # priority is context tag 4 when the value is wrapped in 3
            for t in tags:
                if t.context and t.number == 4 and t.data:
                    msg.priority = t.uint()
    elif name == "deviceCommunicationControl":
        for t in tags:
            if not t.context:
                continue
            if t.number == 0:
                msg.duration = t.uint()
            elif t.number == 1:
                msg.enable_disable = ENABLE_DISABLE.get(t.uint(), str(t.uint()))
            elif t.number == 2:
                msg.password = t.text()
    elif name == "reinitializeDevice":
        for t in tags:
            if not t.context:
                continue
            if t.number == 0:
                msg.reinit_state = REINIT_STATE.get(t.uint(), str(t.uint()))
            elif t.number == 1:
                msg.password = t.text()
    elif name in ("atomicReadFile", "atomicWriteFile"):
        for t in tags:
            if not t.context and t.number == 12:
                msg.object_id = objid_str(t.objid())
    elif name == "subscribeCOV":
        for t in tags:
            if t.context and t.number == 1:
                msg.object_id = objid_str(t.objid())


def decode_apdu(msg: BacnetMsg, apdu: bytes) -> None:
    if not apdu:
        return
    msg.raw_apdu = apdu
    ptype = apdu[0] >> 4
    msg.pdu_type = PDU_TYPES.get(ptype, f"pdu-{ptype}")
    if ptype == 0:  # confirmed request
        flags = apdu[0] & 0x0F
        segmented = bool(flags & 0x08)
        off = 3
        if segmented:
            off += 2
        if len(apdu) <= off:
            return
        msg.invoke_id = apdu[2]
        svc = apdu[off]
        msg.service = CONFIRMED_SERVICES.get(svc, f"confirmed-{svc}")
        _decode_service(msg, svc, apdu[off + 1:])
    elif ptype == 1:  # unconfirmed
        if len(apdu) < 2:
            return
        svc = apdu[1]
        msg.service = UNCONFIRMED_SERVICES.get(svc, f"unconfirmed-{svc}")
        tags = parse_tags(apdu[2:])
        msg.tags = tags
        if msg.service == "i-Am":
            for t in tags:
                if not t.context and t.number == 12:
                    msg.object_id = objid_str(t.objid())
        elif msg.service in ("who-Is", "who-Has"):
            vals = [tag_value(t) for t in tags if t.data]
            msg.value = ",".join(str(v) for v in vals) or None
    elif ptype == 2:  # simple ack
        if len(apdu) >= 3:
            msg.invoke_id = apdu[1]
            msg.service = CONFIRMED_SERVICES.get(apdu[2], f"confirmed-{apdu[2]}")
    elif ptype == 3:  # complex ack
        flags = apdu[0] & 0x0F
        off = 3 if not (flags & 0x08) else 5
        if len(apdu) >= 3:
            msg.invoke_id = apdu[1]
            svc = apdu[2]
            msg.service = CONFIRMED_SERVICES.get(svc, f"confirmed-{svc}")
            tags = parse_tags(apdu[3:])
            msg.tags = tags
            for t in tags:
                if t.context and t.number == 0:
                    msg.object_id = objid_str(t.objid())
                elif t.context and t.number == 1 and t.data:
                    p = t.uint()
                    msg.prop = PROPERTIES.get(p, f"prop-{p}")
            inside = False
            for t in tags:
                if t.context and t.number == 3 and t.opening:
                    inside = True
                    continue
                if t.context and t.number == 3 and t.closing:
                    inside = False
                    continue
                if inside and not t.context:
                    msg.value = tag_value(t)
    elif ptype == 5:  # error
        if len(apdu) >= 3:
            msg.invoke_id = apdu[1]
            msg.service = CONFIRMED_SERVICES.get(apdu[2], f"confirmed-{apdu[2]}")
            tags = parse_tags(apdu[3:])
            vals = [t.uint() for t in tags if not t.context and t.number == 9]
            if len(vals) >= 2:
                msg.error = f"{ERROR_CLASS.get(vals[0], vals[0])}/{ERROR_CODE.get(vals[1], vals[1])}"
            elif vals:
                msg.error = str(vals[0])
    elif ptype in (6, 7):
        if len(apdu) >= 3:
            msg.invoke_id = apdu[1]
            msg.error = f"{msg.pdu_type}-reason-{apdu[2]}"


def parse_packet(pkt) -> Optional[BacnetMsg]:
    """pkt is an icsctf.pcapio.Packet carrying a BVLC payload."""
    data = pkt.payload
    if len(data) < 4 or data[0] != 0x81:
        return None
    func = data[1]
    length = struct.unpack_from(">H", data, 2)[0]
    body = data[4:length] if 4 < length <= len(data) else data[4:]
    msg = BacnetMsg(frame=pkt.index, ts=pkt.ts, src=pkt.src or "", dst=pkt.dst or "",
                    bvlc=BVLC_FUNCTIONS.get(func, f"bvlc-{func:#02x}"), pdu_type="-")
    if func == 0x04 and len(body) >= 6:   # forwarded-NPDU carries the origin IP
        msg.src = ".".join(str(x) for x in body[0:4])
        body = body[6:]
    if func == 0x00:                      # BVLC-Result
        msg.pdu_type = "bvlc-result"
        if len(body) >= 2:
            msg.value = struct.unpack_from(">H", body, 0)[0]
        return msg
    if not body:
        return msg
    # NPDU
    ver = body[0]
    if ver != 1:
        return msg
    ctrl = body[1] if len(body) > 1 else 0
    i = 2
    if ctrl & 0x20 and len(body) >= i + 3:
        msg.dnet = struct.unpack_from(">H", body, i)[0]
        dlen = body[i + 2]
        i += 3 + dlen
    if ctrl & 0x08 and len(body) >= i + 3:
        msg.snet = struct.unpack_from(">H", body, i)[0]
        slen = body[i + 2]
        i += 3 + slen
    if ctrl & 0x20:
        i += 1                            # hop count
    if ctrl & 0x80:
        msg.pdu_type = "network-layer-message"
        if len(body) > i:
            msg.value = f"type {body[i]:#02x}"
        return msg
    decode_apdu(msg, body[i:])
    return msg


def extract(packets, port: int = BACNET_PORT) -> List[BacnetMsg]:
    out: List[BacnetMsg] = []
    for p in packets:
        if p.proto != "udp":
            continue
        if p.sport != port and p.dport != port and not (p.payload[:1] == b"\x81"):
            continue
        m = parse_packet(p)
        if m:
            out.append(m)
    return out


def correlate(msgs: List[BacnetMsg]) -> Dict[Tuple[str, str, int], Dict[str, Any]]:
    """Pair confirmed requests with their SimpleACK / ComplexACK / Error.

    Key: (requester, target, invoke_id) of the latest request seen; the value
    records the outcome so password attempts can be counted as
    failed vs successful without eyeballing the capture.
    """
    pending: Dict[Tuple[str, str, int], BacnetMsg] = {}
    results: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    for m in msgs:
        if m.pdu_type == "confirmed-request" and m.invoke_id is not None:
            key = (m.src, m.dst, m.invoke_id)
            pending[key] = m
            results[key] = {"request": m, "outcome": "no-response", "response": None}
        elif m.pdu_type in ("simple-ack", "complex-ack", "error", "reject", "abort") \
                and m.invoke_id is not None:
            key = (m.dst, m.src, m.invoke_id)
            if key in results:
                results[key]["outcome"] = "ok" if m.pdu_type.endswith("ack") else m.pdu_type
                results[key]["response"] = m
    return results
