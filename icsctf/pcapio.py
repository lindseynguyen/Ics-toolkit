"""Dependency-free pcap / pcapng reader and L2-L4 decoder.

Only the subset needed for ICS traffic triage is implemented:
  * classic libpcap (big + little endian, us + ns timestamps)
  * pcapng (Section Header / Interface Description / Enhanced Packet blocks)
  * Ethernet II, 802.1Q / QinQ, Linux SLL, raw IP
  * IPv4 (incl. fragment flags), IPv6 (no extension-header chains)
  * TCP, UDP

Everything is returned as plain dataclasses so the protocol modules stay
readable and the whole toolkit runs on a stock Python 3.9+ install.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


@dataclass
class Packet:
    index: int          # 1-based frame number, as Wireshark displays it
    ts: float           # epoch seconds
    linktype: int
    raw: bytes          # full captured frame
    src: Optional[str] = None
    dst: Optional[str] = None
    proto: Optional[str] = None     # "tcp" | "udp" | "icmp" | "ip" | None
    sport: Optional[int] = None
    dport: Optional[int] = None
    payload: bytes = b""            # L4 payload
    tcp_flags: int = 0
    tcp_seq: int = 0
    ip_id: int = 0
    frag_off: int = 0
    frag_mf: bool = False
    ttl: int = 0
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

    # --- convenience -----------------------------------------------------
    @property
    def flow(self) -> Tuple[str, int, str, int, str]:
        return (self.src or "", self.sport or 0, self.dst or "", self.dport or 0, self.proto or "")

    @property
    def flow_key(self) -> Tuple:
        """Direction-independent 5-tuple, for grouping both halves of a session."""
        a = (self.src or "", self.sport or 0)
        b = (self.dst or "", self.dport or 0)
        lo, hi = sorted([a, b])
        return (lo, hi, self.proto or "")

    def tcp_flag_str(self) -> str:
        names = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                 (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]
        return "".join(n for bit, n in names if self.tcp_flags & bit) or "-"


# ---------------------------------------------------------------------------
# file layer
# ---------------------------------------------------------------------------
def _ip4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _ip6(b: bytes) -> str:
    parts = [f"{b[i] << 8 | b[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _iter_pcap(data: bytes) -> Iterator[Tuple[float, int, bytes]]:
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise ValueError("not a libpcap file")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        tss, tsu, caplen, _origlen = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if caplen > n - off:
            caplen = n - off
        frame = data[off:off + caplen]
        off += caplen
        ts = tss + (tsu / 1e9 if nano else tsu / 1e6)
        yield ts, linktype, frame


def _iter_pcapng(data: bytes) -> Iterator[Tuple[float, int, bytes]]:
    off = 0
    n = len(data)
    endian = "<"
    iface_link: Dict[int, int] = {}
    iface_tsres: Dict[int, int] = {}
    iface_idx = 0
    while off + 12 <= n:
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:  # Section Header Block - re-read endianness
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            iface_link, iface_tsres, iface_idx = {}, {}, 0
            btype = struct.unpack_from(endian + "I", data, off)[0]
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # IDB
            lt = struct.unpack_from(endian + "H", body, 0)[0]
            tsres = 6
            # walk options for if_tsresol (code 9)
            o = 8
            while o + 4 <= len(body):
                ocode, olen = struct.unpack_from(endian + "HH", body, o)
                oval = body[o + 4:o + 4 + olen]
                if ocode == 0:
                    break
                if ocode == 9 and oval:
                    raw = oval[0]
                    tsres = raw if not (raw & 0x80) else (raw & 0x7F)
                o += 4 + ((olen + 3) & ~3)
            iface_link[iface_idx] = lt
            iface_tsres[iface_idx] = tsres
            iface_idx += 1
        elif btype == 0x00000006:  # EPB
            ifid, tsh, tsl, caplen, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            frame = body[20:20 + caplen]
            res = iface_tsres.get(ifid, 6)
            div = float(10 ** res) if res < 64 else float(2 ** res)
            ts = ((tsh << 32) | tsl) / div
            yield ts, iface_link.get(ifid, LINKTYPE_ETHERNET), frame
        elif btype == 0x00000003:  # Simple Packet Block
            frame = body[4:]
            yield 0.0, iface_link.get(0, LINKTYPE_ETHERNET), frame
        off += blen


def iter_frames(path: str) -> Iterator[Tuple[float, int, bytes]]:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
    else:
        yield from _iter_pcap(data)


# ---------------------------------------------------------------------------
# decode layer
# ---------------------------------------------------------------------------
def _decode_ip(pkt: Packet, buf: bytes) -> None:
    if not buf:
        return
    ver = buf[0] >> 4
    if ver == 4:
        if len(buf) < 20:
            return
        ihl = (buf[0] & 0x0F) * 4
        total = struct.unpack_from(">H", buf, 2)[0]
        pkt.ip_id = struct.unpack_from(">H", buf, 4)[0]
        flags_frag = struct.unpack_from(">H", buf, 6)[0]
        pkt.frag_mf = bool(flags_frag & 0x2000)
        pkt.frag_off = (flags_frag & 0x1FFF) * 8
        pkt.ttl = buf[8]
        proto = buf[9]
        pkt.src, pkt.dst = _ip4(buf[12:16]), _ip4(buf[16:20])
        body = buf[ihl:total] if 0 < total <= len(buf) else buf[ihl:]
    elif ver == 6:
        if len(buf) < 40:
            return
        proto = buf[6]
        pkt.ttl = buf[7]
        pkt.src, pkt.dst = _ip6(buf[8:24]), _ip6(buf[24:40])
        body = buf[40:]
    else:
        return

    if pkt.frag_off:          # non-first fragment: no usable L4 header
        pkt.proto = "ipfrag"
        pkt.payload = body
        return

    if proto == 6:
        pkt.proto = "tcp"
        if len(body) >= 20:
            pkt.sport, pkt.dport = struct.unpack_from(">HH", body, 0)
            pkt.tcp_seq = struct.unpack_from(">I", body, 4)[0]
            doff = (body[12] >> 4) * 4
            pkt.tcp_flags = body[13]
            pkt.payload = body[doff:]
    elif proto == 17:
        pkt.proto = "udp"
        if len(body) >= 8:
            pkt.sport, pkt.dport = struct.unpack_from(">HH", body, 0)
            ulen = struct.unpack_from(">H", body, 4)[0]
            pkt.payload = body[8:ulen] if 8 <= ulen <= len(body) else body[8:]
    elif proto in (1, 58):
        pkt.proto = "icmp"
        pkt.payload = body
    else:
        pkt.proto = f"ip/{proto}"
        pkt.payload = body


def decode(index: int, ts: float, linktype: int, frame: bytes) -> Packet:
    pkt = Packet(index=index, ts=ts, linktype=linktype, raw=frame)
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return pkt
        pkt.eth_dst, pkt.eth_src = _mac(frame[0:6]), _mac(frame[6:12])
        etype = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        while etype in (ETH_P_VLAN, ETH_P_QINQ) and len(frame) >= off + 4:
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        if etype in (ETH_P_IP, ETH_P_IPV6):
            _decode_ip(pkt, frame[off:])
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) >= 16:
            etype = struct.unpack_from(">H", frame, 14)[0]
            if etype in (ETH_P_IP, ETH_P_IPV6):
                _decode_ip(pkt, frame[16:])
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        _decode_ip(pkt, frame)
    return pkt


def read_packets(path: str) -> List[Packet]:
    out: List[Packet] = []
    for i, (ts, lt, frame) in enumerate(iter_frames(path), start=1):
        out.append(decode(i, ts, lt, frame))
    return out


def read_many(paths: List[str], sort_by_time: bool = True) -> List[Packet]:
    """Read several captures as one timeline (for fragmented challenge sets)."""
    pkts: List[Packet] = []
    for p in paths:
        pkts.extend(read_packets(p))
    if sort_by_time:
        pkts.sort(key=lambda p: (p.ts, p.index))
    for i, p in enumerate(pkts, start=1):
        p.index = i
    return pkts


# ---------------------------------------------------------------------------
# TCP stream assembly (sequence-ordered, gap tolerant)
# ---------------------------------------------------------------------------
@dataclass
class TcpStream:
    key: Tuple
    client: Tuple[str, int]
    server: Tuple[str, int]
    to_server: bytes = b""
    to_client: bytes = b""
    packets: List[Packet] = field(default_factory=list)
    syn_ts: Optional[float] = None


def assemble_tcp(packets: List[Packet]) -> Dict[Tuple, TcpStream]:
    """Group TCP packets into streams and order payload bytes by sequence."""
    chunks: Dict[Tuple, Dict[Tuple[str, int], List[Tuple[int, bytes]]]] = {}
    streams: Dict[Tuple, TcpStream] = {}
    for p in packets:
        if p.proto != "tcp":
            continue
        key = p.flow_key
        st = streams.get(key)
        if st is None:
            # client = side that sent SYN without ACK, else first seen
            st = TcpStream(key=key, client=(p.src or "", p.sport or 0),
                           server=(p.dst or "", p.dport or 0))
            streams[key] = st
            chunks[key] = {}
        if p.tcp_flags & 0x02 and not p.tcp_flags & 0x10:
            st.client = (p.src or "", p.sport or 0)
            st.server = (p.dst or "", p.dport or 0)
            st.syn_ts = p.ts
        st.packets.append(p)
        if p.payload:
            side = (p.src or "", p.sport or 0)
            chunks[key].setdefault(side, []).append((p.tcp_seq, p.payload))

    for key, st in streams.items():
        for side, segs in chunks[key].items():
            seen: Dict[int, bytes] = {}
            for seq, data in segs:
                if seq not in seen or len(data) > len(seen[seq]):
                    seen[seq] = data
            blob = b"".join(seen[s] for s in sorted(seen))
            if side == st.client:
                st.to_server += blob
            else:
                st.to_client += blob
    return streams


def tcp_messages(packets: List[Packet], ports: Tuple[int, ...]) -> Iterator[Tuple[Packet, bytes]]:
    """Yield (packet, payload) for TCP packets touching any of `ports`."""
    for p in packets:
        if p.proto == "tcp" and p.payload and (p.sport in ports or p.dport in ports):
            yield p, p.payload


def udp_messages(packets: List[Packet], ports: Tuple[int, ...]) -> Iterator[Tuple[Packet, bytes]]:
    for p in packets:
        if p.proto == "udp" and p.payload and (p.sport in ports or p.dport in ports):
            yield p, p.payload
