#!/usr/bin/env python3
"""First pass over any capture: hosts, conversations, protocol guesses.

Tells you which ICS protocol you are actually looking at before you reach for
a protocol-specific tool, and flags the hosts that behave like scanners.

    pcap-overview.py capture.pcap [more.pcap ...] [--top 25]
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

import _bootstrap  # noqa: F401
import _common
from icsctf.util import pct, section, table, ts

ICS_PORTS = {
    102: "S7comm / ISO-on-TCP (Siemens)",
    502: "Modbus/TCP",
    2404: "IEC 60870-5-104",
    20000: "DNP3",
    44818: "EtherNet/IP explicit (CIP)",
    2222: "EtherNet/IP implicit I/O (CIP class 1)",
    47808: "BACnet/IP",
    4840: "OPC UA binary",
    1911: "Niagara Fox",
    9600: "OMRON FINS",
    5007: "Mitsubishi MELSEC",
    789: "Red Lion / Crimson",
    1962: "PCWorx",
    2455: "CoDeSys / WAGO",
    18245: "GE SRTP",
    34962: "PROFINET RT",
    34964: "PROFINET context manager",
    55000: "FL-net",
    1089: "FF HSE",
    4000: "Fanuc / misc HMI",
    135: "DCE/RPC (OPC classic bootstrap)",
    1433: "MS SQL Server (TDS)",
    3389: "RDP", 22: "SSH", 23: "Telnet", 21: "FTP", 445: "SMB",
    161: "SNMP", 123: "NTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    5900: "VNC", 3306: "MySQL", 389: "LDAP", 88: "Kerberos",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--top", type=int, default=20, help="rows per table")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, keep_raw=False)
    if not pkts:
        print("no packets decoded")
        return
    total = len(pkts)
    t0, t1 = pkts[0].ts, pkts[-1].ts

    print(f"files        : {', '.join(args.pcap)}")
    print(f"packets      : {total}")
    print(f"first / last : {ts(t0)}  ->  {ts(t1)}")
    print(f"duration     : {t1 - t0:.3f} s")

    l4 = Counter(p.proto or "non-ip" for p in pkts)
    print(section("L4 breakdown"))
    print(table([[k, v, pct(v, total)] for k, v in l4.most_common()],
                ["proto", "packets", "share"]))

    svc = Counter()
    for p in pkts:
        for port in (p.dport, p.sport):
            if port in ICS_PORTS:
                svc[(port, ICS_PORTS[port], p.proto)] += 1
    print(section("recognised services (port-based)"))
    rows = [[f"{k[0]}/{k[2]}", k[1], v] for k, v in svc.most_common(args.top)]
    print(table(rows, ["port", "service", "packets"]))

    unknown = Counter()
    for p in pkts:
        if p.proto in ("tcp", "udp") and p.dport and p.dport not in ICS_PORTS \
                and (p.sport or 0) not in ICS_PORTS and p.payload:
            unknown[(p.dport, p.proto)] += 1
    if unknown:
        print(section("unrecognised ports carrying payload"))
        print(table([[f"{k[0]}/{k[1]}", v] for k, v in unknown.most_common(args.top)],
                    ["port", "packets"]))

    hosts = Counter()
    for p in pkts:
        if p.src:
            hosts[p.src] += 1
    print(section("talkers"))
    print(table([[h, n, pct(n, total)] for h, n in hosts.most_common(args.top)],
                ["host", "packets sent", "share"]))

    convs = Counter()
    for p in pkts:
        if p.src and p.dst:
            convs[(p.src, p.dst, p.dport or 0, p.proto)] += 1
    print(section("conversations"))
    print(table([[f"{k[0]} -> {k[1]}", f"{k[3]}/{k[2]}", v]
                 for k, v in convs.most_common(args.top)],
                ["pair", "proto/dport", "packets"]))

    # scan heuristics
    fanout = defaultdict(set)
    portscan = defaultdict(set)
    syn_only = Counter()
    for p in pkts:
        if not p.src or not p.dst:
            continue
        fanout[p.src].add(p.dst)
        if p.dport:
            portscan[(p.src, p.dst)].add(p.dport)
        if p.proto == "tcp" and p.tcp_flags & 0x02 and not p.tcp_flags & 0x10:
            syn_only[p.src] += 1
    suspects = []
    for h, dsts in fanout.items():
        ports = max((len(v) for (s, _d), v in portscan.items() if s == h), default=0)
        if len(dsts) >= 5 or ports >= 10 or syn_only[h] >= 20:
            suspects.append([h, len(dsts), ports, syn_only[h]])
    if suspects:
        print(section("possible scanning / enumeration"))
        suspects.sort(key=lambda r: (-r[1], -r[2]))
        print(table(suspects, ["host", "distinct peers", "max ports/target", "bare SYNs"]))

    frag = [p for p in pkts if p.frag_mf or p.frag_off]
    if frag:
        print(section("IPv4 fragmentation present"))
        print(f"{len(frag)} fragment packets - reassemble before protocol decoding "
              f"(see tools/pcap-merge.py and Wireshark's defragmentation).")


if __name__ == "__main__":
    main()
