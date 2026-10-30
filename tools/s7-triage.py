#!/usr/bin/env python3
"""S7comm / S7comm-plus triage for Siemens PLC traffic.

Surfaces: who connected, which SZL diagnostic identifiers were requested
(fingerprinting), which blocks were uploaded or downloaded (logic change),
CPU STOP / PLC control attempts and whether the PLC refused them, and every
variable write with its IEEE-754 value.

    s7-triage.py capture.pcap
    s7-triage.py capture.pcap --szl
    s7-triage.py capture.pcap --blocks
    s7-triage.py capture.pcap --writes --src 10.10.20.55
    s7-triage.py capture.pcap --timeline --limit 120
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

import _bootstrap  # noqa: F401
import _common
from icsctf import s7comm
from icsctf.util import section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--port", type=int, default=s7comm.ISO_TSAP_PORT)
    ap.add_argument("--src")
    ap.add_argument("--dst")
    ap.add_argument("--szl", action="store_true", help="SZL reads only")
    ap.add_argument("--blocks", action="store_true", help="block up/download only")
    ap.add_argument("--writes", action="store_true", help="write-var only")
    ap.add_argument("--control", action="store_true", help="PLC control / stop only")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, ports=[args.port])
    msgs = s7comm.extract(pkts, args.port)
    if args.src:
        msgs = [m for m in msgs if m.src == args.src]
    if args.dst:
        msgs = [m for m in msgs if m.dst == args.dst]
    if not msgs:
        print("no S7 traffic found on port %d" % args.port)
        return

    def hosts() -> None:
        print(section("endpoints"))
        clients = Counter(m.src for m in msgs if m.rosctr in ("job", "userdata", "connect-request"))
        servers = Counter(m.src for m in msgs if m.rosctr in ("ack-data", "ack", "connect-confirm"))
        rows = []
        for h in sorted(set(list(clients) + list(servers))):
            rows.append([h, clients[h], servers[h],
                         "client/engineering station" if clients[h] > servers[h] else "PLC/server"])
        print(table(rows, ["host", "requests", "responses", "likely role"]))
        pairs = Counter((m.src, m.dst) for m in msgs if m.rosctr in ("job", "userdata"))
        print(table([[k[0], k[1], v] for k, v in pairs.most_common()],
                    ["client", "plc", "requests"]))

    def szl() -> None:
        print(section("SZL (System Status List) reads"))
        rows = []
        for m in msgs:
            if m.szl_id is None:
                continue
            rows.append([m.frame, ts(m.ts), m.src, m.dst, f"0x{m.szl_id:04x}",
                         m.szl_index if m.szl_index is not None else "-",
                         s7comm.SZL_IDS.get(m.szl_id, "unknown"), m.rosctr])
        print(table(rows, ["frame", "time", "src", "dst", "szl-id", "index",
                           "meaning", "dir"]))
        agg = s7comm.szl_summary(msgs)
        if agg:
            print(section("distinct SZL ids per source (ascending)"))
            per_src = defaultdict(list)
            for (src, sid), n in agg.items():
                per_src[src].append(sid)
            for src, ids in per_src.items():
                ids = sorted(set(ids))
                print(f"{src}: " + ", ".join(f"0x{i:04x}" for i in ids))

    def blocks() -> None:
        print(section("block upload / download (logic transfer)"))
        rows = []
        for m in msgs:
            if m.function not in ("request-download", "download-block", "download-ended",
                                  "start-upload", "upload", "end-upload"):
                continue
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.function,
                         m.block or "-", m.filename or "-", m.rosctr,
                         m.error or ""])
        print(table(rows, ["frame", "time", "src", "dst", "function", "block",
                           "filename", "dir", "error"]))
        uploaded = sorted({m.block for m in msgs
                           if m.block and m.function in ("request-download", "download-block")})
        if uploaded:
            print("\ndistinct blocks pushed to the PLC: " + ", ".join(uploaded))
        downloaded = sorted({m.block for m in msgs
                             if m.block and m.function in ("start-upload", "upload")})
        if downloaded:
            print("distinct blocks read out of the PLC: " + ", ".join(downloaded))

    def writes() -> None:
        print(section("variable access"))
        rows = []
        for m in msgs:
            if m.function not in ("write-var", "read-var") or not m.items:
                continue
            for it in m.items:
                rows.append([m.frame, ts(m.ts), m.src, m.dst, m.function,
                             it.tag(), it.area, it.count, it.transport,
                             it.value if it.value is not None else "-",
                             it.rc or "-"])
        print(table(rows, ["frame", "time", "src", "dst", "op", "tag", "area",
                           "count", "type", "value", "rc"]))
        wr = [r for r in rows if r[4] == "write-var"]
        if wr:
            print(section("written values (IEEE-754 reals rounded)"))
            print(table([[r[0], r[5], r[9]] for r in wr], ["frame", "tag", "value"]))

    def control() -> None:
        print(section("PLC control / CPU state changes"))
        rows = []
        for m in msgs:
            if m.function not in ("plc-control", "plc-stop") and m.group != "mode-transition":
                continue
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.function or m.group,
                         m.service or "-", m.rosctr, m.error or "-", m.detail])
        print(table(rows, ["frame", "time", "src", "dst", "function", "service",
                           "dir", "error", "note"]))
        print("\nA job answered with an ack-data carrying a non-zero error class "
              "means the CPU refused the request. Common causes: the CPU keyswitch "
              "is in RUN-P/RUN (not remote-settable), the protection level requires "
              "a password, or know-how protection is active. Cross-check the PLC's "
              "diagnostic buffer (SZL 0x00A0) and the mode-transition cause "
              "(SZL 0x0424) for the exact reason text.")

    def timeline() -> None:
        print(section("timeline"))
        rows = []
        for m in msgs:
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.pduref, m.summary()])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "pduref", "detail"]))

    if args.szl:
        szl()
    elif args.blocks:
        blocks()
    elif args.writes:
        writes()
    elif args.control:
        control()
    elif args.timeline:
        timeline()
    else:
        print(f"S7 messages: {len(msgs)}  window {ts(msgs[0].ts)} -> {ts(msgs[-1].ts)}")
        fam = Counter(m.proto for m in msgs)
        print(table([[k, v] for k, v in fam.items()], ["protocol", "messages"]))
        hosts()
        funcs = Counter((m.src, m.function or m.subfunc or m.rosctr) for m in msgs)
        print(section("functions used"))
        print(table([[k[0], k[1], v] for k, v in funcs.most_common()],
                    ["src", "function", "count"]))
        szl()
        blocks()
        writes()
        control()


if __name__ == "__main__":
    main()
