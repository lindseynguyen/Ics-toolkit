#!/usr/bin/env python3
"""IEC 60870-5-104 triage: APCI session state, ASDU inventory, IOA map,
command timeline and select-before-operate auditing.

    iec104-triage.py capture.pcap
    iec104-triage.py capture.pcap --commands
    iec104-triage.py capture.pcap --ioa
    iec104-triage.py capture.pcap --sbo
    iec104-triage.py capture.pcap --timeline --limit 200
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

import _bootstrap  # noqa: F401
import _common
from icsctf import iec104
from icsctf.util import section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--port", type=int, default=iec104.IEC104_PORT)
    ap.add_argument("--commands", action="store_true", help="control direction only")
    ap.add_argument("--ioa", action="store_true", help="information-object map")
    ap.add_argument("--sbo", action="store_true", help="select-before-operate audit")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, ports=[args.port])
    msgs = iec104.extract(pkts, args.port)
    if not msgs:
        print("no IEC-104 APDUs found")
        return

    def overview() -> None:
        print(f"APDUs: {len(msgs)}  window {ts(msgs[0].ts)} -> {ts(msgs[-1].ts)}")
        fmt = Counter(m.fmt for m in msgs)
        print(section("APCI formats"))
        print(table([[k, v] for k, v in fmt.items()], ["format", "count"]))
        u = [m for m in msgs if m.fmt == "U"]
        if u:
            print(section("session control (U-format)"))
            print(table([[m.frame, ts(m.ts), m.src, m.dst, m.ufunc] for m in u],
                        ["frame", "time", "src", "dst", "function"]))
            print("\nSTARTDT act/con opens data transfer; STOPDT act stops the "
                  "monitored direction without closing TCP - a quiet way to blind "
                  "an operator while the link still looks up.")
        types = Counter((m.type_name, m.cot) for m in msgs if m.type_id is not None)
        print(section("ASDU types seen"))
        print(table([[k[0], k[1], v] for k, v in types.most_common()],
                    ["type", "cause of transmission", "count"]))
        ca = Counter(m.ca for m in msgs if m.ca is not None)
        print(section("common addresses (stations)"))
        print(table([[k, v] for k, v in ca.most_common()], ["CA (ASDU address)", "count"]))
        neg = [m for m in msgs if m.negative]
        if neg:
            print(section("negative confirmations (command rejected)"))
            print(table([[m.frame, ts(m.ts), m.src, m.dst, m.type_name, m.cot,
                          "; ".join(str(o) for o in m.objects[:3])] for m in neg],
                        ["frame", "time", "src", "dst", "type", "cot", "objects"]))

    def commands() -> None:
        print(section("control-direction timeline"))
        rows = []
        for m in iec104.command_timeline(msgs):
            for o in (m.objects or [None]):
                rows.append([m.frame, ts(m.ts), m.src, m.dst, m.type_name, m.cot,
                             m.ca, o.ioa if o else "-",
                             o.value if o and o.value is not None else "-",
                             ("SELECT" if o and o.select else
                              "EXECUTE" if o and o.select is False else "-"),
                             "NEG" if m.negative else ""])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "type", "cot", "CA",
                           "IOA", "value", "S/E", "flag"]))
        print("\nTypical correct order for a controlled output: "
              "C_xx act(SELECT) -> actcon -> C_xx act(EXECUTE) -> actcon -> actterm. "
              "A command whose actcon carries P/N=negative was refused by the device.")

    def ioa_map() -> None:
        print(section("information object map"))
        agg: dict = defaultdict(lambda: {"count": 0, "types": set(), "last": None,
                                         "dirs": set()})
        for m in msgs:
            for o in m.objects:
                e = agg[(m.ca, o.ioa)]
                e["count"] += 1
                e["types"].add(m.type_name or "?")
                e["last"] = o.value
                e["dirs"].add("control" if m.type_id in iec104.COMMAND_TYPES else "monitor")
        rows = [[k[0], k[1], v["count"], ",".join(sorted(v["dirs"])),
                 "; ".join(sorted(v["types"]))[:60],
                 v["last"] if v["last"] is not None else "-"]
                for k, v in sorted(agg.items(), key=lambda kv: (kv[0][0] or 0, kv[0][1]))]
        print(table(rows, ["CA", "IOA", "sightings", "direction", "types", "last value"]))

    def sbo() -> None:
        print(section("select-before-operate audit"))
        f = iec104.sbo_check(msgs)
        if not f:
            print("no SBO anomalies detected")
            return
        print(table([[x["frame"], ts(x["ts"]), x["ca"], x["ioa"], x["type"], x["issue"]]
                     for x in f],
                    ["frame", "time", "CA", "IOA", "type", "finding"]))

    def timeline() -> None:
        print(section("APDU timeline"))
        rows = []
        for m in msgs:
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.summary()])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "detail"]))

    if args.commands:
        commands()
    elif args.ioa:
        ioa_map()
    elif args.sbo:
        sbo()
    elif args.timeline:
        timeline()
    else:
        overview()
        commands()
        ioa_map()
        sbo()


if __name__ == "__main__":
    main()
