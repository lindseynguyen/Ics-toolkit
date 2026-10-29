#!/usr/bin/env python3
"""Modbus/TCP triage: who talked to which unit, register and coil maps,
writes vs reads, exceptions, scan heuristics, and float reconstruction.

    modbus-triage.py capture.pcap
    modbus-triage.py capture.pcap --map
    modbus-triage.py capture.pcap --writes
    modbus-triage.py capture.pcap --floats --unit 1
    modbus-triage.py capture.pcap --timeline --limit 200
    modbus-triage.py capture.pcap --strings      # ASCII hidden in registers
"""
from __future__ import annotations

import argparse
import struct
from collections import Counter

import _bootstrap  # noqa: F401
from icsctf import modbus, pcapio
from icsctf.util import printable, section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--port", type=int, default=modbus.MODBUS_PORT)
    ap.add_argument("--unit", type=int, help="filter on unit id")
    ap.add_argument("--src")
    ap.add_argument("--map", action="store_true", help="register/coil map")
    ap.add_argument("--writes", action="store_true")
    ap.add_argument("--floats", action="store_true",
                    help="interpret register pairs as IEEE-754 (ABCD and CDAB)")
    ap.add_argument("--strings", action="store_true",
                    help="decode register payloads as ASCII")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    pkts = pcapio.read_many(args.pcap)
    msgs = modbus.extract(pkts, args.port)
    if args.unit is not None:
        msgs = [m for m in msgs if m.unit == args.unit]
    if args.src:
        msgs = [m for m in msgs if m.src == args.src or m.dst == args.src]
    if not msgs:
        print("no Modbus/TCP messages found")
        return

    def overview() -> None:
        print(f"Modbus messages: {len(msgs)}  "
              f"window {ts(msgs[0].ts)} -> {ts(msgs[-1].ts)}")
        print(section("endpoints and unit ids"))
        rows = Counter((m.src, m.dst, m.unit) for m in msgs if not m.is_response)
        print(table([[k[0], k[1], k[2], v] for k, v in rows.most_common()],
                    ["client", "server", "unit", "requests"]))
        print(section("function codes"))
        fc = Counter((m.name, "resp" if m.is_response else "req") for m in msgs)
        print(table([[k[0], k[1], v] for k, v in fc.most_common()],
                    ["function", "dir", "count"]))
        exc = [m for m in msgs if m.exception]
        if exc:
            print(section("exception responses"))
            print(table([[m.frame, ts(m.ts), m.src, m.dst, m.unit, m.name, m.exception]
                         for m in exc[:60]],
                        ["frame", "time", "from", "to", "unit", "function", "exception"]))
        sus = modbus.scan_candidates(msgs)
        if sus:
            print(section("scan / enumeration heuristics"))
            print(table([[h, len(v["units"]), len(v["funcs"]), v["reqs"],
                          v["exceptions"], ",".join(sorted(v["targets"]))]
                         for h, v in sus.items()],
                        ["host", "units touched", "functions", "requests",
                         "exceptions received", "targets"]))

    def regmap() -> None:
        print(section("register / coil map"))
        m = modbus.register_map(msgs)
        rows = [[k[0], k[1], v["func"], v["reads"], v["writes"],
                 v["last"] if v["last"] is not None else "-"]
                for k, v in sorted(m.items())]
        print(table(rows, ["unit", "address", "seen as", "reads", "writes", "last value"]))
        blocks = {}
        for m_ in msgs:
            if m_.is_response or m_.addr is None:
                continue
            key = (m_.unit, m_.name, m_.addr, m_.count or 1)
            blocks[key] = blocks.get(key, 0) + 1
        print(section("requested blocks (start + quantity), as scanned"))
        print(table([[k[0], k[1], k[2], k[3], f"{k[2]}-{k[2] + k[3] - 1}", v]
                     for k, v in sorted(blocks.items())],
                    ["unit", "function", "start", "qty", "range", "times"]))

    def writes() -> None:
        print(section("write operations"))
        rows = []
        for m in msgs:
            if m.is_response or m.func not in (5, 6, 15, 16, 22, 23):
                continue
            vals = m.values or m.bits
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.unit, m.name,
                         m.ref(), ",".join(str(v) for v in vals[:12])])
        print(table(rows, ["frame", "time", "src", "dst", "unit", "function",
                           "address", "value(s)"]))

    def floats() -> None:
        print(section("register pairs as IEEE-754 single"))
        rows = []
        for m in msgs:
            if len(m.values) < 2:
                continue
            base = m.addr if m.addr is not None else 0
            for i in range(0, len(m.values) - 1, 2):
                hi, lo = m.values[i], m.values[i + 1]
                abcd = struct.unpack(">f", struct.pack(">HH", hi, lo))[0]
                cdab = struct.unpack(">f", struct.pack(">HH", lo, hi))[0]
                rows.append([m.frame, m.unit, base + i, hi, lo,
                             round(abcd, 6), round(cdab, 6)])
        print(table(rows[:200], ["frame", "unit", "addr", "reg[n]", "reg[n+1]",
                                 "big-endian (ABCD)", "word-swapped (CDAB)"]))
        print("\nPick the word order that yields values inside the engineering "
              "range of the tag (level in %, flow in gpm, pressure in psi).")

    def strings() -> None:
        print(section("ASCII carried in register payloads"))
        rows = []
        for m in msgs:
            if not m.values:
                continue
            raw = b"".join(struct.pack(">H", v & 0xFFFF) for v in m.values)
            for s in printable(raw, 4):
                rows.append([m.frame, ts(m.ts), m.unit, m.ref(), s])
        print(table(rows[:200], ["frame", "time", "unit", "address", "string"]))

    def timeline() -> None:
        print(section("timeline"))
        rows = []
        for req, resp in modbus.pair(msgs):
            rows.append([req.frame, ts(req.ts), req.src, req.dst, req.summary(),
                         resp.summary() if resp else "(no response)"])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "request", "response"]))

    if args.map:
        regmap()
    elif args.writes:
        writes()
    elif args.floats:
        floats()
    elif args.strings:
        strings()
    elif args.timeline:
        timeline()
    else:
        overview()
        regmap()
        writes()


if __name__ == "__main__":
    main()
