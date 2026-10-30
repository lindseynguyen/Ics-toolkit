#!/usr/bin/env python3
"""DNP3 triage: link-layer addressing, application function codes, IIN flags,
object headers and control (CROB / analog output) operations.

    dnp3-triage.py capture.pcap
    dnp3-triage.py capture.pcap --controls
    dnp3-triage.py capture.pcap --timeline --limit 200
"""
from __future__ import annotations

import argparse
from collections import Counter

import _bootstrap  # noqa: F401
import _common
from icsctf import dnp3
from icsctf.util import section, table, ts

CONTROL_FUNCS = {"select", "operate", "direct-operate", "direct-operate-no-ack",
                 "cold-restart", "warm-restart", "disable-unsolicited",
                 "enable-unsolicited", "stop-application", "write"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--port", type=int, default=dnp3.DNP3_PORT)
    ap.add_argument("--controls", action="store_true")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, ports=[args.port])
    msgs = dnp3.extract(pkts, args.port)
    if not msgs:
        print("no DNP3 frames found")
        return

    print(f"DNP3 frames: {len(msgs)}  window {ts(msgs[0].ts)} -> {ts(msgs[-1].ts)}")
    print(section("link-layer addressing"))
    pairs = Counter((m.src, m.dst, m.link_src, m.link_dst) for m in msgs)
    print(table([[k[0], k[1], k[2], k[3], v] for k, v in pairs.most_common()],
                ["ip src", "ip dst", "dnp3 src", "dnp3 dst", "frames"]))

    print(section("application function codes"))
    fc = Counter(m.app_func for m in msgs if m.app_func)
    print(table([[k, v] for k, v in fc.most_common()], ["function", "count"]))

    iin = Counter(flag for m in msgs for flag in m.iin)
    if iin:
        print(section("internal indications reported by outstations"))
        print(table([[k, v] for k, v in iin.most_common()], ["IIN flag", "count"]))
        print("\ndevice-restart / config-corrupt / event-buffer-overflow after an "
              "intrusion are strong impact indicators.")

    if args.controls or not (args.timeline):
        print(section("control operations"))
        rows = []
        for m in msgs:
            if m.app_func not in CONTROL_FUNCS:
                continue
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.link_src, m.link_dst,
                         m.app_func, "; ".join(m.objects[:3])])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "ip src", "ip dst", "dnp3 src",
                           "dnp3 dst", "function", "objects"]))

    if args.timeline:
        print(section("timeline"))
        rows = []
        for m in msgs:
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.summary()])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "detail"]))


if __name__ == "__main__":
    main()
