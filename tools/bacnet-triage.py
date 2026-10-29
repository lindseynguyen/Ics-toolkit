#!/usr/bin/env python3
"""BACnet/IP incident triage.

Answers the questions a BMS compromise raises: which device is foreign to the
segment, which confirmed services were used against which objects, how many
DeviceCommunicationControl / ReinitializeDevice password attempts were made,
which of them succeeded, and in what order the zones were touched.

    bacnet-triage.py capture.pcap                      # full report
    bacnet-triage.py capture.pcap --dcc                 # password attempts only
    bacnet-triage.py capture.pcap --timeline --src 10.0.0.9
    bacnet-triage.py capture.pcap --writes
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

import _bootstrap  # noqa: F401
from icsctf import bacnet, pcapio
from icsctf.util import section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--port", type=int, default=bacnet.BACNET_PORT)
    ap.add_argument("--src", help="filter on source IP")
    ap.add_argument("--dst", help="filter on destination IP")
    ap.add_argument("--service", help="filter on service name substring")
    ap.add_argument("--timeline", action="store_true", help="print every message")
    ap.add_argument("--dcc", action="store_true",
                    help="DeviceCommunicationControl / ReinitializeDevice attempts")
    ap.add_argument("--writes", action="store_true", help="writeProperty activity only")
    ap.add_argument("--devices", action="store_true", help="device inventory only")
    ap.add_argument("--limit", type=int, default=0, help="cap timeline rows")
    args = ap.parse_args()

    pkts = pcapio.read_many(args.pcap)
    msgs = bacnet.extract(pkts, args.port)
    if args.src:
        msgs = [m for m in msgs if m.src == args.src]
    if args.dst:
        msgs = [m for m in msgs if m.dst == args.dst]
    if args.service:
        msgs = [m for m in msgs if m.service and args.service.lower() in m.service.lower()]
    if not msgs:
        print("no BACnet/IP messages found")
        return

    results = bacnet.correlate(msgs)

    def show_devices() -> None:
        print(section("device inventory"))
        rows = []
        iam = {}
        for m in msgs:
            if m.service == "i-Am" and m.object_id:
                iam[m.src] = m.object_id
        talkers = Counter(m.src for m in msgs)
        responders = Counter(m.src for m in msgs
                             if m.pdu_type in ("simple-ack", "complex-ack", "error"))
        requesters = Counter(m.src for m in msgs if m.pdu_type == "confirmed-request")
        for host, n in talkers.most_common():
            role = []
            if requesters[host]:
                role.append(f"client({requesters[host]} req)")
            if responders[host]:
                role.append(f"server({responders[host]} resp)")
            rows.append([host, iam.get(host, "-"), n, " ".join(role) or "-"])
        print(table(rows, ["ip", "i-Am object", "messages", "role"]))
        # a host that only issues requests and never answers is usually foreign
        foreign = [h for h in requesters if not responders[h] and h not in iam]
        if foreign:
            print("\nhosts that only issue requests and never answer BACnet "
                  "(no i-Am of their own) - candidate rogue devices:")
            for h in foreign:
                first = next(m for m in msgs if m.src == h)
                print(f"  {h}  first seen frame {first.frame} at {ts(first.ts)}")

    def show_services() -> None:
        print(section("service usage"))
        agg = Counter((m.src, m.dst, m.service or m.pdu_type) for m in msgs
                      if m.pdu_type in ("confirmed-request", "unconfirmed-request"))
        print(table([[k[0], k[1], k[2], v] for k, v in agg.most_common()],
                    ["src", "dst", "service", "count"]))

    def show_dcc() -> None:
        print(section("DeviceCommunicationControl / ReinitializeDevice attempts"))
        rows = []
        per_target: dict = defaultdict(lambda: {"attempts": 0, "failed": 0, "ok": 0})
        for key, res in results.items():
            m = res["request"]
            if m.service not in ("deviceCommunicationControl", "reinitializeDevice"):
                continue
            resp = res["response"]
            outcome = res["outcome"]
            if resp is not None and resp.error:
                outcome = resp.error
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.service,
                         m.enable_disable or m.reinit_state or "-",
                         repr(m.password) if m.password is not None else "-",
                         outcome])
            st = per_target[(m.src, m.dst)]
            st["attempts"] += 1
            if res["outcome"] == "ok":
                st["ok"] += 1
            else:
                st["failed"] += 1
        rows.sort(key=lambda r: r[0])
        print(table(rows, ["frame", "time", "src", "target", "service",
                           "state", "password", "outcome"]))
        if per_target:
            print(section("attempts per (attacker, target) pair"))
            print(table([[k[0], k[1], v["attempts"], v["failed"], v["ok"]]
                         for k, v in sorted(per_target.items(),
                                            key=lambda kv: -kv[1]["attempts"])],
                        ["src", "target", "total attempts", "failed/no-resp", "accepted"]))
            print("\nnote: 'accepted' counts requests answered with a SimpleACK. A "
                  "password-failure Error PDU (class security) is the failed case.")
            succeeded = [r for r in rows if r[7] == "ok" and r[6] != "-"]
            if succeeded:
                print("\npasswords that were accepted:")
                for r in succeeded:
                    print(f"  frame {r[0]}  {r[2]} -> {r[3]}  {r[6]}")

    def show_writes() -> None:
        print(section("writeProperty / write-like activity"))
        rows = []
        for key, res in results.items():
            m = res["request"]
            if m.service not in ("writeProperty", "writePropertyMultiple",
                                 "atomicWriteFile", "createObject", "deleteObject",
                                 "subscribeCOV", "addListElement", "removeListElement"):
                continue
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.service,
                         m.object_id or "-", m.object_abbr or "-", m.prop or "-",
                         m.value if m.value is not None else "-",
                         m.priority if m.priority is not None else "-",
                         res["outcome"]])
        rows.sort(key=lambda r: r[0])
        print(table(rows, ["frame", "time", "src", "target", "service", "object",
                           "abbr", "property", "value", "prio", "outcome"]))
        objs = Counter((r[3], r[6]) for r in rows if r[6] != "-")
        if objs:
            print(section("objects written, grouped by target device"))
            per_dev = defaultdict(list)
            for (dev, abbr), n in objs.items():
                per_dev[dev].append(f"{abbr} x{n}")
            print(table([[d, ", ".join(v)] for d, v in per_dev.items()],
                        ["target", "objects (wireshark short form)"]))

    def show_timeline() -> None:
        print(section("message timeline"))
        rows = []
        for m in msgs:
            rows.append([m.frame, ts(m.ts), m.src, m.dst, m.bvlc,
                         m.invoke_id if m.invoke_id is not None else "-", m.summary()])
            if args.limit and len(rows) >= args.limit:
                break
        print(table(rows, ["frame", "time", "src", "dst", "bvlc", "iid", "detail"]))

    if args.dcc:
        show_dcc()
    elif args.writes:
        show_writes()
    elif args.devices:
        show_devices()
    elif args.timeline:
        show_timeline()
    else:
        print(f"BACnet messages: {len(msgs)}  "
              f"window {ts(msgs[0].ts)} -> {ts(msgs[-1].ts)}")
        show_devices()
        show_services()
        show_dcc()
        show_writes()
        print(section("last non-read service against each device"))
        rows = []
        last: dict = {}
        for m in msgs:
            if m.pdu_type != "confirmed-request" or not m.service:
                continue
            if m.service.startswith("read"):
                continue
            last[m.dst] = m
        for dst, m in last.items():
            rows.append([dst, m.frame, ts(m.ts), m.src, m.service, m.summary()])
        print(table(rows, ["device", "frame", "time", "src", "service", "detail"]))


if __name__ == "__main__":
    main()
