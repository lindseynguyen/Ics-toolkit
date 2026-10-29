#!/usr/bin/env python3
"""Turn a capture into deployable detections.

Profiles the capture, works out which hosts legitimately speak each
industrial protocol, then writes Suricata rules, a Zeek policy and Sigma
rules for the operations that matter - with the host groups filled in and a
README explaining what to check before deploying.

    make-rules.py capture.pcap                      # print a summary
    make-rules.py capture.pcap --out rules/         # write the rule set
    make-rules.py capture.pcap --format suricata    # just one format, to stdout
    make-rules.py baseline.pcap incident.pcap --out rules/
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
import _common
from icsctf import rules
from icsctf.util import section, table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--out", metavar="DIR", help="write the rule set into this directory")
    ap.add_argument("--format", choices=["suricata", "zeek", "sigma", "all"],
                    default="all")
    ap.add_argument("--only-observed", action="store_true",
                    help="emit only rules for operations seen in this capture "
                         "(by default rules are emitted for the whole protocol, "
                         "because a detection is for what has not happened yet)")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    filters = {}
    if args.max_packets:
        filters["limit"] = args.max_packets
    since = _common.parse_time(args.since)
    until = _common.parse_time(args.until)
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until

    prof = rules.profile_capture(args.pcap, **filters)
    if not prof.protocols:
        print("no industrial protocol found in this capture - nothing to base "
              "rules on. Run pcap-overview.py first.")
        return

    print(section("what the capture shows"))
    rows = []
    for proto in sorted(prof.protocols):
        rows.append([proto,
                     ", ".join(sorted(prof.servers.get(proto, set()))) or "-",
                     ", ".join(sorted(prof.clients.get(proto, set()) - prof.suspects)) or "-"])
    print(table(rows, ["protocol", "devices (answer requests)",
                       "approved clients (inferred)"]))
    if prof.suspects:
        print("\nexcluded from the allow-lists, because they behaved like a "
              "tool during this capture:")
        for h in sorted(prof.suspects):
            print(f"  {h}")
    if prof.observed:
        print(section("operations observed"))
        for k in sorted(prof.observed):
            print(f"  {k}")

    blocks = {}
    if args.format in ("suricata", "all"):
        blocks["ot-rules.rules"] = rules.suricata(prof, args.only_observed)
    if args.format in ("zeek", "all"):
        blocks["ot-detections.zeek"] = rules.zeek(prof)
    if args.format in ("sigma", "all"):
        blocks["sigma/ot-host-rules.yml"] = rules.sigma(prof)
    if args.format == "all":
        blocks["README.md"] = rules.readme(prof)

    if not args.out:
        if args.format == "all":
            print(section("rule set preview"))
            for name, text in blocks.items():
                print(f"\n----- {name} ({len(text.splitlines())} lines) -----")
                print("\n".join(text.splitlines()[:14]))
                print("  ...")
            print("\nPass --out DIR to write the full set.")
        else:
            print()
            print(next(iter(blocks.values())))
        return

    os.makedirs(args.out, exist_ok=True)
    written = []
    for name, text in blocks.items():
        path = os.path.join(args.out, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        written.append((name, len(text.splitlines())))
    print(section("written"))
    print(table([[os.path.join(args.out, n), f"{ln} lines"] for n, ln in written],
                ["file", "size"]))
    print("\nRead README.md in that directory before deploying: the host groups "
          "come from one capture and need checking against your asset inventory, "
          "and the enumeration thresholds need measuring against your own "
          "normal poll rate.")


if __name__ == "__main__":
    main()
