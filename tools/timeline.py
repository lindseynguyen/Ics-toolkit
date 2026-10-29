#!/usr/bin/env python3
"""Build one incident timeline from every artefact in a case.

Captures and text logs become the same kind of record - UTC time, actor,
target, what happened, and a reference you can check - merged in time order.
This is the view an incident report needs and the one a capture alone cannot
give you.

    timeline.py evidence/*                        # everything, merged
    timeline.py capture.pcap auth.log --min-severity 2
    timeline.py evidence/* --csv timeline.csv --md timeline.md
    timeline.py capture.pcap --since 10:40 --until 11:10
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
import _common
from icsctf import timeline
from icsctf.util import section, table

SEV = {"context": 0, "recon": 1, "suspicious": 2, "impact": 3}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="captures, logs, exports - in any mix")
    ap.add_argument("--min-severity", default="context",
                    choices=list(SEV) + [str(i) for i in range(4)],
                    help="context | recon | suspicious | impact (default context)")
    ap.add_argument("--log-year", type=int, metavar="YYYY",
                    help="year for syslog-style lines, which carry no year "
                         "(default: the file's modification year)")
    ap.add_argument("--keep-unmatched", action="store_true",
                    help="keep log lines that match no rule (noisy, but complete)")
    ap.add_argument("--csv", metavar="FILE", help="write the timeline as CSV")
    ap.add_argument("--json", metavar="FILE", help="write the timeline as JSON")
    ap.add_argument("--md", metavar="FILE", help="write the timeline as Markdown")
    ap.add_argument("--gaps", type=float, default=0, metavar="SECONDS",
                    help="also report quiet periods longer than this")
    ap.add_argument("--detail", action="store_true",
                    help="print the raw line or message behind each event")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    min_sev = SEV.get(args.min_severity, None)
    if min_sev is None:
        min_sev = int(args.min_severity)

    filters = {}
    ref = None
    caps = [p for p in args.paths if os.path.isfile(p)]
    if (args.since or args.until) and caps:
        from icsctf import pcapio
        for p in caps:
            try:
                for ts, _lt, _f in pcapio.iter_frames(p):
                    ref = ts
                    break
            except Exception:
                continue
            if ref:
                break
    since = _common.parse_time(args.since, ref)
    until = _common.parse_time(args.until, ref)
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until
    if args.max_packets:
        filters["limit"] = args.max_packets

    events = timeline.build(args.paths, min_severity=min_sev,
                            keep_unmatched=args.keep_unmatched,
                            log_year=args.log_year, **filters)
    syslog_sourced = {os.path.basename(e.source) for e in events
                      if e.ref.startswith("line") and e.ts}
    if syslog_sourced and not args.log_year:
        print("[syslog lines carry no year; using each file's modification "
              "year. Use --log-year to set it.]")
    if not events:
        print("no events found. If you expected log entries, try "
              "--keep-unmatched, or lower --min-severity.")
        return

    print(section(f"timeline: {len(events)} events from {len(args.paths)} file(s)"))
    rows = []
    for e in events:
        rows.append([e.iso(), timeline.SEVERITY_NAME.get(e.severity, "?"),
                     e.actor or "-", e.target or "-", e.summary,
                     e.ref or "-", os.path.basename(e.source)])
    print(table(rows, ["utc", "sev", "actor", "target", "what happened",
                       "ref", "source"]))

    if args.detail:
        print(section("detail"))
        for e in events:
            if e.detail:
                print(f"{e.iso()}  {e.ref}\n    {e.detail}")

    impact = [e for e in events if e.severity >= 3]
    if impact:
        print(section("events that touched the process or an account"))
        print(table([[e.iso(), e.actor or "-", e.summary, e.ref] for e in impact],
                    ["utc", "actor", "what happened", "ref"]))
        first, last = impact[0], impact[-1]
        print(f"\nFirst impact event: {first.iso()} ({first.ref}). "
              f"Last: {last.iso()} ({last.ref}).")
        print("Read the events immediately before the first one: that is "
              "usually where access was obtained, and anything that silenced "
              "reporting will sit between the two.")

    if args.gaps:
        g = timeline.gaps(events, args.gaps)
        if g:
            print(section(f"quiet periods longer than {args.gaps:g}s"))
            print(table([[x["from"], x["to"], x["seconds"], x["before"][:50]]
                         for x in g],
                        ["from", "to", "seconds", "last event before the gap"]))

    for flag, fn, label in ((args.csv, timeline.to_csv, "CSV"),
                            (args.json, timeline.to_json, "JSON"),
                            (args.md, timeline.to_markdown, "Markdown")):
        if flag:
            fn(events, flag)
            print(f"\nwrote {label}: {flag}")


if __name__ == "__main__":
    main()
