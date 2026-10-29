#!/usr/bin/env python3
"""`strings`, with offsets, wide-character support and classification.

Plain `strings` gives you a wall of text. This one tells you where each string
lives, finds UTF-16 text that plain `strings` misses on Windows and firmware
artefacts, and groups what it finds into the categories that matter: addresses,
paths, commands, credential-like text, OT vocabulary, flag-like markers.

    strings-plus.py firmware.bin
    strings-plus.py firmware.bin --only "ot vocabulary"
    strings-plus.py HMI.EXE --grep "setpoint|alarm" --min-len 5
    strings-plus.py firmware.bin --at 0x8000 --length 0x4000
"""
from __future__ import annotations

import argparse
import re

import _bootstrap  # noqa: F401
from icsctf import forensics
from icsctf.util import section, table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--ascii-only", action="store_true",
                    help="skip UTF-16 scanning (faster on a big file)")
    ap.add_argument("--grep", help="keep only strings matching this regex")
    ap.add_argument("--only", help="show one category only (see the summary)")
    ap.add_argument("--at", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--length", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--limit", type=int, default=400)
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        data = fh.read()
    base = args.at
    if args.length:
        data = data[args.at:args.at + args.length]
    elif args.at:
        data = data[args.at:]

    encodings = ("ascii",) if args.ascii_only else ("ascii", "utf-16le", "utf-16be")
    found = forensics.extract_strings(data, args.min_len, encodings)
    for s in found:
        s.offset += base

    if args.grep:
        rx = re.compile(args.grep, re.I)
        found = [s for s in found if rx.search(s.text)]

    buckets = forensics.classify_strings(found)
    if args.only:
        key = args.only.lower()
        match = [k for k in buckets if key in k.lower()]
        if not match:
            print(f"no category matching {args.only!r}. Available: "
                  + ", ".join(sorted(buckets)))
            return
        wanted = set()
        for k in match:
            wanted |= set(buckets[k])
        found = [s for s in found if any(w in s.text for w in wanted)]

    print(f"{args.path}: {len(found)} strings "
          f"({sum(1 for s in found if s.encoding != 'ascii')} wide-character)")
    if buckets and not args.only:
        print(section("what was found, by category"))
        print(table([[name, len(vals), ", ".join(vals[:4])[:88]]
                     for name, vals in sorted(buckets.items(), key=lambda kv: -len(kv[1]))],
                    ["category", "distinct", "examples"]))
        print("\nShow one category with --only \"ot vocabulary\" (or any name above).")

    print(section("strings"))
    print(table([[f"0x{s.offset:08x}", s.encoding, s.text[:110]]
                 for s in found[:args.limit]],
                ["offset", "encoding", "text"]))
    if len(found) > args.limit:
        print(f"\n... {len(found) - args.limit} more. Narrow with --grep or "
              "--min-len, or raise --limit.")
    print("\nJump to any offset with: python3 tools/hexview.py "
          f'"{args.path}" --at 0xOFFSET')


if __name__ == "__main__":
    main()
