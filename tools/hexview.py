#!/usr/bin/env python3
"""Look at the bytes - a hex viewer with search, for people who do not live
in `xxd`.

    hexview.py firmware.bin                      # first 512 bytes
    hexview.py firmware.bin --at 0x4000 --length 256
    hexview.py firmware.bin --find "SETPOINT"    # every occurrence, in context
    hexview.py firmware.bin --find-hex "78 9c"   # a zlib header, say
    hexview.py capture.pcap --at 0 --length 64
"""
from __future__ import annotations

import argparse

import _bootstrap  # noqa: F401
from icsctf import forensics
from icsctf.util import section


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--at", type=lambda s: int(s, 0), default=0,
                    help="start offset (0x1234 or 4660)")
    ap.add_argument("--length", type=lambda s: int(s, 0), default=512)
    ap.add_argument("--width", type=int, default=16)
    ap.add_argument("--find", help="search for text")
    ap.add_argument("--find-hex", help="search for bytes, e.g. \"78 9c\" or 789c")
    ap.add_argument("--context", type=lambda s: int(s, 0), default=64,
                    help="bytes of context around each hit (default 64)")
    ap.add_argument("--max-hits", type=int, default=20)
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        data = fh.read()
    print(f"{args.path}: {len(data):,} bytes")

    needle = None
    if args.find_hex:
        needle = bytes.fromhex(args.find_hex.replace("0x", "").replace(" ", ""))
    elif args.find:
        needle = args.find.encode("latin-1")

    if needle:
        hits = forensics.find_all(data, needle, args.max_hits + 1)
        if not hits:
            print(f"\n{needle!r} does not appear in this file.")
            # a common newcomer trap: text stored as UTF-16
            if args.find:
                wide = args.find.encode("utf-16-le")
                if forensics.find_all(data, wide, 1):
                    print("It does appear as UTF-16 (two bytes per character). "
                          f"Try: --find-hex {wide.hex()}")
            return
        more = len(hits) > args.max_hits
        print(f"\n{len(hits)}{'+' if more else ''} occurrence(s) of {needle!r}")
        for off in hits[:args.max_hits]:
            start = max(0, off - args.context // 2)
            end = min(len(data), off + len(needle) + args.context // 2)
            print(section(f"offset 0x{off:08x} ({off})"))
            print(forensics.hexdump(data[start:end], start, args.width,
                                    highlight=(off, off + len(needle))))
        print("\nBytes of the match are shown in [brackets].")
        return

    end = min(len(data), args.at + args.length)
    print(section(f"0x{args.at:08x} .. 0x{end:08x}"))
    print(forensics.hexdump(data[args.at:end], args.at, args.width))
    if end < len(data):
        print(f"\n... {len(data) - end:,} more bytes. Continue with "
              f"--at 0x{end:x}")


if __name__ == "__main__":
    main()
