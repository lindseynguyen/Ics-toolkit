#!/usr/bin/env python3
"""Compare two files and say what changed, not just that something did.

For firmware and controller images this is the fastest route to an answer:
two builds of the same ROM differ in four places, and the tool tells you that
one of them is a float that went from 1.50 to 9.75.

    bin-diff.py original.gb patched.gb
    bin-diff.py original.gb patched.gb --hexdump        # bytes of each change
    bin-diff.py config_before.txt config_after.txt      # falls back to a text diff
"""
from __future__ import annotations

import argparse
import difflib
import os

import _bootstrap  # noqa: F401
from icsctf import forensics
from icsctf.util import section, table


def is_text(path: str) -> bool:
    with open(path, "rb") as fh:
        head = fh.read(4096)
    if not head:
        return True
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127)
    return printable / len(head) > 0.92


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--hexdump", action="store_true",
                    help="show the bytes of every changed region")
    ap.add_argument("--context", type=int, default=16,
                    help="bytes of context in the hexdumps")
    ap.add_argument("--merge-gap", type=int, default=16,
                    help="merge changed runs separated by fewer bytes than this")
    ap.add_argument("--limit", type=int, default=40, help="regions to show")
    args = ap.parse_args()

    ha = forensics.hashes(args.left)
    hb = forensics.hashes(args.right)
    sa, sb = os.path.getsize(args.left), os.path.getsize(args.right)
    print(table([[os.path.basename(args.left), f"{sa:,}", ha["sha256"][:32] + "..."],
                 [os.path.basename(args.right), f"{sb:,}", hb["sha256"][:32] + "..."]],
                ["file", "bytes", "sha256"]))
    if ha["sha256"] == hb["sha256"]:
        print("\nThe two files are byte-for-byte identical.")
        return

    if is_text(args.left) and is_text(args.right):
        with open(args.left, errors="replace") as fh:
            la = fh.readlines()
        with open(args.right, errors="replace") as fh:
            lb = fh.readlines()
        print(section("text diff"))
        shown = 0
        for line in difflib.unified_diff(la, lb, os.path.basename(args.left),
                                         os.path.basename(args.right), lineterm=""):
            print(line.rstrip())
            shown += 1
            if shown > 400:
                print("... (truncated)")
                break
        return

    with open(args.left, "rb") as fh:
        a = fh.read()
    with open(args.right, "rb") as fh:
        b = fh.read()
    regions = forensics.diff_regions(a, b, args.merge_gap)
    if not regions:
        print("\nThe files differ only in length.")
        return

    changed = sum(r.length for r in regions)
    print(f"\n{len(regions)} changed region(s), {changed:,} bytes "
          f"({changed / max(1, min(len(a), len(b))) * 100:.3f}% of the file)")
    if sa != sb:
        print(f"The files are different lengths: {sa:,} vs {sb:,} bytes.")

    print(section("what changed"))
    rows = []
    for r in regions[:args.limit]:
        rows.append([f"0x{r.start:08x}", r.length,
                     forensics.interpret_region(a, b, r)[:96]])
    print(table(rows, ["offset", "bytes", "interpretation"]))
    if len(regions) > args.limit:
        print(f"\n... {len(regions) - args.limit} more regions.")

    if args.hexdump:
        for r in regions[:args.limit]:
            lo = max(0, r.start - args.context)
            hi = min(max(len(a), len(b)), r.end + args.context)
            print(section(f"0x{r.start:08x} .. 0x{r.end:08x}"))
            print("  --- " + os.path.basename(args.left))
            print(forensics.hexdump(a[lo:hi], lo, highlight=(r.start, r.end)))
            print("  +++ " + os.path.basename(args.right))
            print(forensics.hexdump(b[lo:hi], lo, highlight=(r.start, r.end)))

    print("\nFor a firmware image, a change inside a text bank is a relabelled "
          "message; a four-byte change in a data area is usually a constant - "
          "a setpoint, a limit or a timer. A changed header checksum alone "
          "just means the image was rebuilt.")


if __name__ == "__main__":
    main()
