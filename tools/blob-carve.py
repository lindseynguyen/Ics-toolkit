#!/usr/bin/env python3
"""Generic blob analysis for any binary artefact: magic scan, decompression,
entropy profile, single-byte XOR recovery and extraction.

    blob-carve.py cartridge.img
    blob-carve.py cartridge.img --extract out/
    blob-carve.py cartridge.img --entropy
    blob-carve.py cartridge.img --xor
    blob-carve.py cartridge.img --slice 0x1200 --length 0x400 --out part.bin
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
from icsctf import carve
from icsctf.util import hexdump, printable, section, table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--extract", help="directory for decompressed blobs")
    ap.add_argument("--entropy", action="store_true")
    ap.add_argument("--window", type=int, default=1024)
    ap.add_argument("--xor", action="store_true", help="single-byte XOR magic scan")
    ap.add_argument("--xor-key", type=lambda s: int(s, 0),
                    help="apply this XOR key and report what appears")
    ap.add_argument("--slice", type=lambda s: int(s, 0))
    ap.add_argument("--length", type=lambda s: int(s, 0))
    ap.add_argument("--out", help="write the slice here")
    ap.add_argument("--strings", type=int, metavar="MINLEN")
    args = ap.parse_args()

    with open(args.path, "rb") as fh:
        data = fh.read()
    print(f"{args.path}: {len(data)} bytes, entropy {carve.entropy(data):.3f}")

    if args.strings:
        for s in printable(data, args.strings):
            print(s)
        return

    if args.slice is not None:
        blob = data[args.slice:args.slice + (args.length or 256)]
        print(hexdump(blob, len(blob)))
        res = carve.try_decompress(data, args.slice)
        if res:
            print(f"\ndecompresses as {res[0]}: {len(res[1])} bytes")
            print(hexdump(res[1], 256))
        if args.out:
            with open(args.out, "wb") as fh:
                fh.write(blob)
            print(f"\nwrote {len(blob)} bytes to {args.out}")
        return

    if args.xor_key is not None:
        dec = bytes(b ^ args.xor_key for b in data)
        print(section(f"XOR 0x{args.xor_key:02x} applied"))
        print(hexdump(dec, 256))
        strs = printable(dec, 6)[:40]
        if strs:
            print("\nstrings that appear:")
            for s in strs:
                print("  " + s)
        return

    hits = carve.find_magics(data)
    print(section("magic-byte hits"))
    print(table([[f"0x{h.offset:06x}", h.kind, h.size or "-", h.note] for h in hits],
                ["offset", "kind", "inflated", "note"]))

    if args.xor or not hits:
        x = carve.xor_magic_scan(data)
        print(section("containers behind a single-byte XOR"))
        print(table([[f"0x{h['offset']:06x}", h["kind"], f"0x{h['xor_key']:02x}"]
                     for h in x],
                    ["offset", "kind", "key"]))

    if args.entropy:
        print(section(f"entropy profile (window {args.window})"))
        prof = carve.entropy_profile(data, args.window)
        print(table([[f"0x{o:06x}", e, "#" * int(e * 4)] for o, e in prof],
                    ["offset", "entropy", ""]))
    regions = carve.high_entropy_regions(data, min(512, args.window), 7.2)
    if regions:
        print(section("high-entropy regions"))
        print(table([[f"0x{a:06x}", f"0x{b:06x}", b - a, e] for a, b, e in regions],
                    ["start", "end", "length", "mean entropy"]))

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        n = 0
        for h in hits:
            res = carve.try_decompress(data, h.offset)
            if not res:
                continue
            kind, blob = res
            p = os.path.join(args.extract, f"blob_{h.offset:06x}_{kind}.bin")
            with open(p, "wb") as fh:
                fh.write(blob)
            print(f"{p}  ({kind}, {len(blob)} bytes)")
            n += 1
        print(f"\nextracted {n} blob(s)")


if __name__ == "__main__":
    main()
