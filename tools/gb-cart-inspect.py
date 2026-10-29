#!/usr/bin/env python3
"""Game Boy cartridge image inspector for "training rig" firmware artefacts.

Reports the cartridge header (title, mapper, ROM/RAM layout, checksums),
profiles every 16 KiB bank by entropy and string density, and points at the
banks that hold text tables or embedded archives.

    gb-cart-inspect.py rig.gb
    gb-cart-inspect.py rig.gb --strings 3
    gb-cart-inspect.py rig.gb --bank 4 --dump bank4.bin
    gb-cart-inspect.py rig.gb --blobs --extract out/
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
from icsctf import carve, gbcart
from icsctf.util import hexdump, section, table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rom")
    ap.add_argument("--strings", type=int, metavar="BANK",
                    help="print strings from one bank")
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--bank", type=int, help="hexdump the start of a bank")
    ap.add_argument("--dump", help="write the --bank contents to this file")
    ap.add_argument("--blobs", action="store_true", help="container / magic scan")
    ap.add_argument("--extract", help="directory to write decompressed blobs into")
    ap.add_argument("--vectors", action="store_true", help="print RST/interrupt vectors")
    args = ap.parse_args()

    info = gbcart.inspect(args.rom, string_min=5)

    if args.strings is not None:
        for s in gbcart.bank_strings(args.rom, args.strings, args.min_len):
            print(s)
        return

    if args.bank is not None:
        with open(args.rom, "rb") as fh:
            rom = fh.read()
        off = args.bank * gbcart.BANK_SIZE
        blob = rom[off:off + gbcart.BANK_SIZE]
        print(f"bank {args.bank} at 0x{off:06x}, {len(blob)} bytes, "
              f"entropy {carve.entropy(blob):.3f}")
        print(hexdump(blob, 512))
        if args.dump:
            n = gbcart.dump_bank(args.rom, args.bank, args.dump)
            print(f"\nwrote {n} bytes to {args.dump}")
        return

    print(f"file            : {info.path} ({info.size} bytes)")
    print(f"title           : {info.title!r}")
    if info.manufacturer:
        print(f"manufacturer    : {info.manufacturer!r}")
    print(f"CGB flag        : 0x{info.cgb_flag:02x} "
          f"({'CGB only' if info.cgb_flag == 0xC0 else 'CGB enhanced' if info.cgb_flag == 0x80 else 'DMG'})")
    print(f"SGB flag        : 0x{info.sgb_flag:02x}")
    print(f"cartridge type  : {info.cart_type}")
    print(f"ROM size field  : {info.rom_size}")
    print(f"RAM size field  : {info.ram_size}")
    print(f"destination     : {info.destination}")
    print(f"old licensee    : {info.licensee}")
    print(f"ROM version     : {info.rom_version}")
    print(f"header checksum : 0x{info.header_checksum:02x} "
          f"(computed 0x{info.header_checksum_calc:02x}) "
          f"{'OK' if info.header_ok else 'MISMATCH - header was edited'}")
    print(f"global checksum : 0x{info.global_checksum:04x} "
          f"(computed 0x{info.global_checksum_calc:04x}) "
          f"{'OK' if info.global_ok else 'MISMATCH - ROM body was modified'}")
    print(f"Nintendo logo   : {'intact' if info.logo_ok else 'altered'}")

    print(section("bank profile"))
    print(table([[b.index, f"0x{b.offset:06x}", b.size, b.entropy, b.strings, b.note]
                 for b in info.banks],
                ["bank", "offset", "size", "entropy", "strings", "note"]))

    if info.magic_hits or args.blobs:
        print(section("embedded container candidates"))
        rows = [[f"0x{h.offset:06x}", h.kind, h.size or "-", h.note]
                for h in info.magic_hits]
        print(table(rows, ["offset", "kind", "inflated size", "note"]))
        xor = carve.xor_magic_scan(open(args.rom, "rb").read())
        if xor:
            print(section("containers behind a single-byte XOR"))
            print(table([[f"0x{h['offset']:06x}", h["kind"], f"0x{h['xor_key']:02x}"]
                         for h in xor],
                        ["offset", "kind", "xor key"]))
        if info.entropy_regions:
            print(section("high-entropy regions (compressed or encrypted)"))
            print(table([[f"0x{a:06x}", f"0x{b:06x}", b - a, e]
                         for a, b, e in info.entropy_regions],
                        ["start", "end", "length", "mean entropy"]))

    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        with open(args.rom, "rb") as fh:
            rom = fh.read()
        n = 0
        for h in info.magic_hits:
            res = carve.try_decompress(rom, h.offset)
            if not res:
                continue
            kind, blob = res
            path = os.path.join(args.extract, f"blob_{h.offset:06x}_{kind}.bin")
            with open(path, "wb") as fh:
                fh.write(blob)
            print(f"{path}  ({kind}, {len(blob)} bytes)")
            n += 1
        print(f"\nextracted {n} blob(s)")

    if args.vectors:
        print(section("vectors"))
        print(table([[k, v] for k, v in gbcart.rst_and_vectors(args.rom).items()],
                    ["vector", "bytes"]))


if __name__ == "__main__":
    main()
