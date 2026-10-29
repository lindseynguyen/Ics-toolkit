#!/usr/bin/env python3
"""Static inspection of legacy 16-bit HMI binaries (.COM / MZ .EXE).

Shows the container layout, operator-visible strings, DOS/BIOS interrupt use
(including serial I/O, which means the binary talks to a field device),
candidate IEEE-754 setpoint constants and an optional 16-bit disassembly.

    dos-bin-inspect.py SETPT16.COM
    dos-bin-inspect.py SETPT16.COM --screens
    dos-bin-inspect.py SETPT16.COM --floats
    dos-bin-inspect.py SETPT16.COM --disasm 0 --length 240
"""
from __future__ import annotations

import argparse

import _bootstrap  # noqa: F401
from icsctf import carve, dosbin
from icsctf.util import hexdump, section, table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--min-str", type=int, default=4)
    ap.add_argument("--screens", action="store_true",
                    help="only strings that look like HMI text")
    ap.add_argument("--floats", action="store_true", help="setpoint-like constants")
    ap.add_argument("--ints", action="store_true", help="interrupt call sites")
    ap.add_argument("--disasm", type=lambda s: int(s, 0), metavar="OFF",
                    help="disassemble at file offset (needs capstone)")
    ap.add_argument("--length", type=int, default=160)
    ap.add_argument("--hexdump", type=lambda s: int(s, 0), metavar="OFF")
    args = ap.parse_args()

    info = dosbin.inspect(args.binary, args.min_str)

    if args.hexdump is not None:
        with open(args.binary, "rb") as fh:
            data = fh.read()
        print(hexdump(data[args.hexdump:], 512))
        return
    if args.disasm is not None:
        for line in dosbin.disassemble(args.binary, args.disasm, args.length):
            print(line)
        return
    if args.screens:
        for off, s in dosbin.ascii_screens(info):
            print(f"0x{off:04x}  {s}")
        return
    if args.floats:
        print(table([[f"0x{o:04x}", v] for o, v in info.float_candidates[:200]],
                    ["offset", "value"]))
        return
    if args.ints:
        print(table([[f"0x{i.offset:04x}", f"0x{i.number:02x}", i.name, i.ah_hint]
                     for i in info.interrupts],
                    ["offset", "int", "service", "AH hint"]))
        return

    print(f"file        : {info.path} ({info.size} bytes)")
    print(f"container   : {info.kind}")
    print(f"load base   : 0x{info.load_base:04x}")
    if info.entry is not None:
        print(f"entry point : 0x{info.entry:04x}")
    if info.mz:
        print(section("MZ header"))
        print(table([[k, v, hex(v)] for k, v in info.mz.items()],
                    ["field", "value", "hex"]))
    if info.overlay_offset:
        print(f"\noverlay / appended data starts at 0x{info.overlay_offset:04x} "
              f"({info.size - info.overlay_offset} bytes) - check it for a payload")

    print(section("interrupt usage"))
    print(table([[k, v] for k, v in sorted(info.int_counts.items(),
                                           key=lambda kv: -kv[1])],
                ["service", "call sites"]))
    if info.serial_io:
        print("\nINT 14h present: the binary drives a serial port directly, so it "
              "is likely speaking a field protocol (Modbus RTU, DF1, a vendor ASCII "
              "protocol) rather than only drawing a screen.")

    print(section("strings that look like operator text"))
    print(table([[f"0x{o:04x}", s] for o, s in dosbin.ascii_screens(info)[:60]],
                ["offset", "string"]))

    print(section("setpoint-like IEEE-754 constants"))
    print(table([[f"0x{o:04x}", v] for o, v in info.float_candidates[:40]],
                ["offset", "value"]))
    print("\nA 'limit' that sits just above a normal operating value is the usual "
          "shape of a tampered alarm or trip setpoint: compare each constant with "
          "the ranges the challenge narrative gives for the process.")

    with open(args.binary, "rb") as fh:
        data = fh.read()
    hits = [h for h in carve.find_magics(data) if h.kind != "mz-exe"]
    if hits:
        print(section("embedded containers"))
        print(table([[f"0x{h.offset:04x}", h.kind, h.size or "-", h.note] for h in hits],
                    ["offset", "kind", "size", "note"]))


if __name__ == "__main__":
    main()
