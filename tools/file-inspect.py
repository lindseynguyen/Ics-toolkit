#!/usr/bin/env python3
"""What is this file? - identification, hashes, entropy and first findings.

The first command to run on anything you were handed. It replaces a handful
of separate commands (`file`, `md5sum`, `sha256sum`, `strings | head`) and adds
what matters for OT artefacts: whether the size looks like firmware, what is
embedded inside it, and which strings are worth your attention.

    file-inspect.py evidence/unknown.bin
    file-inspect.py evidence/*                 # a table for a whole folder
    file-inspect.py firmware.bin --strings     # full classified string list
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
from icsctf import detect, forensics
from icsctf.util import section, table


def one(path: str, show_strings: bool, min_len: int) -> None:
    rep = forensics.identify(path)
    print(section(os.path.basename(path)))
    print(f"  path          : {path}")
    print(f"  size          : {rep.size:,} bytes")
    print(f"  looks like    : {rep.kind}")
    print(f"  entropy       : {rep.entropy}  ({rep.entropy_note})")
    print(f"  printable     : {rep.printable_ratio * 100:.1f}% of the first block")
    print(f"  md5           : {rep.hashes['md5']}")
    print(f"  sha1          : {rep.hashes['sha1']}")
    print(f"  sha256        : {rep.hashes['sha256']}")
    if rep.signatures:
        print("\n  signatures found:")
        for s in rep.signatures:
            print(f"    {s}")
    if rep.text_hints:
        print("\n  text format hints:")
        for t in rep.text_hints:
            print(f"    {t}")
    if rep.containers:
        print("\n  embedded containers (offset, kind):")
        for c in rep.containers[:15]:
            print(f"    {c}")
        print("    -> extract them with: python3 tools/blob-carve.py "
              f'"{path}" --extract out/')
    if rep.interesting:
        print("\n  strings worth a look:")
        for name, values in rep.interesting.items():
            shown = ", ".join(values[:6])
            more = f"  (+{len(values) - 6} more)" if len(values) > 6 else ""
            print(f"    {name:<18} {shown}{more}")

    try:
        art = detect.identify(path)
        if art.steps:
            print("\n  suggested next steps:")
            for s in art.steps[:4]:
                extra = (" " + " ".join(s.args)) if s.args else ""
                print(f'    {s.label}\n      $ python3 tools/{s.tool} "{path}"{extra}')
        for w in art.warnings:
            print(f"\n  warning: {w}")
    except Exception:
        pass

    if show_strings:
        with open(path, "rb") as fh:
            data = fh.read(4 * 1024 * 1024)
        found = forensics.extract_strings(data, min_len)
        print(section(f"strings ({len(found)})"))
        print(table([[f"0x{s.offset:08x}", s.encoding, s.text[:110]] for s in found[:400]],
                    ["offset", "encoding", "text"]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--strings", action="store_true", help="also list every string")
    ap.add_argument("--min-len", type=int, default=6)
    ap.add_argument("--summary", action="store_true",
                    help="one row per file instead of a full report")
    args = ap.parse_args()

    files = [p for p in args.paths if os.path.isfile(p)]
    if not files:
        print("no readable files given")
        return
    if args.summary or (len(files) > 3 and not args.strings):
        rows = []
        for p in files:
            rep = forensics.identify(p)
            rows.append([os.path.basename(p), f"{rep.size:,}", rep.kind[:46],
                         rep.entropy, rep.hashes["sha256"][:16] + "..."])
        print(table(rows, ["file", "bytes", "looks like", "entropy", "sha256"]))
        print("\nRun without --summary for the full report on one file.")
        return
    for p in files:
        one(p, args.strings, args.min_len)


if __name__ == "__main__":
    main()
