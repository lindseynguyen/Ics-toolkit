#!/usr/bin/env python3
"""Identify artefacts and print the recommended order of analysis.

Point it at everything you were given and it tells you what each file is and
which command to run next, in order. The terminal equivalent of the guided
mode in the GUI.

    triage-plan.py evidence/*
    triage-plan.py capture.pcap --commands      # just the command lines
"""
from __future__ import annotations

import argparse
import os
import textwrap

import _bootstrap  # noqa: F401
from icsctf import detect
from icsctf.util import section


def wrap(text: str, indent: str = "      ") -> str:
    return "\n".join(textwrap.wrap(text, 92, initial_indent=indent,
                                   subsequent_indent=indent))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--commands", action="store_true",
                    help="print only the command lines, ready to paste")
    args = ap.parse_args()

    files = [p for p in args.paths if os.path.isfile(p)]
    if not files:
        print("no readable files given")
        return

    group = detect.plan_group(files)
    if group and not args.commands:
        print(section("before anything else"))
        for s in group:
            print(f"  * {s.label}")
            print(wrap(s.why))
            print(f"      $ python3 tools/{s.tool} merged.pcap "
                  + " ".join(f'"{f}"' for f in files))

    for path in files:
        try:
            art = detect.identify(path)
        except Exception as exc:
            print(f"\n{path}: could not identify ({exc})")
            continue
        if args.commands:
            for s in art.steps:
                extra = (" " + " ".join(s.args)) if s.args else ""
                print(f'python3 tools/{s.tool} "{path}"{extra}')
            continue

        print(section(os.path.basename(path)))
        print(f"  what it is : {art.summary}")
        print(f"  size       : {art.size:,} bytes")
        for d in art.details:
            print(f"  note       : {d}")
        for w in art.warnings:
            print(f"  warning    : {w}")
        if art.protocols:
            print(f"  protocols  : {', '.join(art.protocols)}")
        if not art.steps:
            print("\n  Nothing to decode here - read the file directly.")
            continue
        print("\n  suggested order:\n")
        for i, s in enumerate(art.steps, 1):
            mark = " (start here)" if s.primary else ""
            print(f"   {i}. {s.label}{mark}")
            if s.why:
                print(wrap(s.why))
            extra = (" " + " ".join(s.args)) if s.args else ""
            print(f'      $ python3 tools/{s.tool} "{path}"{extra}\n')


if __name__ == "__main__":
    main()
