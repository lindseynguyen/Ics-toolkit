#!/usr/bin/env python3
"""Merge fragmented capture sets into a single time-ordered pcap.

Challenge artefacts are often split (frag_01.pcap ... frag_NN.pcap) or shipped
out of order. This rewrites them as one classic pcap with original timestamps,
so any tool - including Wireshark - sees one coherent timeline.

    pcap-merge.py out.pcap frag_*.pcap
    pcap-merge.py out.pcap frag_*.pcap --keep-order   # concatenate as given
"""
from __future__ import annotations

import argparse
import struct

import _bootstrap  # noqa: F401
import _common
from icsctf.util import ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--keep-order", action="store_true",
                    help="do not sort by timestamp")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, keep_raw=True)
    if not args.keep_order:
        pkts.sort(key=lambda p: p.ts)
    if not pkts:
        print("nothing to merge")
        return
    linktypes = {p.linktype for p in pkts}
    lt = pkts[0].linktype
    if len(linktypes) > 1:
        print(f"warning: mixed link types {linktypes}; writing as {lt}")
    with open(args.out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, lt))
        for p in pkts:
            sec = int(p.ts)
            usec = int(round((p.ts - sec) * 1e6))
            fh.write(struct.pack("<IIII", sec, usec, len(p.raw), len(p.raw)))
            fh.write(p.raw)
    print(f"wrote {len(pkts)} packets to {args.out}")
    print(f"window {ts(pkts[0].ts)} -> {ts(pkts[-1].ts)}")


if __name__ == "__main__":
    main()
