#!/usr/bin/env python3
"""List and export TCP streams, and carve files out of them.

    stream-carve.py capture.pcap                       # stream index
    stream-carve.py capture.pcap --stream 3            # print both directions
    stream-carve.py capture.pcap --stream 3 --out dir/ # write raw halves
    stream-carve.py capture.pcap --carve dir/          # magic-based extraction
"""
from __future__ import annotations

import argparse
import os

import _bootstrap  # noqa: F401
import _common
from icsctf import carve, pcapio
from icsctf.util import hexdump, printable, section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="+")
    ap.add_argument("--stream", type=int, help="stream index from the listing")
    ap.add_argument("--out", help="directory for raw stream halves")
    ap.add_argument("--carve", help="directory for carved files")
    ap.add_argument("--ascii", action="store_true", help="print strings not hexdump")
    ap.add_argument("--max", type=int, default=2048, help="bytes to print")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    pkts = _common.load_capture(args, args.pcap, protos=["tcp"])
    streams = pcapio.assemble_tcp(pkts)
    ordered = sorted(streams.values(),
                     key=lambda s: (s.packets[0].ts if s.packets else 0))

    if args.stream is None and not args.carve:
        print(section(f"{len(ordered)} TCP streams"))
        rows = []
        for i, s in enumerate(ordered):
            first = s.packets[0]
            rows.append([i, ts(first.ts), f"{s.client[0]}:{s.client[1]}",
                         f"{s.server[0]}:{s.server[1]}", len(s.packets),
                         len(s.to_server), len(s.to_client)])
        print(table(rows, ["idx", "first seen", "client", "server", "packets",
                           "c->s bytes", "s->c bytes"]))
        return

    if args.carve:
        os.makedirs(args.carve, exist_ok=True)
        n = 0
        for i, s in enumerate(ordered):
            for label, blob in (("c2s", s.to_server), ("s2c", s.to_client)):
                for hit in carve.find_magics(blob):
                    if hit.kind in ("flag-like", "mz-exe", "riff/wav"):
                        continue
                    ext = hit.kind.split("/")[0].split()[0]
                    path = os.path.join(args.carve, f"stream{i}_{label}_{hit.offset}.{ext}")
                    res = carve.try_decompress(blob, hit.offset)
                    data = res[1] if res else blob[hit.offset:]
                    with open(path, "wb") as fh:
                        fh.write(data)
                    n += 1
                    print(f"{path}  ({hit.kind}, {len(data)} bytes"
                          f"{', decompressed' if res else ''})")
        print(f"\ncarved {n} object(s)")
        return

    s = ordered[args.stream]
    print(f"stream {args.stream}: {s.client[0]}:{s.client[1]} <-> "
          f"{s.server[0]}:{s.server[1]}  packets={len(s.packets)}")
    for label, blob in (("client -> server", s.to_server), ("server -> client", s.to_client)):
        print(section(f"{label} ({len(blob)} bytes)"))
        if args.ascii:
            for line in printable(blob, 4)[:200]:
                print("  " + line)
        else:
            print(hexdump(blob, args.max))
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for label, blob in (("c2s", s.to_server), ("s2c", s.to_client)):
            p = os.path.join(args.out, f"stream{args.stream}_{label}.bin")
            with open(p, "wb") as fh:
                fh.write(blob)
            print(f"wrote {p} ({len(blob)} bytes)")


if __name__ == "__main__":
    main()
