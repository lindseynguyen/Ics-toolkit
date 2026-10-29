#!/usr/bin/env python3
"""Decode an encoded blob without having to guess which encoding it is.

Tries base64, base32, hex, URL encoding, gzip, zlib, raw deflate, ROT13,
UTF-16 and single-byte XOR, scores each result by how much it looks like real
text, and shows what came out. Chains are followed, so base64 wrapping a gzip
stream decodes in one step.

    decode.py --text "SGVsbG8gZnJvbSB0aGUgUExD"
    decode.py blob.bin
    decode.py blob.bin --at 0x8000 --length 400
    echo "7b22..." | decode.py -
"""
from __future__ import annotations

import argparse
import sys

import _bootstrap  # noqa: F401
from icsctf import forensics
from icsctf.util import hexdump, section


def preview(data: bytes, limit: int = 600) -> str:
    printable = sum(1 for b in data[:256] if 9 <= b <= 13 or 32 <= b < 127)
    if data and printable / len(data[:256]) > 0.85:
        return data[:limit].decode("latin-1")
    return hexdump(data, min(limit, 256))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="file to decode, or - for stdin")
    ap.add_argument("--text", help="decode this string instead of a file")
    ap.add_argument("--at", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--length", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--no-xor", action="store_true", help="skip the XOR sweep")
    ap.add_argument("--chain", action="store_true",
                    help="keep decoding the best result, up to three times")
    ap.add_argument("--out", help="write the best result to this file")
    args = ap.parse_args()

    if args.text is not None:
        data = args.text.encode("latin-1")
    elif args.path == "-":
        data = sys.stdin.buffer.read()
    elif args.path:
        with open(args.path, "rb") as fh:
            data = fh.read()
        if args.length:
            data = data[args.at:args.at + args.length]
        elif args.at:
            data = data[args.at:]
    else:
        ap.error("give a file, --text, or - for stdin")

    print(f"input: {len(data):,} bytes")
    results = forensics.try_decoders(data, xor_keys=not args.no_xor)
    if not results:
        print("\nNothing decoded to anything more readable than the input.\n"
              "That usually means one of three things: it is already plain "
              "data; it is compressed with something unusual (try "
              "blob-carve.py); or it is genuinely encrypted, in which case the "
              "key has to come from somewhere else.")
        return

    print(section(f"{len(results)} candidate decoding(s), best first"))
    for name, out, score in results[:6]:
        print(f"\n--- {name}  ({len(out):,} bytes, readability {score})")
        print(preview(out))

    if args.chain:
        chain = forensics.nested_decode(data)
        if len(chain) > 1:
            print(section("decoding chain"))
            for i, (name, out) in enumerate(chain, 1):
                print(f"  step {i}: {name} -> {len(out):,} bytes")
            print("\nfinal result:")
            print(preview(chain[-1][1]))

    if args.out:
        best = results[0][1]
        with open(args.out, "wb") as fh:
            fh.write(best)
        print(f"\nwrote the best result ({results[0][0]}) to {args.out}")


if __name__ == "__main__":
    main()
