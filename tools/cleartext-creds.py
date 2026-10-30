#!/usr/bin/env python3
"""Harvest cleartext credentials and secrets from a capture.

FTP, Telnet, HTTP Basic / form fields, SNMP communities, mail AUTH, LDAP
simple bind, MySQL handshakes and MS SQL Server TDS LOGIN7 - including the
nibble-swap + XOR 0xA5 password obfuscation, which is not encryption.

    cleartext-creds.py capture.pcap
    cleartext-creds.py capture.pcap --proto tds
    cleartext-creds.py --tds-decode 0xa5a5...     # decode a captured blob
"""
from __future__ import annotations

import argparse

import _bootstrap  # noqa: F401
import _common
from icsctf import creds
from icsctf.util import section, table, ts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="*")
    ap.add_argument("--proto", help="filter: ftp|telnet|http|mail|snmp|ldap|mysql|tds")
    ap.add_argument("--tds-decode", help="hex blob of a TDS password field")
    _common.add_capture_args(ap)
    args = ap.parse_args()

    if args.tds_decode:
        raw = bytes.fromhex(args.tds_decode.replace("0x", "").replace(" ", ""))
        print(creds.tds_decode_password(raw))
        return
    if not args.pcap:
        ap.error("give at least one capture, or --tds-decode")

    pkts = _common.load_capture(args, args.pcap,
                                ports=sorted(set(list(creds.CLEARTEXT_HINT_PORTS))))
    found = creds.harvest(pkts)
    if args.proto:
        found = [f for f in found if f.proto == args.proto]
    if not found:
        print("nothing in the cleartext-credential patterns matched")
        return
    print(section(f"{len(found)} findings"))
    print(table([[f.frame, ts(f.ts), f.src, f.dst, f.proto, f.kind, f.value[:120]]
                 for f in found],
                ["frame", "time", "src", "dst", "proto", "kind", "value"]))


if __name__ == "__main__":
    main()
