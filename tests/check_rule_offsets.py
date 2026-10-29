#!/usr/bin/env python3
"""Verify that the byte offsets used by the generated Suricata rules match
real traffic.

A detection rule that does not fire is worse than no rule, so the offsets the
rule generator relies on are checked against the synthetic captures, where the
expected content is known.

    python3 tests/check_rule_offsets.py fixtures/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from icsctf import pcapio  # noqa: E402

CHECKS = [
    # file, description, predicate over the L4 payload
    ("bacnet_bms.pcap", "BACnet confirmed-request DCC: service id at offset 9",
     lambda d: d[:1] == b"\x81" and len(d) > 9 and d[6] == 0x00 and d[9] == 0x11),
    ("bacnet_bms.pcap", "BACnet reinitializeDevice: service id at offset 9",
     lambda d: d[:1] == b"\x81" and len(d) > 9 and d[6] == 0x00 and d[9] == 0x14),
    ("bacnet_bms.pcap", "BACnet writeProperty: service id at offset 9",
     lambda d: d[:1] == b"\x81" and len(d) > 9 and d[6] == 0x00 and d[9] == 0x0F),
    ("s7comm_wtp.pcap", "S7 job header at offset 7, PLC stop function at 17",
     lambda d: len(d) > 17 and d[:2] == b"\x03\x00" and d[7:9] == b"\x32\x01"
     and d[17] == 0x29),
    ("s7comm_wtp.pcap", "S7 request-download function at offset 17",
     lambda d: len(d) > 17 and d[7:9] == b"\x32\x01" and d[17] == 0x1A),
    ("s7comm_wtp.pcap", "S7 userdata (SZL) header at offset 7",
     lambda d: len(d) > 9 and d[7:9] == b"\x32\x07"),
    ("modbus_plc.pcap", "Modbus function code at offset 7 (write single coil)",
     lambda d: len(d) > 7 and d[2:4] == b"\x00\x00" and d[7] == 0x05),
    ("modbus_plc.pcap", "Modbus function code at offset 7 (write multiple regs)",
     lambda d: len(d) > 7 and d[2:4] == b"\x00\x00" and d[7] == 0x10),
    ("iec104_rtu.pcap", "IEC-104 STOPDT act is the first six bytes",
     lambda d: d[:6] == b"\x68\x04\x13\x00\x00\x00"),
    ("iec104_rtu.pcap", "IEC-104 ASDU type id at offset 6 (single command = 45)",
     lambda d: len(d) > 6 and d[0] == 0x68 and d[6] == 45),
    ("dnp3_outstation.pcap", "DNP3 application function code at offset 12",
     lambda d: len(d) > 12 and d[:2] == b"\x05\x64" and d[12] in (1, 5, 13, 21)),
]


def main() -> int:
    fx = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    failures = []
    for name, desc, pred in CHECKS:
        path = os.path.join(fx, name)
        if not os.path.isfile(path):
            failures.append(f"missing fixture {name}")
            continue
        hits = 0
        for p in pcapio.iter_packets([path], keep_raw=False):
            if not p.payload:
                continue
            try:
                if pred(p.payload):
                    hits += 1
            except (IndexError, TypeError):
                continue
        status = "ok" if hits else "NO MATCH"
        print(f"{status:>8}  {desc}  ({hits} packets)")
        if not hits:
            failures.append(desc)
    if failures:
        print("\nthese rule offsets would never fire:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nevery generated rule offset matches real traffic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
