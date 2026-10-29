# Triage workflow

A repeatable order of operations for an OT artefact set, whether it comes from
a CTF or from a real incident.

## 1. Inventory the artefacts

```bash
file *            # containers
ls -l             # sizes: a 64 KiB "image" is a ROM, a 2 MB one is firmware
```

Captures, logs, binaries and diagrams answer different questions. Read the
network diagram first if one is provided: it tells you which IP is a PLC, an
HMI, a historian or a jump host, and you will not have to infer it.

## 2. Stitch and orient the captures

```bash
python3 tools/pcap-merge.py merged.pcap frag_*.pcap
python3 tools/pcap-overview.py merged.pcap
```

From the overview, note: the time window, which ICS protocol is present, which
hosts speak it, and which host behaves like a tool (high fan-out, bare SYNs,
many ports). If IPv4 fragmentation is reported, reassemble before decoding.

## 3. Decode the protocol, not the packets

Pick the matching tool and run its default report first, then narrow:

```bash
python3 tools/bacnet-triage.py  merged.pcap            # then --dcc / --writes
python3 tools/s7-triage.py      merged.pcap            # then --szl / --blocks / --control
python3 tools/modbus-triage.py  merged.pcap            # then --map / --writes / --floats
python3 tools/iec104-triage.py  merged.pcap            # then --commands / --sbo
python3 tools/dnp3-triage.py    merged.pcap
```

## 4. Separate reads from writes, and attempts from successes

This is the step that answers most questions. Every protocol here has an
explicit success/failure signal:

| Protocol | Failure signal |
|---|---|
| BACnet | Error PDU, class `security` code `password-failure` |
| S7comm | non-zero error class/code in the ack-data |
| Modbus | function code OR 0x80 plus exception code |
| IEC-104 | activation confirmation with the P/N bit set |
| DNP3 | IIN flags; `func-not-supported`, `already-executing` |

## 5. Build a timeline in the order the attacker worked

Sort the write/control events by timestamp and group them by target. Per-zone
or per-device attack order, and the clean-up at the end, fall straight out of
that ordering. Keep frame numbers next to every claim so the finding is
checkable.

## 6. Mine the cleartext

```bash
python3 tools/cleartext-creds.py merged.pcap
python3 tools/stream-carve.py    merged.pcap                 # stream index
python3 tools/stream-carve.py    merged.pcap --stream 3 --ascii
python3 tools/stream-carve.py    merged.pcap --carve out/
```

Historian and database traffic is the richest source: tag names, areas, units
and often credentials. MS SQL Server's TDS "encryption" of the password field
is a nibble swap and an XOR with 0xA5.

## 7. Work the binary artefacts

```bash
python3 tools/gb-cart-inspect.py  rig.gb
python3 tools/gb-cart-inspect.py  rig.gb --strings 1
python3 tools/blob-carve.py       rig.gb --extract out/
python3 tools/dos-bin-inspect.py  LEGACY.COM
```

Container, then regions, then data, then code - in that order.

## 7b. Merge everything into one timeline

```bash
python3 tools/timeline.py evidence/* --min-severity suspicious --md report.md
```

Captures, auth logs, shell history and CSV exports become one UTC sequence.
This is the step that turns separate reports into an account of what happened;
[`timeline.md`](timeline.md) covers how to read one and the clock traps.

## 7c. Turn the findings into detections

```bash
python3 tools/make-rules.py evidence/*.pcap --out rules/
```

Suricata, Zeek and Sigma rules with the host allow-lists inferred from the
capture and the misbehaving hosts excluded from them. Read the generated
README before deploying - see [`detection-rules.md`](detection-rules.md).

## 8. Write it down as an incident, not as a flag

For each finding record: frame number, timestamp (UTC), source, target,
protocol operation, value, outcome. That table is simultaneously a CTF answer
sheet, an incident report and the input to a detection rule.

## Wireshark equivalents

These tools exist because scripted output is diffable and citable, but
Wireshark remains the fastest interactive view. Useful display filters:

```
bacapp.confirmed_service == 17        # DeviceCommunicationControl
bacapp.confirmed_service == 15        # writeProperty
s7comm.param.func == 0x29             # PLC stop
s7comm.param.func in {0x1a 0x1b}      # block download
s7comm.szl.id                         # any SZL read
modbus.func_code in {5 6 15 16 22}    # Modbus writes
mbtcp && modbus.exception_code
104asdu.typeid in {45 46 47 48 49 50} # IEC-104 commands
104apci.utype == 0x13                 # STOPDT act
dnp3.al.func in {3 4 5 6 13 21}
tds.type == 0x10                      # TDS LOGIN7
```
