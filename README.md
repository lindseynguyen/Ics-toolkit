# ics-ctf-toolkit

Analysis tooling for OT/ICS artefacts: packet captures carrying industrial
protocols, firmware and cartridge images, and legacy HMI binaries.

Built while working through the kind of OT challenge set that ships a BACnet
capture of a building-management intrusion, an S7comm capture of a water
treatment plant, an IEC-104 client binary and a plant simulator packed into a
Game Boy ROM. The tools answer the questions those artefacts raise - *who
issued which command, to which point, with what value, and did the device
accept it* - and the `docs/` directory explains the engineering behind each
protocol so the answers mean something.

**No challenge data, no flags and no solutions are included.** The fixtures
under `tests/` are hand-built synthetic packets whose field values are known,
so every decoder can be verified against ground truth.

## Why

Wireshark already dissects these protocols. What it does not do is give you a
diffable, citable table of *the twelve things that mattered* in a 40 000-packet
capture - request/response pairing with success and failure separated, a
register map, a select-before-operate audit, an SZL fingerprinting summary.
That is the gap these scripts fill, and they do it with no dependencies, so
they run on an air-gapped analysis box with a stock Python.

## Requirements

Python 3.9+. No required third-party packages: the pcap/pcapng reader and all
protocol decoders are implemented in the standard library.

Optional: `capstone` for 16-bit disassembly in `dos-bin-inspect.py`.

```bash
git clone https://github.com/<you>/ics-ctf-toolkit
cd ics-ctf-toolkit
python3 tests/make_fixtures.py fixtures/     # synthetic captures to try it on
python3 tools/pcap-overview.py fixtures/bacnet_bms.pcap
```

## Tools

| Tool | Purpose |
|---|---|
| `tools/pcap-overview.py` | first pass on any capture: hosts, conversations, protocol identification, scan heuristics, fragmentation warning |
| `tools/bacnet-triage.py` | BACnet/IP: device inventory, service usage, DeviceCommunicationControl / ReinitializeDevice password attempts with accepted-vs-failed counts, writeProperty targets and priorities |
| `tools/s7-triage.py` | S7comm / S7comm-plus: endpoints and roles, SZL diagnostic reads, block upload/download, CPU STOP and why it was refused, IEEE-754 tag writes |
| `tools/modbus-triage.py` | Modbus/TCP: function-code inventory, register and coil map, write operations, exception trails, scan heuristics, float word-order reconstruction, ASCII in registers |
| `tools/iec104-triage.py` | IEC 60870-5-104: APCI session state, ASDU inventory, IOA map, control-direction timeline, select-before-operate audit |
| `tools/dnp3-triage.py` | DNP3: link-layer addressing, application function codes, IIN flags, CROB and analog-output command decoding |
| `tools/cleartext-creds.py` | credentials in the clear: FTP, Telnet, HTTP Basic and form fields, SNMP communities, mail AUTH, LDAP simple bind, MS SQL Server TDS LOGIN7 (including the nibble-swap + XOR 0xA5 password field) |
| `tools/pcap-merge.py` | stitch fragmented capture sets into one time-ordered pcap |
| `tools/stream-carve.py` | TCP stream index, stream export, magic-based file carving |
| `tools/gb-cart-inspect.py` | Game Boy cartridge images: header, mapper, checksum tampering, per-bank entropy and string profile, embedded archive detection |
| `tools/dos-bin-inspect.py` | 16-bit `.COM` / MZ `.EXE`: container layout, operator strings, DOS/BIOS interrupt usage (INT 14h = serial field protocol), setpoint-like IEEE-754 constants, optional disassembly |
| `tools/blob-carve.py` | any binary: magic scan, decompression, entropy profile, single-byte-XOR container recovery, extraction |

Every tool is `--help`-documented and prints plain tables, so output pipes into
`grep`, `diff` and a report.

## Library

The CLIs are thin; the decoders are importable.

```python
from icsctf import pcapio, bacnet

packets = pcapio.read_many(["frag_01.pcap", "frag_02.pcap"])
messages = bacnet.extract(packets)
results = bacnet.correlate(messages)          # request -> ack / error

for key, res in results.items():
    req = res["request"]
    if req.service == "deviceCommunicationControl":
        print(req.frame, req.src, req.dst, req.password, res["outcome"])
```

| Module | Contents |
|---|---|
| `icsctf.pcapio` | pcap + pcapng reader, Ethernet/VLAN/SLL/raw, IPv4/IPv6, TCP/UDP, TCP stream assembly |
| `icsctf.bacnet` | BVLC/NPDU/APDU, tag walker, object and property tables, request/response correlation |
| `icsctf.s7comm` | TPKT/COTP/S7 header, read-write items, SZL table, block filename decoding, S7comm-plus classification |
| `icsctf.modbus` | MBAP + PDU, request pairing, register map, scan heuristics |
| `icsctf.iec104` | APCI formats, ASDU types, information-object decoding, SBO audit |
| `icsctf.dnp3` | link-layer de-stuffing, transport assembly, application objects, CROB |
| `icsctf.creds` | cleartext credential patterns, TDS password de-obfuscation |
| `icsctf.carve` | magic scan, decompression, entropy profiling, XOR recovery |
| `icsctf.gbcart` | cartridge header, bank profiling, blob location |
| `icsctf.dosbin` | MZ/COM layout, interrupt scan, float constants |

## Documentation

`docs/` is the point of the repository as much as the code is:

- [`00-challenge-map.md`](docs/00-challenge-map.md) - which technology each
  OT challenge family exercises, and where to start
- [`bacnet-ip.md`](docs/bacnet-ip.md) - BVLC/NPDU/APDU, the object and
  property model, priority arrays, DCC as a denial-of-control primitive
- [`s7comm.md`](docs/s7comm.md) - ISO-on-TCP, function codes, DB addressing,
  the SZL table, block filenames, why a CPU STOP gets refused
- [`modbus-tcp.md`](docs/modbus-tcp.md) - framing, function codes, the
  addressing traps (zero-based, word order, ASCII in registers)
- [`iec-60870-5-104.md`](docs/iec-60870-5-104.md) - APCI formats, ASDU
  structure, select-before-operate, command ordering and interlocks
- [`dnp3.md`](docs/dnp3.md) - three layers, CRC de-stuffing, groups and
  variations, CROB, IIN flags
- [`firmware-artifacts.md`](docs/firmware-artifacts.md) - cartridge headers
  and bank layout, embedded archives, 16-bit HMI binaries
- [`attack-mapping.md`](docs/attack-mapping.md) - MITRE ATT&CK for ICS
  technique mapping, and what generalises
- [`workflow.md`](docs/workflow.md) - the triage order of operations, plus
  Wireshark display filters for the same questions
- [`defense-notes.md`](docs/defense-notes.md) - turning each observation into
  a control an operator can implement

## Verifying the decoders

```bash
python3 tests/make_fixtures.py fixtures/
bash tests/run_all.sh fixtures/
```

`make_fixtures.py` builds synthetic BACnet, S7comm, Modbus, IEC-104, DNP3 and
TDS captures plus a Game Boy ROM with an embedded zlib archive and a `.COM`
HMI binary, all with known field values. `run_all.sh` runs every tool against
them.

## Scope and intent

Defensive analysis: reading artefacts, understanding protocol behaviour,
turning both into detections and hardening. Nothing here generates traffic
toward a device, brute-forces anything, or alters a controller. Use it on
captures and files you are authorised to analyse.

## Licence

MIT - see [LICENSE](LICENSE).
