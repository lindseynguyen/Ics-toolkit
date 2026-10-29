# Challenge-to-technology map

A reading guide for OT-focused CTF categories: what technology each category
exercises, which artefact it ships, and which tool in this repository gives
you a first answer. **No flags, no solutions** - this maps categories to the
engineering concepts you need to understand them.

| Category pattern | Artefact | Technology under test | Start with |
|---|---|---|---|
| Building management / "access granted" series | BACnet/IP pcap | BACnet object & property model, DeviceCommunicationControl, ReinitializeDevice, priority arrays | `bacnet-triage.py --dcc`, `--writes` |
| "ICS PCAP analysis" / reservoir incident | BACnet/IP pcap | password brute force over an unauthenticated protocol, service denial by protocol abuse | `bacnet-triage.py`, `pcap-overview.py` |
| Water treatment "insane" series | S7comm pcap + network diagram | ISO-on-TCP, SZL diagnostics, block download, CPU STOP, IEEE-754 tag writes, protection levels | `s7-triage.py --szl --blocks --writes --control` |
| Impact / "104" | IEC 60870-5-104 client binary + IOA map | APCI framing, ASDU types, cause of transmission, select-before-operate ordering | `iec104-triage.py --commands --sbo` |
| Grid "blackout" chain | Mixed IT + Modbus pcaps, auth.log, bash history | pivoting into an OT DMZ, cleartext database and FTP credentials, Modbus register/coil scanning and forcing | `pcap-overview.py`, `cleartext-creds.py`, `modbus-triage.py --map` |
| Training rig / cartridge image | Game Boy ROM (`.gb`) | cartridge header and bank layout, embedded archive blobs, a simulated plant control loop | `gb-cart-inspect.py`, `blob-carve.py` |
| Legacy HMI | DOS `.COM` / MZ `.EXE` | 16-bit real-mode HMI, DOS/BIOS interrupts, serial field protocols, hard-coded setpoints | `dos-bin-inspect.py` |
| Fragmented captures | several `*_frag_NN.pcap` | capture stitching, TCP stream reassembly, file carving | `pcap-merge.py`, `stream-carve.py` |

## Why these artefacts show up

Each category corresponds to a stage of an OT intrusion as the industry
models it (see `attack-mapping.md`):

1. **Initial access and lateral movement** - IT-side artefacts: Windows logs,
   SSH auth logs, exposed services. Nothing OT-specific yet.
2. **Collection** - the adversary inventories the environment: asset lists,
   CVE lookups, documentation, historian queries.
3. **Inhibit response function** - alarms and safety reporting are suppressed
   so operators stop seeing reality.
4. **Impair process control** - setpoints, coils and logic are changed.
5. **Impact** - the physical process is pushed out of its safe envelope.

Protocol choice follows the sector: BACnet/IP for building and facility
systems, Modbus/TCP for small PLC and packaged skids, S7comm for Siemens
process control, IEC-104 and DNP3 for electricity transmission and
distribution.

## The common thread

None of these protocols authenticate by design. BACnet's password fields,
S7comm's protection levels and Modbus's unit identifiers are *addressing and
convenience features*, not security controls. That is why a capture of a few
hundred packets is often enough to reconstruct a complete attack: every
command, every value and every rejection is in cleartext.
