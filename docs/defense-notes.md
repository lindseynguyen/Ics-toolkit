# From challenge to control

Each challenge family corresponds to a control an operator can actually
implement. This is the translation layer - the reason analysing these artefacts
is worth the time.

## Segmentation and conduits

Every scenario here starts with reachability that should not exist: a BACnet
segment reachable from a corporate VLAN, a PLC reachable from a jump host that
is reachable from the internet. Define zones and conduits (IEC 62443-3-2),
then verify them by capture rather than by diagram - a routing table and a
firewall rule set are claims; a packet is evidence.

Minimum set of deny rules for a utility:

- UDP/47808, TCP/102, 502, 2404, 20000, 44818 must not cross the IT/OT
  boundary at all.
- Engineering protocols (TCP/102, CIP, 2455, 1962) only from a named
  engineering jump host, during a change window.
- Historians pull through a one-way gateway or a read-only account; the
  historian never initiates into the control zone.

## Protocol-aware monitoring

Signature lists are short because the dangerous operations are few and they
are all legitimate functions used by the wrong source:

| Alert on | Protocol |
|---|---|
| `deviceCommunicationControl`, `reinitializeDevice`, writes to `out-of-service`, writes at priority 1-2 | BACnet |
| `plc-stop`, PI-service, `request-download`, SZL bursts from a new host | S7comm |
| any write function code from a read-only client; writes to alarm coils and limit registers | Modbus |
| `STOPDT act`, `C_RP_NA_1`, clock sync from a non-master, command from a non-master IP | IEC-104 |
| `disable-unsolicited`, cold/warm restart, CROB from a non-master | DNP3 |
| new MAC/IP appearing on a control VLAN | all |

Asset inventory is the prerequisite: the rules above all depend on knowing
which host is *allowed* to issue control.

## Credentials

The captures in these challenge sets contain FTP, SNMP and database
credentials in cleartext because the real environments they model do too.
Practical steps: remove default SNMP communities, move to SNMPv3 or disable
SNMP write entirely, retire FTP and Telnet on field devices where firmware
allows, require TLS on the historian's SQL listener, and stop shared service
accounts from being reachable from the OT DMZ.

## Device-level hardening

- Siemens: protection level 3, block know-how protection, keyswitch out of
  `RUN-P`, access levels and secure communication on S7-1500.
- BACnet: DCC password set on every device, BBMD foreign-device registration
  restricted, BACnet/SC where supported.
- Modbus devices: disable unused function codes if the firmware allows;
  otherwise compensate with a protocol-aware firewall.
- IEC-104/DNP3: enable IEC 62351-3 TLS or DNP3-SA where the equipment and the
  master station both support it; require select-before-operate on points that
  move plant.

## Logging that survives the incident

Diagnostic buffers are small and circular (S7 SZL 0x00A0 holds a few hundred
entries) and an adversary can fill or clear them. Export PLC diagnostic
buffers on a schedule to a collector outside the control zone, keep network
captures at the boundary, and timestamp everything in UTC from a trusted
source - the clock-sync command exists in these protocols precisely because it
is trusted.

## Exercise design

If you build drills from this material, keep the artefact realistic and the
question operational. "Which IP issued the command, at what time, to which
point, and was it accepted?" is the question a responder answers on a real
night shift. Everything in this repository is built around producing that
answer with a frame number attached to it.
