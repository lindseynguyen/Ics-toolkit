# BACnet/IP for incident responders

BACnet (ASHRAE 135, ISO 16484-5) is the dominant building-automation protocol:
door controllers, lighting, air handling, occupancy sensing. BACnet/IP carries
it over UDP port **47808 (0xBAC0)**.

## Layering

```
UDP/47808
  BVLL / BVLC    1 byte 0x81, function, 2-byte length
  NPDU           version 0x01, control byte, optional DNET/SNET routing
  APDU           PDU type + service choice + ASN.1-style tagged parameters
```

BVLC functions worth knowing:

| Function | Name | Why it matters |
|---|---|---|
| 0x0A | original-unicast-NPDU | ordinary request/response |
| 0x0B | original-broadcast-NPDU | `who-Is` discovery sweeps |
| 0x04 | forwarded-NPDU | a BBMD relayed it; the **origin IP is inside the payload**, not the IP header |
| 0x05 | register-foreign-device | a host outside the subnet joining the BACnet network |

If a capture shows `forwarded-NPDU`, read the originating address from the
BVLC body: the IP header only shows the BBMD that forwarded it.

## APDU types

0 confirmed-request, 1 unconfirmed-request, 2 simple-ACK, 3 complex-ACK,
4 segment-ACK, 5 error, 6 reject, 7 abort. Requests carry an **invoke id**;
pairing request to response on that id is how you tell an accepted command
from a refused one.

## The object and property model

Everything is an object with a type and an instance number, written
`analog-output:4` (Wireshark short form `AO:4`). Common types: AI, AO, AV
(analog), BI, BO, BV (binary), MSI/MSO/MSV (multi-state), DEV (device),
`access-door`, `program`, `schedule`.

Properties are numbered. The ones that appear in attacks:

| # | Property | Effect when written |
|---|---|---|
| 85 | `present-value` | the actual command: unlock a door, stop a fan, turn off lights |
| 81 | `out-of-service` | decouples an object from the physical world - the sensor still reports, but the value is now whatever was written (a textbook way to blind operators) |
| 87 | `priority-array` | 16 command priorities; writing at a high priority overrides the controller's own logic |
| 104 | `relinquish-default` | the value used when all priorities are released |
| 77 | `object-name`, 28 `description` | relabelling, useful for hiding changes |

Writes carry an optional **priority** (1-16, 1 highest). A write at priority 8
("manual operator") beats normal program logic; priority 1 is reserved for
life safety. An adversary writing at priority 1-2 is making the change hard
for the control program to take back.

## DeviceCommunicationControl (service 17)

```
enable-disable : 0 enable | 1 disable | 2 disable-initiation
time-duration  : optional, in minutes (absent = indefinite)
password       : optional character string
```

`disable` tells a device to stop responding to **all** BACnet traffic except
DCC itself. The device stays powered, its link lights stay on, and the
operator workstation simply sees everything time out. That is a complete
denial of the monitoring and control function with one packet - and the only
protection is an optional password, sent in cleartext, with no rate limiting
and no lockout.

A wrong password answers with an **Error PDU, error class `security` (4),
error code `password-failure` (26)**. A correct one answers with a SimpleACK.
So counting attempts is mechanical: every confirmed request with service 17
is an attempt; the Error/SimpleACK split tells you which failed.

`ReinitializeDevice` (service 20) is the sibling: `coldstart` / `warmstart`
reboot the controller, `startbackup` / `startrestore` move its configuration.
It takes the same cleartext password.

## Reading a BACnet capture

1. Inventory devices: `i-Am` responses give each device's object identifier.
   A host that issues requests but never answers one, and never sends `i-Am`,
   is not a BACnet device - it is a tool.
2. Separate reads from writes. `readProperty` / `readPropertyMultiple` storms
   are reconnaissance; `writeProperty` is the action.
3. Order the writes by time: per-zone attack sequences fall out of the
   timeline directly.
4. Look at the last non-read service against each device. Clean-up steps
   (`reinitializeDevice`, writes to `object-name`, re-enabling comms) land
   at the end.

`bacnet-triage.py` does all four: `--devices`, `--writes`, `--dcc`, and the
default report, which ends with the last non-read service per device.

## Hardening

- BACnet/IP belongs on its own VLAN, never routed to a user network. Block
  UDP/47808 at the boundary; allow it only from the operator workstations.
- Set a DCC password on every device, and alert on *any* DCC or
  ReinitializeDevice on the wire - legitimate use is rare and planned.
- Restrict `register-foreign-device` on BBMDs to known addresses.
- Monitor for writes to `out-of-service` and for writes at priority 1-2.
- BACnet Secure Connect (BACnet/SC, ASHRAE 135 Annex AB) adds TLS and
  certificate-based device identity; it is the real fix where the equipment
  supports it.
