# Modbus/TCP

Modbus is the lowest common denominator of industrial networking: TCP port
**502**, no authentication, no encryption, no session state beyond the
transaction id.

## Framing

```
MBAP header: transaction id (2) | protocol id (2, always 0) | length (2) | unit id (1)
PDU        : function code (1) | function data
```

`length` counts the unit id plus the PDU. The **unit id** was originally the
serial slave address behind a gateway; on native TCP devices it is often 1 or
255 and ignored, which is why scanners sweep it.

## Function codes

| FC | Name | Data model | Notes |
|---|---|---|---|
| 1 | read coils | discrete outputs (`0x`) | read/write bits |
| 2 | read discrete inputs | discrete inputs (`1x`) | read-only bits |
| 3 | read holding registers | holding registers (`4x`) | read/write 16-bit words |
| 4 | read input registers | input registers (`3x`) | read-only words |
| 5 | write single coil | `0x` | `0xFF00` = ON, `0x0000` = OFF |
| 6 | write single register | `4x` | one word |
| 15 | write multiple coils | `0x` | bit-packed, LSB first |
| 16 | write multiple registers | `4x` | the usual way to set a float |
| 22 | mask write register | `4x` | AND/OR mask - changes one bit without reading |
| 23 | read/write multiple | `4x` | atomic read and write |
| 43 | encapsulated interface | - | device identification (vendor, model) |

Errors come back with the function code **OR 0x80** plus an exception code:
1 illegal function, 2 illegal data address, 3 illegal data value,
4 server device failure, 6 busy, 11 gateway target no response. A sweep of
unit ids produces a trail of exception 11 or 2 - a reliable scan signature.

## Addressing traps

- **Zero- vs one-based.** The wire carries a zero-based address; documentation
  and HMIs usually show one-based "4x" references. Wire address 0 is register
  40001. Off-by-one answers usually come from this.
- **Register pairs.** 32-bit values occupy two registers. Byte/word order is
  vendor-specific: `ABCD` (big-endian) and `CDAB` (word-swapped) are both
  common; `BADC` and `DCBA` exist. Decode both and keep the one that lands in
  the engineering range of the tag.
- **ASCII in registers.** Device names, tag names and (in CTFs) hidden text
  are packed two characters per register.

`modbus-triage.py --floats` prints both word orders side by side and
`--strings` decodes register payloads as ASCII.

## What an attack looks like

1. **Discovery** - a host reading FC 3 at address 0, quantity 1, across many
   unit ids; many exceptions in reply.
2. **Mapping** - block reads with increasing start addresses, building a
   register map. This shows up as a staircase of (start, quantity) pairs.
3. **Impair** - FC 5/6/15/16 writes. Forcing an alarm coil to 0 silences a
   horn; writing a trip limit changes the plant's safe envelope; writing a
   pump command bit starts equipment.
4. **Impact** - the process leaves its envelope. The capture shows the
   written values; the consequence is in the narrative or the historian.

Reads are not harmless in context: a sustained high-rate poll can overrun a
small PLC's communication stack and cause a watchdog fault.

## Hardening

- Modbus has no authentication. Treat every reachable TCP/502 as writable by
  anyone who can route to it, and segment accordingly.
- Use a unidirectional gateway or a protocol-aware firewall that permits only
  the function codes a client genuinely needs (read-only for historians).
- Alert on *any* write function code from a host that normally only reads, and
  on writes to alarm coils and limit registers.
- Where devices support it, disable the programming port or require the
  keyswitch for logic changes; Modbus itself cannot enforce either.
