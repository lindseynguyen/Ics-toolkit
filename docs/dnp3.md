# DNP3 (IEEE 1815)

DNP3 is the North American counterpart to IEC-104: substation RTUs, reclosers,
water districts. TCP/UDP port **20000**.

## Three layers

1. **Data link.** Frames start `05 64`, then length, control, 2-byte
   destination and source addresses, header CRC. The payload is split into
   16-octet blocks, each followed by its own 2-byte CRC - strip those before
   parsing anything above. (A parser that forgets the per-block CRC produces
   garbage one byte at a time; this is the classic DNP3 decoding bug.)
2. **Transport.** One octet: FIR, FIN and a 6-bit sequence, for segmenting
   application fragments.
3. **Application.** Application control octet, function code, and for
   responses a 2-octet **IIN** (internal indications).

## Function codes

| Code | Function | Significance |
|---|---|---|
| 1 | read | polling, or reconnaissance |
| 2 | write | configuration and flags |
| 3 / 4 | select / operate | the two-step control sequence |
| 5 / 6 | direct operate / no-ack | **single-step control** |
| 13 / 14 | cold / warm restart | **outage of the outstation** |
| 18 | stop application | halts the outstation's application |
| 20 / 21 | enable / disable unsolicited | **disable = the outstation stops reporting events on its own** |
| 129 / 130 | response / unsolicited response | |

`disable-unsolicited` followed by control operations is a textbook
inhibit-then-impair pair: the outstation stops volunteering events, so the
master's screen goes quiet while the adversary works.

## Objects

Objects are addressed by **group** and **variation** with a qualifier that
encodes an index prefix and a range specifier. Groups to know:

| Group | Contents |
|---|---|
| 1 / 2 | binary input (status / event) |
| 10 / 11 | binary output status / event |
| **12** | **binary output command - CROB** |
| 20-22 | counters |
| 30 / 32 | analog input (static / event) |
| 40 | analog output status |
| **41** | **analog output command** |
| 50 / 51 | time and date |
| 60 | class objects (class 0 = static data, 1-3 = event classes) |
| 80 | internal indications |

A **CROB** (g12v1) is 11 octets: control code, count, on-time, off-time,
status. Control codes: `LATCH_ON` (3), `LATCH_OFF` (4), `PULSE_ON` (1) and
the trip/close pair used for breakers. A breaker open is a `TRIP` CROB on the
right index - a one-packet outage.

Analog output commands (g41) carry an int32, int16, float32 or float64 value
plus a status octet - this is how a setpoint is pushed.

## IIN flags worth alerting on

`device-restart` (the outstation rebooted), `config-corrupt`,
`event-buffer-overflow` (events were lost - possibly a flood used to hide
something), `already-executing`, `func-not-supported`.

## Secure Authentication

DNP3-SA (IEEE 1815 / "SAv5") adds challenge-response authentication of
critical function codes with pre-shared or certificate-managed keys. It is
underdeployed; where it is absent, treat any routable DNP3 outstation as
controllable by anyone who can reach it.
