# S7comm and S7comm-plus

Siemens SIMATIC PLCs speak **S7comm** over ISO-on-TCP (RFC 1006) on TCP port
**102**. S7-300/400 use the classic protocol (protocol id `0x32`); S7-1200/1500
use **S7comm-plus** (`0x72`), which is proprietary and partly encrypted.

## Layering

```
TCP/102
  TPKT      03 00 <2-byte length>
  COTP      length, PDU type (E0 CR, D0 CC, F0 DT), TPDU number
  S7 header 32 <ROSCTR> <redundancy id> <pduref> <param len> <data len> [error]
  parameter function code + items
  data      values, return codes
```

ROSCTR: `01` job (request), `02` ack, `03` ack-data (response with payload),
`07` userdata (diagnostics, security, time, block functions).

A **non-zero error class/code in an ack-data** means the CPU refused the job.
This is the single most useful field in an S7 capture: it separates *attempted*
from *achieved*.

## Function codes that matter

| Code | Function | Meaning in an intrusion |
|---|---|---|
| 0xF0 | setup-communication | negotiates PDU size; always first |
| 0x04 | read-var | reads tags - reconnaissance or legitimate polling |
| 0x05 | write-var | **changes a process value** |
| 0x1A/0x1B/0x1C | request-download / download-block / download-ended | **pushes logic into the PLC** |
| 0x1D/0x1E/0x1F | start-upload / upload / end-upload | pulls logic out (IP theft, or preparing a modified version) |
| 0x28 | PI-service (PLC control) | program invocation: restart, hot start, `P_PROGRAM` |
| 0x29 | PLC stop | **CPU STOP** - halts the scan cycle |

Note the direction convention: *download* means PLC-bound (engineering station
to CPU), *upload* means toward the engineering station. A "download" is the
logic-modification event.

### Addressing in read-var / write-var

Each item carries area, DB number, a 3-byte **bit** address and a transport
size:

| Area | Code | Notation |
|---|---|---|
| Inputs | 0x81 | `I` |
| Outputs | 0x82 | `Q` |
| Flags / merkers | 0x83 | `M` |
| Data block | 0x84 | `DBn.DBX b.x` |
| Instance DB | 0x85 | `DI` |

Transport size 0x07 is `real`: four bytes, **big-endian IEEE-754**. A chemical
dose, a flow setpoint or a level limit written as a real is read directly with
`struct.unpack('>f', ...)`. Byte order mistakes here produce absurd values -
if your dose comes out as 1e-38, you swapped the endianness.

### Block names

Download/upload parameters carry an ASCII filename: `_` + two-digit block type
+ five-digit number + one filesystem character.

| Code | Block |
|---|---|
| 08 | OB (organisation block - e.g. OB1, the cyclic program) |
| 0A | DB (data block) |
| 0C | FC (function) |
| 0E | FB (function block) |
| 0B / 0D / 0F | SDB / SFC / SFB (system blocks) |

`_0800001P` is therefore OB1 on the passive filesystem. Three distinct
filenames in a capture means three distinct code blocks were transferred.

## SZL: the System Status List

Userdata function group `0x04`, subfunction `0x01` ("Read SZL") is the PLC's
diagnostic interface. The request carries a 2-byte **SZL-ID** and an index.
It needs no authentication, which makes it the standard fingerprinting step.

| SZL-ID | Contents |
|---|---|
| 0x0011 | module identification: order number (6ES7...), CPU type, firmware |
| 0x001C | component identification: plant designation, module name, serial |
| 0x0012 / 0x0013 / 0x0014 | CPU characteristics, memory areas, system areas |
| 0x0019 / 0x0074 | LED status |
| 0x0024 / 0x0424 | operating-mode transitions and the **cause of the last STOP** |
| 0x0091 / 0x0092 / 0x0094 | module and rack status |
| 0x00A0 | **diagnostic buffer entries** - the PLC's own event log |
| 0x0232 | protection level / password status |

An attacker reading 0x0011 and 0x001C is identifying what it is talking to;
reading 0x00A0 or 0x0424 is reading the PLC's own log, often to learn *why*
a command was refused.

## Why a CPU STOP gets refused

A `plc-stop` job answered with an error typically means one of:

- **Keyswitch position.** On S7-300/400 the mode selector in `RUN` (not
  `RUN-P`) refuses remote mode changes.
- **Protection level.** Levels 1-3 in the hardware configuration; level 2 or 3
  requires a password for write or for any access. Login is userdata group
  `0x05`.
- **Know-how protection** on the blocks, or **copy protection** bound to the
  memory card serial.
- **F-CPU / safety program** restrictions, where a stop is only allowed
  through a controlled sequence.

The precise reason is in the diagnostic buffer (SZL 0x00A0) and the
mode-transition cause (SZL 0x0424) as a human-readable text - which is why
challenge sets often ship a PCS 7 diagnostics export alongside the capture.

## S7comm-plus

S7-1200/1500 wrap requests in protocol id `0x72` with opcodes
`0x31` request / `0x32` response / `0x33` notification, and function ids such
as `GetMultiVariables` (0x04BB), `SetMultiVariables` (0x04CA), `Explore`
(0x0524) and `CreateObject` (0x0586). Integrity protection and session keys
were added across firmware versions. You can still profile *who* talked and
*which* function was called - which is usually enough for attribution - but
the payload is not plaintext tag data.

## Hardening

- Put engineering access behind a jump host; allow TCP/102 only from it.
- Set protection level 3 plus block know-how protection; on S7-1500 enable
  access levels and (where available) secure communication.
- Alert on any `request-download`, `plc-stop` or `PI-service` outside a change
  window. These are rare, planned events in a healthy plant.
- Log SZL reads: a burst of 0x0011/0x001C from an unexpected host is
  reconnaissance.
- Keep the keyswitch out of `RUN-P` in production where the CPU supports it.
