# Getting started: your first analysis

A hands-on walkthrough for someone who has never analysed industrial traffic.
It uses the synthetic fixtures shipped with the repository, so you can follow
every step and compare your output with what is described here. No real
network, no device, nothing to break.

Allow about forty minutes.

---

## 0. What you need

Python 3.9 or newer. Nothing else.

```bash
python3 --version
git clone https://github.com/lindseynguyen/Ics-toolkit
cd Ics-toolkit
python3 tests/make_fixtures.py fixtures/
```

The last command writes eight practice artefacts into `fixtures/`: five
captures carrying different industrial protocols, one capture full of
cleartext credentials, a Game Boy ROM standing in for a plant simulator, and
an old DOS executable standing in for a legacy operator station.

Start the interface:

```bash
python3 gui/serve.py
```

Leave that terminal running; it is the server. Everything below can also be
done entirely from a second terminal with the CLI commands shown.

---

## 1. Vocabulary, in one minute

You will meet these words constantly. You do not need more than this to start.

- A **PLC** is the computer that runs the plant. It executes a small program
  over and over - read the sensors, decide, drive the outputs - typically
  tens of times a second. That loop is the *scan cycle*.
- An **HMI** is the operator's screen. It does not control anything itself; it
  reads values from the PLC and sends the operator's commands to it.
- A **tag** or **point** is one named value inside the controller:
  `TANK_LEVEL`, `PUMP_RUN`, `CL2_DOSE_A`.
- A **setpoint** is the target the control loop aims for. Changing a setpoint
  changes what the plant does without touching a single line of code - which
  is why setpoints are a favourite target.
- **OT** (operational technology) is this world, as opposed to **IT**. The key
  difference for an analyst: in IT the worst case is data loss; in OT the worst
  case is a physical event.

And the one fact that explains almost every finding in this toolkit:
**these protocols have no authentication.** They were designed for a private,
trusted wire. Anyone who can reach the network can issue a valid command.

---

## 2. A building-management intrusion (BACnet/IP)

Drag `fixtures/bacnet_bms.pcap` onto the page.

The identification card says it is a capture carrying **BACnet/IP**, the
protocol behind door controllers, lighting and ventilation. Six hosts, half a
second of traffic.

### 2.1 Orient yourself

Click **Overview: who is on this network**.

```bash
python3 tools/pcap-overview.py fixtures/bacnet_bms.pcap
```

Read the *talkers* table. One host sent far more than anyone else. In a control
network that is already interesting: control traffic is repetitive and
balanced, because devices poll each other on a schedule.

### 2.2 Find the host that does not belong

Click **Device inventory**.

```bash
python3 tools/bacnet-triage.py fixtures/bacnet_bms.pcap --devices
```

BACnet devices announce themselves with an `i-Am` message carrying their device
object - `device:901`, for example. The report ends with a short list of hosts
that **issue requests but never answer any, and never announce themselves**.
A building controller answers questions. A tool only asks them. That is your
foreign device.

### 2.3 The password attempts

Click **Password attempts (DCC / reinitialize)**.

```bash
python3 tools/bacnet-triage.py fixtures/bacnet_bms.pcap --dcc
```

You should see nine rows. Four are marked `security/password-failure`, and the
rest `ok`.

What you are looking at: **DeviceCommunicationControl** is a legitimate BACnet
service that tells a device to stop answering the network. The device stays
powered, its network port stays up, and the operator's screen simply goes
blank for that device. The only protection is an optional password - sent in
cleartext, with no rate limiting and no lockout. So an attacker simply tries
passwords until one is accepted.

The second table counts attempts per attacker/target pair, splitting refusals
from acceptances. If someone asks "how many attempts were made against the
first target", that is the `total attempts` cell for that target - failures
plus the one that worked.

Note the last row: a `reinitializeDevice` with `warmstart`. That reboots the
controller. Coming at the end of a timeline, it is clean-up.

### 2.4 What was actually changed

Click **Changes written to devices**.

```bash
python3 tools/bacnet-triage.py fixtures/bacnet_bms.pcap --writes
```

Three writes, one per zone controller, all to `out-of-service`.

This is the part worth understanding properly. `out-of-service` disconnects a
BACnet object from the physical world. The object keeps reporting a value, and
the operator's screen keeps displaying it - but the value is now whatever was
written, not what the sensor sees. It is how you blind a monitoring system
without touching a single sensor.

The `prio` column is the BACnet command priority, 1 to 16, lowest number wins.
A write at priority 8 is "manual operator"; a write at priority 1 or 2 is very
hard for the control program to take back.

### 2.5 Write the finding down

You now have, with frame numbers and timestamps:

- a host that is on the BACnet segment and is not a BACnet device;
- a password brute force against the building controller, and the moment it
  succeeded;
- the same password reused against three zone controllers, in order;
- three sensor objects decoupled from reality;
- a controller reboot at the end.

That is an incident report. Keep the frame numbers: they are what makes each
sentence checkable by someone else.

---

## 3. A PLC under attack (S7comm)

Add `fixtures/s7comm_wtp.pcap`, then work down the steps.

```bash
python3 tools/s7-triage.py fixtures/s7comm_wtp.pcap --szl
python3 tools/s7-triage.py fixtures/s7comm_wtp.pcap --blocks
python3 tools/s7-triage.py fixtures/s7comm_wtp.pcap --control
python3 tools/s7-triage.py fixtures/s7comm_wtp.pcap --writes
```

**Fingerprinting.** The SZL report shows reads of `0x0011` and `0x001C` - the
CPU's order number and firmware, and the plant designation someone typed into
the engineering software. No password is needed for these. The third,
`0x0424`, is the reason for the CPU's last stop: whoever this is, they are
reading the PLC's own log.

**Logic transfer.** The blocks report shows three downloads: `OB1`, `DB5`,
`FB12`. In Siemens terminology *download* means toward the PLC, so this is
code being written **into** the controller. OB1 is the cyclic program - the
code that runs every scan. This is the most consequential event that can
appear in an S7 capture.

**CPU STOP.** Two attempts, both answered with an error class. The PLC refused.
That usually means the mode keyswitch is not in a remotely settable position,
or the protection level requires a password. Note what this tells you: the
attacker *tried* to halt the plant and could not. Refusals are evidence.

**Tag writes.** One real value written to `DB1.DBX2.0`: 4.25, where the PLC had
been reading 1.5. S7 reals are big-endian IEEE-754, and the tool decodes them
for you. Whether 4.25 is dangerous depends on the units and the process - which
is exactly the question to take to an engineer.

---

## 4. The smallest protocol (Modbus/TCP)

```bash
python3 tools/modbus-triage.py fixtures/modbus_plc.pcap
python3 tools/modbus-triage.py fixtures/modbus_plc.pcap --map
python3 tools/modbus-triage.py fixtures/modbus_plc.pcap --writes
python3 tools/modbus-triage.py fixtures/modbus_plc.pcap --floats
python3 tools/modbus-triage.py fixtures/modbus_plc.pcap --strings
```

Three things to take away.

**Enumeration leaves a trail of errors.** One host walked unit ids 1 to 7. Ids
1 and 2 answered; the rest returned exception 11. Modbus has no directory
service, so the only way to discover what exists is to ask for everything and
keep what answers - which is also what makes it so visible.

**Writes are few and they matter.** Function 5 forced coil 17 to 0. On a real
plant that single bit might be an alarm horn or a pump permissive. Function 16
wrote two registers at address 40.

**Two registers are one number.** Click *Decode register pairs as floating
point*: the pair reads 62.5 in big-endian order and nonsense in word-swapped
order. Vendors disagree about word order, so you always decode both and keep
the one that makes engineering sense. And *Find ASCII hidden in registers*
shows text packed two characters per register - how device labels, and
sometimes planted messages, travel.

One trap worth internalising now: the address on the wire is **zero-based**,
while operator documentation is usually one-based. Wire address 0 is register
40001. Most off-by-one arguments come from this.

---

## 5. Telecontrol and command ordering (IEC-104)

```bash
python3 tools/iec104-triage.py fixtures/iec104_rtu.pcap --commands
python3 tools/iec104-triage.py fixtures/iec104_rtu.pcap --sbo
```

IEC 60870-5-104 runs the electricity grid's remote control. Two ideas:

**Select before operate.** Moving plant is a two-step handshake: select the
point, let the device confirm, then execute. The audit flags an execute with
no select, and a select that was never executed. The first is a command issued
without the safety handshake; the second leaves a point reserved, which can
block a real operator.

**Refusals map the interlocks.** One setpoint came back *negatively confirmed*:
the device refused it. When a sequence has to be driven in a particular order -
open the valve, confirm the position, then start the pump - the negative
confirmations tell you exactly which precondition you have not met. Drive the
next step off the feedback point, not off a fixed delay.

Also notice the `STOPDT` at the end: it stops the device reporting while
leaving the TCP connection up. The link looks healthy and the operator sees
nothing. That pattern - silence the reporting first, act second - repeats in
every scenario in this repository.

---

## 6. Everything in the clear

```bash
python3 tools/cleartext-creds.py fixtures/cleartext_dmz.pcap
```

An FTP password, an SNMP community string, and a full MS SQL Server login
including the password. Nothing was cracked: FTP and SNMP transmit in the
clear, and SQL Server's "encrypted" password field is each byte XORed with
0xA5 with its nibbles swapped - obfuscation, not encryption.

Read the SQL query in the output too. Table and column names tell you the tag
naming scheme and the plant areas, which is reconnaissance in itself.

---

## 7. Binary artefacts

```bash
python3 tools/gb-cart-inspect.py fixtures/rig.gb
python3 tools/gb-cart-inspect.py fixtures/rig.gb --strings 1
python3 tools/gb-cart-inspect.py fixtures/rig.gb --blobs
python3 tools/dos-bin-inspect.py fixtures/SETPT16.COM
```

**The ROM.** Treat it as firmware. The header gives the mapper and the ROM
size, and the two checksums tell you whether the image was modified after it
was built. The bank profile is the map: string-heavy banks hold operator text,
high-entropy banks hold packed data. In this fixture, bank 1 holds plant
messages and bank 2 holds a zlib archive, which the blob scan finds and can
extract.

**The DOS binary.** It calls INT 14h, the BIOS serial service - so it talks to
a field device over a serial port, which means it implements a field protocol.
Its strings describe a chlorine setpoint utility, and the floating-point
constants near the end are candidate setpoints and trip limits. A limit sitting
just above a normal operating value is the classic shape of a tampered alarm
threshold.

The method generalises: **container, then regions, then data, then code.**
Reading strings and tables answers more questions than disassembly does, and it
answers them faster.

---

## 8. Putting the case together

Up to here you have run one tool against one file. Two commands work on the
whole case at once, and they are where the method pays off.

### One timeline

```bash
python3 tools/timeline.py fixtures/bacnet_bms.pcap fixtures/modbus_plc.pcap \
    fixtures/jumpbox_auth.log fixtures/jumpbox_bash_history \
    --log-year 2023 --min-severity suspicious
```

Captures and logs become the same kind of record, merged in UTC order: an SSH
login accepted after a run of failures, an account created and added to
`sudo`, a tool downloaded, a scan run, then the BACnet password attempts, then
the writes, then the history file being cleared.

Read it the way a responder does: **find the first `impact` row, then read
upwards.** Access was obtained somewhere above it. Anything that silenced
reporting sits between the two.

Every row carries the frame or line number it came from, so each sentence in
your report stays checkable. `--csv` and `--md` export it.

A warning worth internalising: syslog lines carry no year, so the year is
guessed from the file. That is why `--log-year` exists, and why log events can
otherwise sort a year away from capture events.

### Detections, not just findings

```bash
python3 tools/make-rules.py fixtures/bacnet_bms.pcap fixtures/modbus_plc.pcap \
    --out rules/
```

This works out which hosts legitimately speak each protocol - devices answer
requests, clients issue them - excludes the hosts that scanned or issued the
dangerous operations, and writes Suricata rules, a Zeek policy and Sigma rules
with those groups filled in.

Open `rules/README.md`. It tells you what to check before deploying, and that
list is the honest part: the groups came from one capture, the thresholds are
a guess, and in OT you start in alert mode because dropping a control packet
can be as damaging as the attack.

This is the step that turns an exercise into something your employer can use.

### When you do not know what a file is

```bash
python3 tools/file-inspect.py fixtures/*  --summary
python3 tools/file-inspect.py fixtures/rig.gb
python3 tools/strings-plus.py fixtures/SETPT16.COM
python3 tools/hexview.py fixtures/SETPT16.COM --find "SETPOINT"
python3 tools/bin-diff.py fixtures/rig.gb fixtures/rig_v2.gb
python3 tools/decode.py --text "UFVNUCBQLTEwMSBUUklQUEVEIC0gTEVWRUwgTE9X"
```

These are the everyday commands with OT knowledge built in. The one to try
first is `bin-diff.py` on the two ROM builds: it reports three changes and
tells you that one of them is a float that went from 1.5 to 9.75. That is a
complete firmware review in three lines, and it is the shape of a real finding -
someone moved a setpoint and rebuilt the image.

## 9. Several files at once

If you are given a capture split into fragments:

```bash
python3 tools/pcap-merge.py merged.pcap fragment_*.pcap
python3 tools/triage-plan.py merged.pcap
```

In the interface, Ctrl/Cmd-click several captures and the merge step is offered
automatically. Always analyse the merged file: cross-file ordering is where
split captures mislead you.

`triage-plan.py` is the terminal version of guided mode - point it at
everything you were given and it prints what each file is and which command to
run next.

If a capture is large - and a real one will be - read
[`large-captures.md`](large-captures.md) before you start. The short version:
every capture tool takes `--max-packets`, `--since` and `--until`, and cutting
the window out once with `pcap-merge.py` beats re-filtering a big file for
every question.

---

## 10. The habit to build

Four questions, in this order, for any OT artefact:

1. **Who spoke?** Which hosts, and does each one belong on this network?
2. **Read or write?** Reads observe; writes change the physical process.
3. **Accepted or refused?** Every protocol here says so explicitly.
4. **In what order?** Reporting is usually silenced before anything is changed.

Everything in `tools/` exists to answer one of those four. When you can answer
them without the interface, you have outgrown it - which is the point.

## Where to go next

- [`workflow.md`](workflow.md) - the same method as a checklist, with
  Wireshark display filters for each question
- [`00-challenge-map.md`](00-challenge-map.md) - which artefact type belongs to
  which kind of scenario
- the protocol documents, when you need the field-level detail
- [`attack-mapping.md`](attack-mapping.md) - how these observations map to
  MITRE ATT&CK for ICS
- [`defense-notes.md`](defense-notes.md) - turning the findings into controls
