# From findings to detections

Analysis tells you what happened. A detection tells you if it happens again.
`tools/make-rules.py` closes that gap.

```bash
python3 tools/make-rules.py capture.pcap --out rules/
```

It profiles the capture, works out which hosts legitimately speak each
protocol, and writes:

```
rules/
  ot-rules.rules          Suricata
  ot-detections.zeek      Zeek policy
  sigma/ot-host-rules.yml Sigma, for the log side
  README.md               what to check before deploying
```

## How the allow-lists are inferred

- A **device** is a host that answers requests: it sends acknowledgements,
  responses, or an `i-Am`.
- A **client** is a host that issues requests.
- A host that scanned, or that issued one of the dangerous operations, is
  **excluded from the allow-lists**, so a rule set built from an incident
  capture does not whitelist the intruder.

This is inference from one capture, and the generated README says so. A device
that happened to be quiet is missing; a maintenance laptop that was connected
that day will look like a legitimate client. Check both lists against your
asset inventory - that is a five-minute job that decides whether the rules are
worth anything.

## What is covered

| Protocol | Detections |
|---|---|
| BACnet | DeviceCommunicationControl, ReinitializeDevice, writeProperty from an unapproved host |
| S7comm | CPU STOP, block download, SZL read bursts |
| Modbus | each write function code from an unapproved client, address and unit-id enumeration |
| IEC-104 | STOPDT, control commands from a non-master, reset process |
| DNP3 | operate / direct-operate from a non-master, restart and disable-unsolicited |
| Hosts (Sigma) | local account creation, history and log wiping, offensive tooling, monitoring services stopped, successful SSH after a failure burst |

Rules are emitted for the **whole protocol**, not only for what the capture
contained: the point of a detection is to catch what has not happened yet.
`--only-observed` narrows it when you want the smaller set.

## Byte offsets, and why they are checked

The Suricata rules match on content at fixed offsets - the BACnet service
choice at offset 9, the S7 function code at 17, the Modbus function code at 7.
Those offsets hold for the common case: one message per packet, no BACnet
routing header, no COTP segmentation.

A rule that never fires is worse than no rule, so the offsets are verified
against real traffic:

```bash
python3 tests/check_rule_offsets.py fixtures/
```

If your environment uses BACnet routing between networks, or S7 messages that
span TCP segments, re-check before relying on them - the toolkit's own reports
tell you whether your traffic looks like that.

## Before deploying

1. **Check the host groups** against your asset inventory.
2. **Measure the thresholds.** The enumeration rules are tuned to a guess. Your
   normal poll rate is in the overview report; use it.
3. **Test against a known-good capture.** `suricata -r baseline.pcap -S
   ot-rules.rules` should be silent. If it is not, fix the rule, not the
   baseline.
4. **Start in alert mode.** In OT, dropping a control packet can be as damaging
   as the attack it was meant to stop. Blocking is a decision for the people
   who own the process, not for the rule author.

## Zeek notes

The Zeek policy uses the built-in Modbus and DNP3 analyzers, plus a
first-seen-today notice for any host that speaks to an OT port. Zeek has no
analyzer for BACnet or S7comm, so those stay with Suricata - which is a
reasonable division: payload matching in Suricata, behavioural and stateful
logic in Zeek.
