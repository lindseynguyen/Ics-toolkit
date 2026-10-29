# The incident timeline

A capture answers "what happened on the wire". A log answers "what happened on
the host". Neither answers "what happened", because an intrusion crosses both
and the order is the story. `tools/timeline.py` merges them.

```bash
python3 tools/timeline.py evidence/*
python3 tools/timeline.py capture.pcap auth.log --min-severity suspicious
python3 tools/timeline.py evidence/* --csv timeline.csv --md report.md
```

## What goes in

| Input | What is read |
|---|---|
| `.pcap` / `.pcapng` | the protocol events that matter: BACnet DCC and writes, S7 block downloads, CPU control and tag writes, Modbus writes and enumeration, IEC-104 commands and STOPDT, DNP3 control and restarts, cleartext credentials |
| syslog / `auth.log` | accepted and failed logins, invalid users, sudo, account and group creation, services stopped |
| shell history | every command, dated when the file was written with `HISTTIMEFORMAT`; downloads, scanners, history and log deletion are flagged |
| ISO-timestamped logs | application logs, as long as each line starts with a timestamp |
| CSV exports | an EVTX dump, a firewall export, a historian extract - any column that parses as a time becomes the event time |

Protocol events are **selected, not dumped**. A capture of 40 000 packets
usually holds a dozen events worth a line in a report, and those are the ones
that come out.

## What comes out

Each event carries a UTC timestamp, the actor, the target, a plain-language
summary, and a reference - `frame 46`, `line 9` - plus the file it came from.
That reference is the point: every sentence in your report stays checkable by
someone else.

```
2023-11-14T22:13:20.200Z  impact  10.20.30.77  10.20.30.10  DCC with password 'x' accepted   frame 20  bms.pcap
2023-11-14T22:13:20.280Z  impact  10.20.30.77  10.20.30.11  wrote out-of-service = 1 on BI:30 frame 28  bms.pcap
2023-11-14T22:13:24.000Z  impact  -            -            an offensive tool was run: nmap   line 8   bash_history
```

## Severity

Four levels, and they are a filter, not a verdict:

| Level | Meaning |
|---|---|
| `context` | background: a login, a routine message |
| `recon` | someone is looking: discovery sweeps, SZL reads, failed logins |
| `suspicious` | behaviour that is wrong for the host doing it: enumeration, refused password attempts, cleartext credentials |
| `impact` | something changed: a value written, an account created, a reporting channel silenced |

`--min-severity suspicious` is the usual working view. `impact` alone gives you
the short list to put in front of a plant manager.

## Reading one

Three habits make a timeline produce conclusions rather than rows:

1. **Find the first impact event, then read upwards.** Access was obtained
   somewhere above it, and anything that silenced reporting sits between the
   two.
2. **Watch for the inhibit-then-impair pattern.** A STOPDT, a
   `disable-unsolicited`, an alarm coil forced off, a historian service
   stopped - these come *before* the damaging command in almost every
   scenario, because the attacker wants the operator looking the other way.
3. **Treat gaps as evidence.** `--gaps 300` reports quiet periods. Control
   traffic is periodic, so a silent stretch usually means the capture stopped,
   a device stopped answering, or reporting was suppressed.

## Clock problems, which you will have

- **Syslog has no year.** The file's modification year is assumed; pass
  `--log-year 2024` when that is wrong. If log events sort a year away from
  capture events, this is why.
- **Captures are UTC, hosts often are not.** A PLC, a jump host and a SIEM can
  disagree by hours. The timeline does not correct for this - it cannot know -
  so check one known event in two sources before trusting the ordering.
- **Clock sync is a protocol function.** IEC-104 and DNP3 can set a device's
  clock, so a timestamp from a field device is only as trustworthy as the
  master that set it.

## Exports

`--csv` for a spreadsheet, `--json` for a pipeline, `--md` for a report you can
paste into a ticket. The Markdown export is a table with the same columns, and
it is the fastest path from analysis to something a colleague can read.
