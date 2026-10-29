"""One timeline out of every artefact in a case.

An incident is a sequence, not a pile of reports. This module turns captures
and text logs into the same kind of record - an `Event` with a UTC timestamp,
an actor, a target, a one-line summary and a reference you can check (a frame
number, a line number) - and merges them in time order.

Protocol events are selected, not dumped: a capture of 40 000 packets usually
contains a dozen things that matter, and those are what a timeline needs.
"""
from __future__ import annotations

import csv
import datetime as _dt
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from . import bacnet, creds, dnp3, iec104, modbus, pcapio, s7comm

# severity: 0 context, 1 reconnaissance, 2 suspicious, 3 impact on the process
SEVERITY_NAME = {0: "context", 1: "recon", 2: "suspicious", 3: "impact"}


@dataclass
class Event:
    ts: Optional[float]
    source: str                 # file the event came from
    kind: str                   # short machine-ish label
    summary: str                # one line, plain language
    actor: str = ""
    target: str = ""
    ref: str = ""               # frame 1234 / line 87
    severity: int = 1
    detail: str = ""
    tags: List[str] = field(default_factory=list)

    def iso(self) -> str:
        if self.ts is None:
            return "(no timestamp)"
        return _dt.datetime.fromtimestamp(self.ts, _dt.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def row(self) -> List[str]:
        return [self.iso(), SEVERITY_NAME.get(self.severity, "?"), self.kind,
                self.actor, self.target, self.summary, self.ref,
                os.path.basename(self.source)]


# ---------------------------------------------------------------------------
# captures
# ---------------------------------------------------------------------------
def _ev(pkt_ts, src, kind, summary, actor="", target="", frame=None,
        severity=1, detail="", tags=None) -> Event:
    return Event(ts=pkt_ts, source=src, kind=kind, summary=summary, actor=actor,
                 target=target, ref=(f"frame {frame}" if frame else ""),
                 severity=severity, detail=detail, tags=tags or [])


def from_capture(path: str, **filters) -> List[Event]:
    """Significant protocol events from one capture."""
    out: List[Event] = []
    ports = set(filters.pop("ports", []) or [])
    packets = pcapio.read_many([path], keep_raw=False, **filters)
    if not packets:
        return out

    # --- BACnet ----------------------------------------------------------
    bmsgs = bacnet.extract(packets)
    if bmsgs:
        results = bacnet.correlate(bmsgs)
        for res in results.values():
            m = res["request"]
            ok = res["outcome"] == "ok"
            if m.service in ("deviceCommunicationControl", "reinitializeDevice"):
                verb = "accepted" if ok else "refused"
                out.append(_ev(m.ts, path, "bacnet-" + m.service,
                               f"{m.service} ({m.enable_disable or m.reinit_state or '-'}) "
                               f"with password {m.password!r} was {verb}",
                               m.src, m.dst, m.frame, 3 if ok else 2,
                               tags=["T0814" if m.service.startswith("device") else "T0858"]))
            elif m.service in ("writeProperty", "writePropertyMultiple",
                               "atomicWriteFile", "createObject", "deleteObject"):
                out.append(_ev(m.ts, path, "bacnet-write",
                               f"wrote {m.prop or 'a property'} = {m.value} on "
                               f"{m.object_id or 'an object'}"
                               + (f" at priority {m.priority}" if m.priority else ""),
                               m.src, m.dst, m.frame, 3 if ok else 2,
                               tags=["T0836"]))
        sweeps = [m for m in bmsgs if m.service == "who-Is"]
        if sweeps:
            first = sweeps[0]
            out.append(_ev(first.ts, path, "bacnet-discovery",
                           f"BACnet discovery sweep ({len(sweeps)} who-Is messages)",
                           first.src, "broadcast", first.frame, 1, tags=["T0846"]))

    # --- S7comm ----------------------------------------------------------
    smsgs = s7comm.extract(packets)
    if smsgs:
        szl_first: Dict[str, Any] = {}
        for m in smsgs:
            if m.szl_id is not None and m.rosctr == "userdata" and m.src not in szl_first:
                szl_first[m.src] = m
            if m.function in ("request-download", "download-block") and m.block:
                out.append(_ev(m.ts, path, "s7-logic-download",
                               f"downloaded code block {m.block} into the PLC",
                               m.src, m.dst, m.frame, 3, tags=["T0821"]))
            elif m.function in ("start-upload", "upload") and m.block:
                out.append(_ev(m.ts, path, "s7-logic-upload",
                               f"read block {m.block} out of the PLC",
                               m.src, m.dst, m.frame, 2, tags=["T0845"]))
            elif m.function in ("plc-stop", "plc-control") and m.rosctr == "job":
                out.append(_ev(m.ts, path, "s7-cpu-control",
                               f"{m.function} requested ({m.service or '-'})",
                               m.src, m.dst, m.frame, 3, tags=["T0858"]))
            elif m.function in ("plc-stop", "plc-control") and m.error:
                out.append(_ev(m.ts, path, "s7-cpu-control-refused",
                               f"PLC refused the request ({m.error})",
                               m.src, m.dst, m.frame, 2))
            elif m.function == "write-var" and m.items and m.rosctr == "job":
                for it in m.items:
                    out.append(_ev(m.ts, path, "s7-tag-write",
                                   f"wrote {it.value} to {it.tag()}",
                                   m.src, m.dst, m.frame, 3, tags=["T0836"]))
        for src, m in szl_first.items():
            n = sum(1 for x in smsgs if x.src == src and x.szl_id is not None)
            out.append(_ev(m.ts, path, "s7-fingerprint",
                           f"read PLC diagnostic data ({n} SZL requests)",
                           src, m.dst, m.frame, 1, tags=["T0888"]))

    # --- Modbus ----------------------------------------------------------
    mmsgs = modbus.extract(packets)
    if mmsgs:
        for m in mmsgs:
            if m.is_response or m.func not in (5, 6, 15, 16, 22, 23):
                continue
            vals = m.values or m.bits
            out.append(_ev(m.ts, path, "modbus-write",
                           f"{m.name} on unit {m.unit} at {m.ref()} = "
                           + ",".join(str(v) for v in vals[:6]),
                           m.src, m.dst, m.frame, 3, tags=["T0855"]))
        scanners = modbus.scan_candidates(mmsgs)
        for host, info in scanners.items():
            first = next(m for m in mmsgs if m.src == host)
            out.append(_ev(first.ts, path, "modbus-enumeration",
                           f"enumerated {len(info['units'])} unit ids with "
                           f"{len(info['funcs'])} function codes "
                           f"({info['exceptions']} error replies)",
                           host, ",".join(sorted(info["targets"])), first.frame, 2,
                           tags=["T0846"]))

    # --- IEC-104 ---------------------------------------------------------
    imsgs = iec104.extract(packets)
    if imsgs:
        for m in imsgs:
            if m.fmt == "U" and m.ufunc and "STOPDT" in m.ufunc:
                out.append(_ev(m.ts, path, "iec104-stopdt",
                               "STOPDT sent: the station stops reporting while "
                               "the TCP session stays up",
                               m.src, m.dst, m.frame, 3, tags=["T0804"]))
            elif m.type_id in iec104.COMMAND_TYPES and m.cot == "activation":
                for o in (m.objects or [None]):
                    sel = ("select" if o and o.select else
                           "execute" if o and o.select is False else "command")
                    out.append(_ev(m.ts, path, "iec104-command",
                                   f"{m.type_name} {sel} on IOA "
                                   f"{o.ioa if o else '?'} = {o.value if o else '-'}",
                                   m.src, m.dst, m.frame,
                                   3 if sel != "select" else 2, tags=["T0855"]))
            elif m.negative:
                out.append(_ev(m.ts, path, "iec104-refused",
                               f"{m.type_name} was refused by the station",
                               m.src, m.dst, m.frame, 2))

    # --- DNP3 ------------------------------------------------------------
    dmsgs = dnp3.extract(packets)
    for m in dmsgs:
        if m.app_func in ("direct-operate", "direct-operate-no-ack", "operate",
                          "select", "write"):
            out.append(_ev(m.ts, path, "dnp3-control",
                           f"{m.app_func}: " + ("; ".join(m.objects[:2]) or "-"),
                           m.src, m.dst, m.frame, 3, tags=["T0855"]))
        elif m.app_func in ("cold-restart", "warm-restart", "stop-application"):
            out.append(_ev(m.ts, path, "dnp3-restart",
                           f"{m.app_func} commanded on the outstation",
                           m.src, m.dst, m.frame, 3, tags=["T0814"]))
        elif m.app_func == "disable-unsolicited":
            out.append(_ev(m.ts, path, "dnp3-silence",
                           "unsolicited reporting disabled: the outstation stops "
                           "volunteering events",
                           m.src, m.dst, m.frame, 3, tags=["T0804"]))

    # --- cleartext secrets -----------------------------------------------
    for f in creds.harvest(packets):
        out.append(_ev(f.ts, path, "credential-" + f.proto,
                       f"{f.proto} {f.kind} in the clear: {f.value[:90]}",
                       f.src, f.dst, f.frame, 2, tags=["T0812"]))
    return out


# ---------------------------------------------------------------------------
# text logs
# ---------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], start=1)}

RE_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$")
RE_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?\s+(.*)$")
RE_EPOCH_COMMENT = re.compile(r"^#(\d{9,11})\s*$")
RE_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# (pattern, kind, severity, template) - the small set that actually matters
LOG_RULES = [
    (re.compile(r"Accepted (password|publickey|keyboard-interactive) for (\S+) from (\S+)"),
     "ssh-login", 3, "SSH login accepted for {2} from {3} ({1})"),
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
     "ssh-failed", 1, "SSH password failed for {1} from {2}"),
    (re.compile(r"Invalid user (\S+) from (\S+)"),
     "ssh-invalid-user", 2, "SSH attempt for a user that does not exist: {1} from {2}"),
    (re.compile(r"session opened for user (\S+)"),
     "session-open", 2, "session opened for {1}"),
    (re.compile(r"new user: name=(\S+?),"),
     "user-created", 3, "a new local account was created: {1}"),
    (re.compile(r"to group '(\S+)'"),
     "group-change", 3, "an account was added to the group {1}"),
    (re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)$"),
     "sudo", 2, "{1} ran a command as root: {2}"),
    (re.compile(r"authorized_keys"),
     "ssh-key", 3, "an SSH authorized_keys file was touched"),
    (re.compile(r"(?:systemctl|service)\s+(stop|disable|mask)\s+(\S+)"),
     "service-stopped", 3, "a service was stopped or disabled: {2}"),
    (re.compile(r"\b(wget|curl)\b.*?(https?://\S+)"),
     "download", 2, "a file was downloaded with {1}: {2}"),
    (re.compile(r"\b(nmap|masscan|hydra|medusa|responder|mimikatz|plcscan|modbus-cli)\b"),
     "tooling", 3, "an offensive tool was run: {1}"),
    (re.compile(r"\b(?:rm|shred)\b\s+(?:-\w+\s+)*(/var/log\S*|\S*history\S*)"),
     "log-tampering", 3, "log or history files were deleted: {1}"),
    (re.compile(r"\b(?:iptables|ufw)\b.*\b(ACCEPT|flush|-F)\b"),
     "firewall-change", 3, "a firewall rule was changed"),
]


def _year_hint(path: str) -> int:
    try:
        return _dt.datetime.fromtimestamp(os.path.getmtime(path),
                                          _dt.timezone.utc).year
    except OSError:
        return _dt.datetime.now(_dt.timezone.utc).year


def _classify(text: str) -> Optional[tuple]:
    for rx, kind, sev, tmpl in LOG_RULES:
        m = rx.search(text)
        if m:
            groups = [g or "" for g in m.groups()]
            try:
                # templates use {1}, {2}, ... so pass a leading placeholder
                summary = tmpl.format(*([""] + groups))
            except (KeyError, IndexError):
                summary = text[:120]
            return kind, sev, summary.strip()
    return None


def from_log(path: str, year: Optional[int] = None,
             keep_unmatched: bool = False) -> List[Event]:
    """Parse a text log: syslog/auth.log, an ISO-timestamped log, a shell
    history (with or without HISTTIMEFORMAT epochs), or a CSV export."""
    events: List[Event] = []
    year = year or _year_hint(path)
    pending_ts: Optional[float] = None
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return events
    if path.lower().endswith(".csv") or (lines and lines[0].count(",") >= 2
                                         and "," in lines[min(1, len(lines) - 1)]):
        return _from_csv(path, lines)

    for n, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ts: Optional[float] = None
        text = line

        m = RE_EPOCH_COMMENT.match(line)
        if m:                                   # bash history timestamp line
            pending_ts = float(m.group(1))
            continue
        m = RE_ISO.match(line)
        if m:
            frac = float("0." + m.group(3)) if m.group(3) else 0.0
            d = _dt.datetime.fromisoformat(m.group(1) + "T" + m.group(2))
            d = d.replace(tzinfo=_dt.timezone.utc)
            ts, text = d.timestamp() + frac, m.group(5)
        else:
            m = RE_SYSLOG.match(line)
            if m:
                mon = MONTHS.get(m.group(1))
                if mon:
                    d = _dt.datetime(year, mon, int(m.group(2)), int(m.group(3)),
                                     int(m.group(4)), int(m.group(5)),
                                     tzinfo=_dt.timezone.utc)
                    ts, text = d.timestamp(), m.group(7)
            elif pending_ts is not None:
                ts, pending_ts = pending_ts, None

        hit = _classify(text)
        if hit is None and not keep_unmatched:
            continue
        kind, sev, summary = hit if hit else ("log-line", 0, text[:140])
        ip = RE_IP.search(text)
        events.append(Event(ts=ts, source=path, kind=kind, summary=summary,
                            actor=ip.group(1) if ip else "", target="",
                            ref=f"line {n}", severity=sev, detail=line.strip()))
    return events


def _from_csv(path: str, lines: List[str]) -> List[Event]:
    """A CSV export (an EVTX dump, a firewall export, a historian extract).

    Any column that parses as a timestamp becomes the event time; the rest of
    the row becomes the summary.
    """
    events: List[Event] = []
    reader = csv.reader(lines)
    rows = list(reader)
    if not rows:
        return events
    header = rows[0]
    time_col = 0
    for i, name in enumerate(header):
        if re.search(r"time|date|utc|@timestamp", name, re.I):
            time_col = i
            break
    for n, row in enumerate(rows[1:], start=2):
        if not row:
            continue
        ts = None
        raw = row[time_col] if time_col < len(row) else ""
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                    "%m/%d/%Y %I:%M:%S %p"):
            try:
                ts = _dt.datetime.strptime(raw.replace("Z", "").split(".")[0], fmt) \
                    .replace(tzinfo=_dt.timezone.utc).timestamp()
                break
            except ValueError:
                continue
        text = " | ".join(f"{h}={v}" for h, v in zip(header, row) if v and h != header[time_col])
        hit = _classify(text)
        kind, sev, summary = hit if hit else ("csv-row", 0, text[:160])
        ip = RE_IP.search(text)
        events.append(Event(ts=ts, source=path, kind=kind, summary=summary,
                            actor=ip.group(1) if ip else "", ref=f"line {n}",
                            severity=sev, detail=text[:400]))
    return events


# ---------------------------------------------------------------------------
# assembly and output
# ---------------------------------------------------------------------------
def build(paths: Iterable[str], min_severity: int = 0,
          keep_unmatched: bool = False, log_year: Optional[int] = None,
          **filters) -> List[Event]:
    events: List[Event] = []
    for p in paths:
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as fh:
            head = fh.read(4)
        if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                    b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
            events += from_capture(p, **filters)
        else:
            events += from_log(p, year=log_year, keep_unmatched=keep_unmatched)
    events = [e for e in events if e.severity >= min_severity]
    dated = [e for e in events if e.ts is not None]
    undated = [e for e in events if e.ts is None]
    dated.sort(key=lambda e: (e.ts, e.ref))
    return dated + undated


def to_csv(events: List[Event], path: str) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["utc", "severity", "kind", "actor", "target", "summary",
                    "reference", "source"])
        for e in events:
            w.writerow(e.row())


def to_json(events: List[Event], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(e) | {"utc": e.iso()} for e in events], fh, indent=2)


def to_markdown(events: List[Event], path: str, title: str = "Incident timeline") -> None:
    with open(path, "w") as fh:
        fh.write(f"# {title}\n\n")
        fh.write(f"_{len(events)} events, generated by ics-toolkit._\n\n")
        fh.write("| UTC | severity | actor | target | what happened | reference |\n")
        fh.write("|---|---|---|---|---|---|\n")
        for e in events:
            safe = e.summary.replace("|", r"\|")
            sev = SEVERITY_NAME.get(e.severity, "?")
            fh.write(f"| {e.iso()} | {sev} | {e.actor or '-'} | "
                     f"{e.target or '-'} | {safe} | "
                     f"{e.ref or '-'} ({os.path.basename(e.source)}) |\n")


def gaps(events: List[Event], threshold: float = 300.0) -> List[Dict[str, Any]]:
    """Quiet periods between events - often where the capture ends or where
    reporting was suppressed."""
    out = []
    dated = [e for e in events if e.ts is not None]
    for a, b in zip(dated, dated[1:]):
        if b.ts - a.ts >= threshold:
            out.append({"from": a.iso(), "to": b.iso(),
                        "seconds": round(b.ts - a.ts, 1),
                        "before": a.summary, "after": b.summary})
    return out
