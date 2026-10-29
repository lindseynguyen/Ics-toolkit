"""Artefact identification and suggested-step planning.

The GUI (and `tools/triage-plan.py`) uses this to answer two questions for a
newcomer: *what am I looking at*, and *what should I run first*. Detection is
content-based - extensions are only a tie-breaker - so a capture named
`evidence.bin` is still recognised.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import pcapio

# port -> (artefact kind, human name, tool, extra args)
ICS_PROTOCOLS: Dict[int, Tuple[str, str, str]] = {
    47808: ("bacnet", "BACnet/IP (building management)", "bacnet-triage.py"),
    102: ("s7comm", "S7comm / ISO-on-TCP (Siemens PLC)", "s7-triage.py"),
    502: ("modbus", "Modbus/TCP", "modbus-triage.py"),
    2404: ("iec104", "IEC 60870-5-104 (telecontrol)", "iec104-triage.py"),
    20000: ("dnp3", "DNP3 (IEEE 1815)", "dnp3-triage.py"),
}

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 161: "SNMP",
                   389: "LDAP", 1433: "MS SQL Server (TDS)", 3306: "MySQL",
                   25: "SMTP", 110: "POP3", 143: "IMAP"}

NINTENDO_LOGO_HEAD = bytes([0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B])


@dataclass
class Step:
    """One suggested analysis action."""
    label: str                      # button text
    tool: str                       # script name under tools/
    args: List[str] = field(default_factory=list)
    why: str = ""                   # plain-language reason
    primary: bool = False           # highlight as the recommended next click


@dataclass
class Artefact:
    path: str
    size: int
    kind: str                       # pcap | gbrom | dosbin | archive | text | unknown
    summary: str                    # one line, plain language
    details: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    steps: List[Step] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _sniff(path: str, n: int = 4096) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def _is_pcap(head: bytes) -> bool:
    return head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                        b"\x0a\x0d\x0d\x0a")


def _is_gb(path: str, head: bytes) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0x104)
            logo = fh.read(8)
        if logo == NINTENDO_LOGO_HEAD:
            return True
    except OSError:
        pass
    return path.lower().endswith((".gb", ".gbc"))


def _is_dosbin(path: str, head: bytes) -> bool:
    if head[:2] in (b"MZ", b"ZM"):
        return True
    if path.lower().endswith(".com"):
        return True
    # a small flat binary full of INT instructions is almost certainly a .COM
    if len(head) < 65536 and head.count(b"\xcd") >= 3 and b"$" in head:
        return True
    return False


def _is_text(head: bytes) -> bool:
    if not head:
        return False
    printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b < 127)
    return printable / len(head) > 0.92


def _analyse_pcap(path: str) -> Artefact:
    art = Artefact(path=path, size=os.path.getsize(path), kind="pcap",
                   summary="Packet capture")
    try:
        packets = pcapio.read_packets(path)
    except Exception as exc:                      # malformed or truncated
        art.warnings.append(f"could not parse as a capture: {exc}")
        art.kind = "unknown"
        return art
    if not packets:
        art.warnings.append("the capture decoded to zero packets")
        return art

    counts: Dict[int, int] = {}
    clear: Dict[int, int] = {}
    for p in packets:
        for port in (p.dport, p.sport):
            if port in ICS_PROTOCOLS:
                counts[port] = counts.get(port, 0) + 1
            elif port in CLEARTEXT_PORTS:
                clear[port] = clear.get(port, 0) + 1

    t0, t1 = packets[0].ts, packets[-1].ts
    hosts = {p.src for p in packets if p.src}
    art.details.append(f"{len(packets)} packets, {len(hosts)} hosts, "
                       f"{t1 - t0:.1f} s of traffic")
    frag = sum(1 for p in packets if p.frag_mf or p.frag_off)
    if frag:
        art.warnings.append(
            f"{frag} IPv4 fragments present - protocol decoding may miss "
            "messages until the capture is reassembled")

    art.steps.append(Step(
        label="Overview: who is on this network",
        tool="pcap-overview.py",
        why="Lists every host, every conversation and which industrial "
            "protocol is present. Always the first step: it tells you which "
            "specialised tool to use next.",
        primary=not counts))

    ordered = sorted(counts.items(), key=lambda kv: -kv[1])
    for port, n in ordered:
        kind, name, tool = ICS_PROTOCOLS[port]
        art.protocols.append(name)
        art.steps.append(Step(
            label=f"Analyse {name}",
            tool=tool,
            why=f"{n} packets use port {port}, so this capture carries {name}. "
                "This report pairs each request with its response, so you can "
                "see what the device accepted and what it refused.",
            primary=(port == ordered[0][0])))
        # protocol-specific follow-ups, in the order a responder would use them
        if kind == "bacnet":
            art.steps += [
                Step("Password attempts (DCC / reinitialize)", tool, ["--dcc"],
                     "BACnet device passwords travel in cleartext and are not "
                     "rate limited. This counts every attempt per target and "
                     "separates the refusals from the one that worked."),
                Step("Changes written to devices", tool, ["--writes"],
                     "Reads are monitoring; writes are the attack. This lists "
                     "every object that was written, with the command priority."),
                Step("Device inventory", tool, ["--devices"],
                     "A host that only asks questions and never answers any, "
                     "and never announces itself, is a tool rather than a "
                     "building controller."),
            ]
        elif kind == "s7comm":
            art.steps += [
                Step("PLC fingerprinting (SZL reads)", tool, ["--szl"],
                     "The System Status List is the PLC's own diagnostic "
                     "interface and needs no password. Reading it is how an "
                     "intruder identifies the CPU before touching it."),
                Step("Logic transfers (block up/download)", tool, ["--blocks"],
                     "A 'download' means code was pushed into the PLC. This is "
                     "the event that changes how the plant behaves."),
                Step("CPU state changes (STOP / restart)", tool, ["--control"],
                     "Shows attempts to halt the CPU and whether the PLC "
                     "refused them, with the error class that says why."),
                Step("Tag reads and writes", tool, ["--writes"],
                     "Every variable touched, with real values decoded as "
                     "IEEE-754 - this is where a changed setpoint shows up."),
            ]
        elif kind == "modbus":
            art.steps += [
                Step("Register and coil map", tool, ["--map"],
                     "Builds the address map the intruder built: which blocks "
                     "were scanned, which were written, and the last value seen."),
                Step("Write operations only", tool, ["--writes"],
                     "Modbus writes change plant state. Forcing a coil off can "
                     "silence an alarm; writing a register can move a setpoint."),
                Step("Decode register pairs as floats", tool, ["--floats"],
                     "32-bit process values span two registers and vendors "
                     "disagree on word order. Both orders are shown; keep the "
                     "one that lands in a sensible engineering range."),
                Step("Find ASCII hidden in registers", tool, ["--strings"],
                     "Tag names, device labels and sometimes planted text are "
                     "packed two characters per register."),
            ]
        elif kind == "iec104":
            art.steps += [
                Step("Control commands sent", tool, ["--commands"],
                     "The control direction only: every command, its cause of "
                     "transmission, and whether the device confirmed it "
                     "positively or negatively."),
                Step("Select-before-operate audit", tool, ["--sbo"],
                     "Controlled outputs are supposed to be selected, then "
                     "executed. An execute with no select, or a select never "
                     "executed, is either a replay or a blocked operator."),
                Step("Point map (information objects)", tool, ["--ioa"],
                     "Which points are measurements and which are commands - "
                     "the map you need before driving a process sequence."),
            ]
        elif kind == "dnp3":
            art.steps.append(Step(
                "Control operations (CROB / setpoints)", tool, ["--controls"],
                "A single CROB can trip a breaker. This decodes the control "
                "code, the index and the pulse timing."))

    if clear:
        names = ", ".join(sorted(CLEARTEXT_PORTS[p] for p in clear))
        art.steps.append(Step(
            label="Harvest cleartext credentials",
            tool="cleartext-creds.py",
            why=f"Traffic on {names} is present, and these protocols send "
                "credentials in the clear. MS SQL Server's 'encrypted' "
                "password field is a nibble swap and an XOR - this decodes it.",
            primary=not counts))
        art.protocols += [CLEARTEXT_PORTS[p] for p in sorted(clear)]

    art.steps.append(Step(
        label="List TCP streams",
        tool="stream-carve.py",
        why="Groups the capture into conversations you can read end to end, "
            "and lets you carve any file that was transferred."))

    if art.protocols:
        art.summary = "Packet capture carrying " + ", ".join(art.protocols[:3])
    else:
        art.summary = ("Packet capture with no recognised industrial protocol "
                       "on a standard port - start with the overview")
    return art


def _analyse_gb(path: str) -> Artefact:
    from . import gbcart
    art = Artefact(path=path, size=os.path.getsize(path), kind="gbrom",
                   summary="Game Boy cartridge image (a self-contained "
                           "simulator or training rig)")
    try:
        info = gbcart.inspect(path)
        art.details.append(f"title {info.title!r}, {info.cart_type}, "
                           f"{info.rom_size}")
        if not info.header_ok:
            art.warnings.append("header checksum mismatch - the header was edited")
        if not info.global_ok:
            art.warnings.append("global checksum mismatch - the ROM body was "
                                "modified after it was built")
        hi = [b for b in info.banks if b.entropy >= 7.2]
        if hi:
            art.details.append("high-entropy bank(s): "
                               + ", ".join(str(b.index) for b in hi)
                               + " - compressed or encrypted data lives there")
    except Exception as exc:
        art.warnings.append(f"header parse failed: {exc}")
    art.steps = [
        Step("Inspect cartridge header and banks", "gb-cart-inspect.py",
             why="Reads the header (mapper, ROM/RAM size, checksums) and "
                 "profiles each 16 KiB bank. Text-heavy banks hold operator "
                 "messages; high-entropy banks hold packed data.",
             primary=True),
        Step("Find embedded archives", "gb-cart-inspect.py", ["--blobs"],
             why="Scans for compressed containers, including ones hidden "
                 "behind a single-byte XOR, which is the usual 'encryption'."),
        Step("Read text from bank 1", "gb-cart-inspect.py", ["--strings", "1"],
             why="Menu text, alarm messages and prompts describe the simulated "
                 "process and often name the mode you are looking for."),
        Step("Interrupt vectors", "gb-cart-inspect.py", ["--vectors"],
             why="Useful when comparing a patched ROM against an original."),
        Step("Generic blob analysis", "blob-carve.py", ["--entropy"],
             why="Entropy profile of the whole file, so you can see where the "
                 "code ends and the data begins."),
    ]
    return art


def _analyse_dosbin(path: str) -> Artefact:
    from . import dosbin
    art = Artefact(path=path, size=os.path.getsize(path), kind="dosbin",
                   summary="Legacy 16-bit DOS binary (an old HMI or utility)")
    try:
        info = dosbin.inspect(path)
        art.details.append(info.kind)
        if info.serial_io:
            art.details.append("calls INT 14h - it talks to a field device "
                               "over a serial port, so it implements a "
                               "field protocol")
        if info.overlay_offset:
            art.warnings.append(
                f"data appended beyond the executable image at offset "
                f"0x{info.overlay_offset:04x} - a classic hiding place")
        if info.float_candidates:
            art.details.append(f"{len(info.float_candidates)} setpoint-like "
                               "floating-point constants found")
    except Exception as exc:
        art.warnings.append(f"parse failed: {exc}")
    art.steps = [
        Step("Full static report", "dos-bin-inspect.py",
             why="Container layout, interrupt usage, operator strings and "
                 "candidate setpoint constants in one pass.",
             primary=True),
        Step("Operator-visible text only", "dos-bin-inspect.py", ["--screens"],
             why="The prompts and alarm messages tell you what process the "
                 "program controls and in which units."),
        Step("Setpoint-like constants", "dos-bin-inspect.py", ["--floats"],
             why="A limit sitting just above a normal operating value is the "
                 "shape of a tampered alarm threshold."),
        Step("Interrupt call sites", "dos-bin-inspect.py", ["--ints"],
             why="Shows whether the binary reads files, draws a screen, or "
                 "drives a serial port - and where in the file it does it."),
        Step("Look for embedded containers", "blob-carve.py",
             why="Checks for appended archives or images inside the binary."),
    ]
    return art


def _analyse_text(path: str) -> Artefact:
    art = Artefact(path=path, size=os.path.getsize(path), kind="text",
                   summary="Text log or export")
    head = _sniff(path, 2048).decode("latin-1")
    low = head.lower()
    hints: List[str] = []
    if "sshd" in low or "authentication failure" in low or "sudo:" in low:
        hints.append("Linux authentication log: look for accepted logins after "
                     "a run of failures, and for new keys or users")
    if "powershell" in low or "event" in low and "id" in low:
        hints.append("Windows event export: correlate logon type and process "
                     "creation around the suspicious window")
    if low.strip().startswith(("#", "time", "date")) or "," in head.split("\n")[0]:
        hints.append("delimited export: a spreadsheet or `awk` is faster than "
                     "a decoder here")
    art.details += hints or ["no specific log format recognised"]
    art.warnings.append("This toolkit decodes binary artefacts; text logs are "
                        "read directly. Nothing to run here - open it, or use "
                        "grep/sort/uniq.")
    return art


def identify(path: str) -> Artefact:
    """Content-based identification plus a suggested order of analysis."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    head = _sniff(path)
    if _is_pcap(head):
        return _analyse_pcap(path)
    if _is_gb(path, head):
        return _analyse_gb(path)
    if _is_dosbin(path, head):
        return _analyse_dosbin(path)
    if _is_text(head):
        return _analyse_text(path)
    art = Artefact(path=path, size=os.path.getsize(path), kind="archive",
                   summary="Binary file of an unrecognised type")
    art.details.append("Treated as a generic blob: container scan, "
                       "decompression attempts and an entropy profile.")
    art.steps = [
        Step("Scan for containers and compression", "blob-carve.py",
             why="Finds zip/gzip/zlib/xz payloads, tries to decompress them, "
                 "and sweeps for containers hidden behind a single-byte XOR.",
             primary=True),
        Step("Entropy profile", "blob-carve.py", ["--entropy"],
             why="Shows which parts of the file are code, which are plain data "
                 "and which are packed."),
        Step("Printable strings", "blob-carve.py", ["--strings", "6"],
             why="Often the fastest way to recognise what a file belongs to."),
    ]
    return art


def plan_group(paths: List[str]) -> List[Step]:
    """Cross-file suggestions, e.g. stitching a fragmented capture set."""
    steps: List[Step] = []
    caps = [p for p in paths if _is_pcap(_sniff(p))]
    if len(caps) > 1:
        steps.append(Step(
            label=f"Merge {len(caps)} captures into one timeline",
            tool="pcap-merge.py",
            why="Challenge artefacts often arrive split into fragments. "
                "Merging them in timestamp order lets every decoder see one "
                "coherent session instead of pieces.",
            primary=True))
    return steps
