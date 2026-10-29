"""Plain-language interpretation of tool output.

The tables the tools print are precise but assume you know the protocol. These
rules read a report back and state, in ordinary words, what it says and what to
look at next - so someone new to OT can act on the result instead of only
reading it.

Everything here is heuristic and additive: it never hides or rewrites the
report, it only annotates it.
"""
from __future__ import annotations

import re
from typing import Dict, List

GLOSSARY: Dict[str, str] = {
    "PLC": "Programmable Logic Controller - the industrial computer that runs "
           "the plant's control logic on a repeating scan cycle.",
    "HMI": "Human-Machine Interface - the operator's screen.",
    "RTU": "Remote Terminal Unit - a field device that reports measurements and "
           "accepts commands, common in electricity and water networks.",
    "BMS": "Building Management System - controls doors, lighting, ventilation.",
    "coil": "A single on/off output bit in Modbus. Forcing one can start a "
            "pump or silence an alarm horn.",
    "register": "A 16-bit value in Modbus. Process values that need more range "
                "(a flow, a dose) use two registers together.",
    "setpoint": "The target value the control loop aims for. Changing it "
                "changes what the plant does, without touching any code.",
    "tag": "A named value inside a controller, for example CL2_DOSE_A.",
    "SZL": "System Status List - a Siemens PLC's built-in diagnostic data. "
           "Readable without a password, so it is the standard way to "
           "identify a CPU.",
    "DCC": "DeviceCommunicationControl - a BACnet service that tells a device "
           "to stop answering the network. One packet, protected only by an "
           "optional cleartext password.",
    "IOA": "Information Object Address - the number identifying one point "
           "(one measurement or one command) in IEC-104.",
    "CROB": "Control Relay Output Block - the DNP3 message that operates a "
            "digital output, for example tripping a breaker.",
    "select-before-operate": "A two-step safety handshake: the master selects "
                             "a point, the device confirms, then the master "
                             "executes. It prevents a stray command from "
                             "moving plant.",
    "out-of-service": "A BACnet property that disconnects an object from the "
                      "physical world. The screen keeps showing a value, but "
                      "it is no longer the real one.",
    "priority": "BACnet commands carry a priority from 1 to 16. A low number "
                "wins. Writing at priority 1 or 2 makes a change hard for the "
                "control program to take back.",
    "exception code": "A Modbus error reply. A trail of them usually means "
                      "something was scanning addresses that do not exist.",
    "DeviceCommunicationControl": "The BACnet service that tells a device to "
        "stop answering the network - a one-packet denial of monitoring and "
        "control, protected only by an optional cleartext password.",
    "SimpleACK": "A bare BACnet acknowledgement: the device accepted the "
                 "request. An Error PDU instead means it refused.",
    "writeProperty": "The BACnet service that changes a value on a device. "
                     "This is the action, as opposed to readProperty, which "
                     "only observes.",
    "IEEE-754": "The standard binary layout for floating-point numbers. S7comm "
                "sends them big-endian, IEC-104 little-endian; getting the "
                "order wrong produces absurd values.",
    "unit id": "The Modbus field that addresses a device behind a gateway. "
               "Scanners sweep it because it is the only way to discover what "
               "is there.",
    "function code": "The Modbus field that says what kind of operation this "
                     "is - reading inputs, or writing an output.",
    "diagnostic buffer": "A ring buffer inside a Siemens PLC holding its own "
                         "event log, including why it last stopped. Small, so "
                         "it can be overwritten or cleared.",
    "entropy": "How unpredictable the bytes of a file are, from 0 to 8. Plain "
               "text sits near 4-5, ordinary code near 6, compressed or "
               "encrypted data above 7.2.",
    "offset": "A position in a file, counted in bytes from the start, usually "
              "written in hexadecimal. The hex view jumps to one directly.",
    "hash": "A fixed-length fingerprint of a file (md5, sha256). Two files with "
            "the same hash are the same file; it is how you prove later which "
            "file you analysed.",
    "UTF-16": "A text encoding that stores two bytes per character. Plain "
              "`strings` misses it, which is why text can look absent from a "
              "Windows binary or a firmware image.",
    "severity": "In the timeline: context, recon, suspicious, or impact. "
                "Impact means something was changed - a value, an account, a "
                "reporting channel - not that damage was proven.",
    "allow-list": "The set of hosts permitted to do something. In OT it is the "
                  "main control available, because the protocols themselves do "
                  "not authenticate.",
    "IIN": "Internal Indications - status flags a DNP3 outstation reports, "
           "including whether it has just restarted.",
}


def _count_rows(block: str) -> int:
    rows = 0
    for line in block.splitlines():
        if not line.strip() or line.startswith(("==", "--")) or "  " not in line:
            continue
        rows += 1
    return max(0, rows - 1)          # minus the header line


def _section(out: str, title_fragment: str) -> str:
    """Return the text of the first == section whose title matches."""
    blocks = re.split(r"\n== ", out)
    for b in blocks[1:]:
        head, _, body = b.partition("\n")
        if title_fragment.lower() in head.lower():
            return body
    return ""


def interpret(tool: str, args: List[str], out: str) -> List[str]:
    """Return plain-language observations about a report."""
    notes: List[str] = []
    low = out.lower()

    if not out.strip():
        return ["The tool produced no output - the artefact probably does not "
                "contain this protocol. Try the overview first."]
    if "no bacnet" in low or "no s7 traffic" in low or "no modbus" in low \
            or "no iec-104" in low or "no dnp3 frames" in low:
        return ["This capture does not carry that protocol. Run the overview "
                "to see which protocols are actually present."]

    # ---------------------------------------------------------------- overview
    if tool.startswith("pcap-overview"):
        m = re.search(r"packets\s+:\s+(\d+)", out)
        if m:
            notes.append(f"{m.group(1)} packets decoded. The 'recognised "
                         "services' table names the industrial protocols found; "
                         "that decides which specialised report to open next.")
        if "possible scanning" in low:
            notes.append("At least one host behaves like a scanner: it contacts "
                         "many peers or many ports, or sends connection "
                         "attempts without completing them. In an OT network "
                         "that is abnormal on its own - control traffic is "
                         "repetitive and goes to fixed peers.")
        if "fragmentation present" in low:
            notes.append("The capture contains IPv4 fragments. Some messages "
                         "may be split across packets, so a decoder can miss "
                         "them. Merge or reassemble before drawing conclusions.")
        if "unrecognised ports carrying payload" in low:
            notes.append("Some traffic sits on non-standard ports. Industrial "
                         "protocols are often relocated (Modbus on 10502, for "
                         "example); you can force a port with the --port option "
                         "of the matching tool.")
        return notes

    # ------------------------------------------------------------------ BACnet
    if tool.startswith("bacnet"):
        acc = _section(out, "attempts per")
        if acc:
            total = sum(int(x) for x in re.findall(r"\s(\d+)\s+\d+\s+\d+\s*$",
                                                   acc, re.M)) or None
            ok = re.findall(r"passwords that were accepted", low)
            notes.append("The attempts table counts every "
                         "DeviceCommunicationControl or ReinitializeDevice "
                         "request per attacker/target pair. 'failed/no-resp' "
                         "are the refusals - BACnet answers a wrong password "
                         "with an error of class 'security' and code "
                         "'password-failure'.")
            if ok:
                notes.append("At least one password was accepted (answered with "
                             "a SimpleACK). From that point the device was "
                             "under the sender's control; everything after it "
                             "in the timeline is the consequence.")
            if total:
                notes.append(f"If a challenge asks for a count of attempts "
                             f"against the first target, use the row for that "
                             f"target: total attempts there includes both the "
                             f"failures and the success.")
        if "candidate rogue devices" in low:
            notes.append("A host that issues BACnet requests but never answers "
                         "one, and never announces itself with an i-Am, is not "
                         "a building controller. That is the foreign device.")
        wr = _section(out, "writeproperty")
        if wr and _count_rows(wr) > 0:
            notes.append("Writes are the part that changed something. Read the "
                         "table in time order: the object column says what was "
                         "touched (a door, a lighting output, a sensor), and the "
                         "priority column says how hard it is for the control "
                         "program to take the change back.")
        if "out-of-service" in low:
            notes.append("A write to 'out-of-service' decouples a point from the "
                         "field. The operator's screen keeps showing a value "
                         "that is no longer real - this is how a sensor is "
                         "blinded without touching the sensor.")
        if "reinitializedevice" in low:
            notes.append("ReinitializeDevice reboots a controller or moves its "
                         "configuration. Appearing at the end of a timeline, it "
                         "is usually clean-up.")
        if not notes:
            notes.append("No password attempts or writes in this view. Try the "
                         "'Changes written to devices' and 'Password attempts' "
                         "reports, and the device inventory to find the host "
                         "that does not belong.")
        return notes

    # ------------------------------------------------------------------ S7comm
    if tool.startswith("s7"):
        if "szl" in low and _count_rows(_section(out, "szl")) > 0:
            notes.append("SZL reads are fingerprinting. 0x0011 and 0x001C "
                         "return the CPU order number, firmware and plant "
                         "designation; 0x00A0 and 0x0424 read the PLC's own "
                         "diagnostic log and the reason for its last STOP. No "
                         "password is needed for any of them.")
        if "blocks pushed to the plc" in low:
            notes.append("Blocks were downloaded *into* the PLC. In Siemens "
                         "terminology 'download' means PLC-bound, so this is a "
                         "logic change - the most consequential event in an S7 "
                         "capture. Each filename decodes to a block: OB is the "
                         "cyclic program, FB/FC are functions, DB is data.")
        if "cpu stop requested" in low:
            if re.search(r"class 0x[0-9a-f]{2} code 0x[0-9a-f]{2}", low):
                notes.append("The CPU STOP was refused: the response carries a "
                             "non-zero error class. Usual reasons are the mode "
                             "keyswitch not being in a remote-settable "
                             "position, a protection level that requires a "
                             "password, or know-how protection on the blocks. "
                             "The exact wording is in the PLC's diagnostic "
                             "buffer, which is why these challenges ship a "
                             "diagnostics export alongside the capture.")
            else:
                notes.append("A CPU STOP was requested. If the response shows no "
                             "error, the PLC halted its scan cycle - the plant "
                             "lost its controller.")
        if "written values" in low:
            notes.append("Written values are decoded as big-endian IEEE-754 "
                         "reals, which is what S7 uses. Compare each value "
                         "against the normal range for that tag: a chlorine "
                         "dose or a level limit pushed outside its envelope is "
                         "the impact.")
        if "s7comm-plus" in low:
            notes.append("Some traffic is S7comm-plus (S7-1200/1500). Its "
                         "payload is proprietary, so you get the function names "
                         "and the endpoints but not plaintext tag values.")
        if not notes:
            notes.append("Nothing dramatic in this view. Work through the "
                         "buttons in order: fingerprinting, then logic "
                         "transfers, then CPU state, then tag writes.")
        return notes

    # ------------------------------------------------------------------ Modbus
    if tool.startswith("modbus"):
        if "scan / enumeration" in low:
            notes.append("A host touched many unit ids or many function codes "
                         "and collected error replies. That is address "
                         "enumeration: Modbus has no authentication, so the "
                         "only way to learn a device's map is to ask for "
                         "everything and keep what answers.")
        if "exception responses" in low:
            notes.append("Exception replies tell you what does *not* exist. "
                         "Code 2 means illegal address, 11 means a gateway got "
                         "no answer from the serial device behind it.")
        if "write operations" in low and _count_rows(_section(out, "write operations")) > 0:
            notes.append("Writes changed plant state. Function 5 forces one "
                         "coil (an on/off output), 6 writes one register, 15 and "
                         "16 write blocks. A coil forced to 0 is often an alarm "
                         "being silenced; a register write is often a setpoint "
                         "or a limit.")
        if "ieee-754" in low:
            notes.append("Both word orders are printed because vendors "
                         "disagree. Keep the column whose value makes "
                         "engineering sense - a level of 62.5 percent is real, "
                         "1.4e-42 is the wrong order.")
        if "ascii carried in register" in low and _count_rows(_section(out, "ascii carried")) > 0:
            notes.append("Text was packed into registers, two characters per "
                         "register. Device labels and tag names live there, and "
                         "so does planted text.")
        if "address" in low and "0-based" not in low:
            notes.append("Addresses here are the raw wire values, which are "
                         "zero-based. Operator documentation usually shows them "
                         "one-based (wire 0 = register 40001), so expect an "
                         "off-by-one when comparing with a tag list.")
        return notes

    # ----------------------------------------------------------------- IEC-104
    if tool.startswith("iec104"):
        if "stopdt" in low:
            notes.append("A STOPDT was sent. That stops the device reporting "
                         "measurements and events while the TCP connection "
                         "stays up - the operator's screen goes quiet but the "
                         "link still looks healthy. Treat it as a deliberate "
                         "blinding step.")
        if "negative-confirm" in low or "negative confirmations" in low:
            notes.append("At least one command came back negatively confirmed: "
                         "the device refused it. Refusals map the interlocks - "
                         "they tell you which precondition you have not met "
                         "yet.")
        if "select-before-operate audit" in low:
            if "no sbo anomalies" in low:
                notes.append("Commands followed the select-then-execute "
                             "handshake correctly.")
            else:
                notes.append("Anomalies found. 'Execute without select' means a "
                             "command was issued without the safety handshake - "
                             "either the device permits direct execute, or "
                             "someone replayed a frame. 'Select never executed' "
                             "leaves a point reserved, which can block a "
                             "legitimate operator.")
        if "information object map" in low:
            notes.append("The point map separates the monitored direction "
                         "(measurements the device reports) from the control "
                         "direction (commands it accepts). Build a sequence off "
                         "the measurements, not off fixed delays: wait for the "
                         "feedback point to confirm each step.")
        if "short-float" in low:
            notes.append("IEC-104 short floats are little-endian IEEE-754 - the "
                         "opposite of S7comm. Mixing the two up produces "
                         "nonsense values.")
        return notes

    # -------------------------------------------------------------------- DNP3
    if tool.startswith("dnp3"):
        if "disable-unsolicited" in low:
            notes.append("Unsolicited reporting was disabled: the outstation "
                         "stops volunteering events, so the master only sees "
                         "what it polls for. Classic inhibit-then-impair "
                         "ordering.")
        if "cold-restart" in low or "warm-restart" in low:
            notes.append("A restart was commanded. For an RTU that is an "
                         "outage of monitoring and control for as long as it "
                         "takes to come back.")
        if "crob" in low:
            notes.append("A CROB operated a digital output. LATCH_ON/OFF holds "
                         "a state; PULSE_ON closes a contact for the on-time "
                         "given. On a substation device this is how a breaker "
                         "is tripped or closed.")
        if "device-restart" in low:
            notes.append("The outstation reported the device-restart flag, so it "
                         "really did reboot - the command took effect.")
        return notes

    # --------------------------------------------------------------- creds
    if tool.startswith("cleartext"):
        n = _count_rows(out)
        if n:
            notes.append(f"{n} credential or secret item(s) recovered in "
                         "cleartext. None of this required cracking: the "
                         "protocols transmit it as-is.")
        if "login7" in low:
            notes.append("A MS SQL Server login was captured. The password "
                         "field is not encrypted - it is each byte XORed with "
                         "0xA5 with its nibbles swapped - so it is shown "
                         "decoded. Historian and SCADA databases are a common "
                         "pivot because their accounts are often shared and "
                         "over-privileged.")
        if "community" in low:
            notes.append("An SNMP community string is effectively a password "
                         "sent in the clear in every packet. A write community "
                         "lets an attacker change device configuration.")
        if "query" in low:
            notes.append("The SQL queries themselves are worth reading: table "
                         "and column names reveal the tag naming scheme and the "
                         "plant areas.")
        return notes

    # ------------------------------------------------------------------ binary
    if tool.startswith("gb-cart"):
        if "mismatch" in low:
            notes.append("A checksum mismatch means the image was modified "
                         "after it was built. A bad header checksum points at "
                         "an edited header; a bad global checksum with a good "
                         "header checksum points at a patched body.")
        if "high entropy" in low or "high-entropy" in low:
            notes.append("High-entropy banks hold compressed or encrypted data - "
                         "that is where an embedded archive lives. Use 'Find "
                         "embedded archives' to extract it.")
        if "string-heavy" in low:
            notes.append("String-heavy banks hold menu text, alarm messages and "
                         "prompts. Read them: they describe the simulated "
                         "process and name the modes the rig supports.")
        if "xor" in low:
            notes.append("A container was found behind a single-byte XOR. That "
                         "is obfuscation, not encryption - the key is in the "
                         "table.")
        notes.append("Remember that a Game Boy address is not a file offset: "
                     "banked code at 0x4000-0x7FFF lives at "
                     "bank * 0x4000 in the file.")
        return notes

    if tool.startswith("dos-bin"):
        if "int 14h present" in low:
            notes.append("The binary drives a serial port directly, so it speaks "
                         "a field protocol (Modbus RTU, DF1 or a vendor ASCII "
                         "protocol). That is the half of the program worth "
                         "reversing.")
        if "overlay" in low:
            notes.append("Data is appended past the end of the executable "
                         "image. Carve it out and inspect it separately.")
        if "setpoint-like" in low:
            notes.append("The floating-point constants are candidate setpoints "
                         "and trip limits. Compare them with the operating "
                         "ranges in the strings: a limit sitting just above a "
                         "normal value is the shape of a tampered threshold.")
        notes.append("A .COM file has no header at all - the first byte of the "
                     "file is the first instruction, loaded at CS:0100h. "
                     "Offsets in this report are file offsets; add 0x100 for "
                     "the run-time address.")
        return notes

    if tool.startswith("blob-carve"):
        if "inflates to" in low or "magic-byte hits" in low:
            notes.append("Containers were found. Extract them, then run the "
                         "identification step again on what comes out - nested "
                         "containers are common.")
        if "high-entropy regions" in low:
            notes.append("High-entropy regions are packed or encrypted. If no "
                         "container magic appears there, test a single-byte XOR "
                         "before assuming real cryptography.")
        return notes

    if tool.startswith("stream-carve"):
        notes.append("Each stream is one conversation. Read the client-to-server "
                     "half for commands and the server-to-client half for "
                     "answers; carving extracts any file that was transferred.")
        return notes

    # ------------------------------------------------------------- timeline
    if tool.startswith("timeline"):
        n_impact = low.count("impact")
        notes.append("Each row is one event with the file and the frame or line "
                     "number it came from, so every statement in your report "
                     "stays checkable.")
        if "events that touched the process" in low:
            notes.append("The second table is the short list that matters: "
                         "commands that changed plant state, and accounts that "
                         "were created or used. Read the rows immediately "
                         "before the first one - that is usually where access "
                         "was obtained.")
        if n_impact:
            notes.append("Severity is a guide, not a verdict: 'impact' means "
                         "the event changed something (a value, an account, a "
                         "reporting channel), not that damage was proven.")
        if "quiet periods" in low:
            notes.append("A long gap in a control network is itself a finding. "
                         "Control traffic is periodic, so silence usually means "
                         "the capture stopped, a device stopped answering, or "
                         "reporting was suppressed.")
        if "no year" in low or "syslog lines carry no year" in low:
            notes.append("Syslog lines carry no year, so the file's "
                         "modification year was assumed. If the log is from "
                         "another year, pass --log-year, or the log events will "
                         "sort away from the capture events.")
        notes.append("Export it with --csv for a spreadsheet or --md for a "
                     "report you can paste into a ticket.")
        return notes

    # -------------------------------------------------------------- rules
    if tool.startswith("make-rules"):
        notes.append("The host groups were inferred from this capture: devices "
                     "are the hosts that answer requests, approved clients are "
                     "the ones that issue them and did not behave like a tool. "
                     "Check both against your asset inventory before deploying "
                     "anything.")
        if "excluded from the allow-lists" in low:
            notes.append("The excluded hosts are the ones that scanned, or that "
                         "issued the dangerous operations. They are kept out of "
                         "the allow-lists on purpose - otherwise the rules "
                         "would whitelist the attacker.")
        notes.append("Rules are emitted for the whole protocol, not only for "
                     "what happened here: a detection exists for what has not "
                     "happened yet. Use --only-observed if you want the "
                     "narrower set.")
        notes.append("Test the rules against a known-good capture before "
                     "deploying: 'suricata -r baseline.pcap -S ot-rules.rules' "
                     "should be silent. In OT, start in alert mode - dropping a "
                     "control packet can be as damaging as the attack.")
        return notes

    # ----------------------------------------------------- forensic helpers
    if tool.startswith("file-inspect"):
        notes.append("The hashes belong in your notes: they are how you prove "
                     "later that you analysed this exact file.")
        if "very high" in low:
            notes.append("Very high entropy means the content is compressed or "
                         "encrypted. If a container was found, extract it; if "
                         "not, test a single-byte XOR before assuming real "
                         "cryptography.")
        if "very low" in low:
            notes.append("Very low entropy means mostly padding or repeated "
                         "bytes - typical of a firmware image with large empty "
                         "regions. The interesting parts are the few dense "
                         "areas.")
        if "embedded containers" in low:
            notes.append("Something is packed inside this file. Extract it and "
                         "identify what comes out - nested containers are "
                         "common.")
        if "16 kib banks" in low:
            notes.append("The size is a whole number of 16 KiB banks, which is "
                         "what firmware and cartridge images look like. Treat "
                         "offsets as bank-relative rather than absolute.")
        return notes

    if tool.startswith("strings-plus"):
        notes.append("Each string carries its offset, so you can jump straight "
                     "to it with the hex view instead of searching again.")
        if "utf-16" in low or "wide-character" in low:
            notes.append("Some strings are UTF-16 (two bytes per character). "
                         "Plain `strings` misses those entirely, which is why "
                         "text seems to be 'missing' from Windows binaries and "
                         "firmware.")
        if "ot vocabulary" in low:
            notes.append("The OT vocabulary group is the fastest way to tell "
                         "what process a binary belongs to: units, equipment "
                         "names and alarm wording come from the plant it was "
                         "written for.")
        if "credential-like" in low:
            notes.append("Credential-like strings are a pattern match, not a "
                         "finding. Confirm each one in context before calling "
                         "it a password.")
        return notes

    if tool.startswith("hexview"):
        if "does not appear" in low:
            notes.append("Not finding text is normal: it may be stored as "
                         "UTF-16, compressed, or built at run time rather than "
                         "stored. The tool suggests the UTF-16 search when that "
                         "is the case.")
        else:
            notes.append("The left column is the file offset. Matched bytes are "
                         "shown in [brackets], and the right column is the same "
                         "bytes as text, with unprintable values shown as dots.")
        return notes

    if tool.startswith("bin-diff"):
        if "identical" in low:
            notes.append("The two files are the same. If you expected a "
                         "difference, you may be comparing a copy with itself.")
            return notes
        notes.append("Read the interpretation column first: a text change is a "
                     "relabelled message, a four-byte change in a data area is "
                     "usually a constant - a setpoint, a limit or a timer.")
        if "checksum" in low or "0x0000014" in low:
            notes.append("A change in the header area alone usually just means "
                         "the image was rebuilt, not that behaviour changed.")
        notes.append("Add --hexdump to see the bytes of each region if you need "
                     "to quote them in a report.")
        return notes

    if tool.startswith("decode"):
        if "nothing decoded" in low:
            notes.append("No encoding produced something more readable. That "
                         "usually means it is already plain data, it is packed "
                         "with something unusual, or it is genuinely encrypted - "
                         "in which case the key has to come from elsewhere.")
        else:
            notes.append("Candidates are ranked by how much the result looks "
                         "like real text. The top one is usually right, but "
                         "read it before trusting it - a high score on random "
                         "bytes is possible.")
            notes.append("XOR with a single byte is obfuscation, not "
                         "encryption. If that is what worked, the 'key' is just "
                         "a byte value and the data was never protected.")
        return notes

    if tool.startswith("triage-plan"):
        notes.append("This is the plan, not the analysis: each line is a command "
                     "you can run, in the order a responder would run them.")
        return notes

    if tool.startswith("pcap-merge"):
        notes.append("The captures are now one timeline with original "
                     "timestamps. Re-run identification on the merged file and "
                     "work from that, so cross-capture ordering is correct.")
        return notes

    return notes


def glossary_terms(text: str) -> Dict[str, str]:
    """Glossary entries whose term appears in the given text."""
    low = text.lower()
    return {k: v for k, v in GLOSSARY.items() if k.lower() in low}
