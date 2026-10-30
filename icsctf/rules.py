"""Turn what a capture shows into detections you can deploy.

Reading a capture answers "what happened". A detection answers "tell me if it
happens again". This module closes that gap: it profiles a capture, works out
which hosts legitimately speak each industrial protocol, and emits Suricata
rules, Zeek policy and Sigma rules for the operations that matter.

Everything is emitted with the environment variables left as named
placeholders and with a comment saying what to check before deploying. A rule
you cannot explain is a rule you should not deploy.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set

from . import bacnet, dnp3, iec104, modbus, pcapio, s7comm

SID_BASE = 9100000

PROTO_PORTS = {"bacnet": 47808, "s7comm": 102, "modbus": 502,
               "iec104": 2404, "dnp3": 20000}


@dataclass
class Profile:
    """What a capture says about the environment."""
    protocols: Set[str] = field(default_factory=set)
    servers: Dict[str, Set[str]] = field(default_factory=dict)   # proto -> device ips
    clients: Dict[str, Set[str]] = field(default_factory=dict)   # proto -> master ips
    suspects: Set[str] = field(default_factory=set)              # scanners / rogue
    observed: Set[str] = field(default_factory=set)              # finding keys
    notes: List[str] = field(default_factory=list)

    def net_guess(self) -> str:
        ips = {ip for s in self.servers.values() for ip in s}
        nets = sorted({".".join(ip.split(".")[:3]) + ".0/24" for ip in ips
                       if ip.count(".") == 3})
        return ",".join(f"[{n}]" for n in nets) if len(nets) > 1 else \
            (nets[0] if nets else "any")


def profile_capture(paths: Iterable[str], **filters) -> Profile:
    p = Profile()
    packets = pcapio.read_many(list(paths), keep_raw=False, **filters)
    if not packets:
        return p

    bmsgs = bacnet.extract(packets)
    if bmsgs:
        p.protocols.add("bacnet")
        servers = {m.src for m in bmsgs
                   if m.pdu_type in ("simple-ack", "complex-ack", "error")} | \
                  {m.src for m in bmsgs if m.service == "i-Am"}
        clients = {m.src for m in bmsgs if m.pdu_type == "confirmed-request"}
        p.servers["bacnet"] = servers
        p.clients["bacnet"] = clients - servers
        for m in bmsgs:
            if m.service == "deviceCommunicationControl":
                p.observed.add("bacnet-dcc")
            elif m.service == "reinitializeDevice":
                p.observed.add("bacnet-reinit")
            elif m.service in ("writeProperty", "writePropertyMultiple"):
                p.observed.add("bacnet-write")
                if m.prop == "out-of-service":
                    p.observed.add("bacnet-out-of-service")
                if m.priority and m.priority <= 2:
                    p.observed.add("bacnet-high-priority")
            elif m.service == "who-Is":
                p.observed.add("bacnet-discovery")
        # only the requester counts: a device that answers a DCC is the victim
        p.suspects |= {m.src for m in bmsgs
                       if m.pdu_type == "confirmed-request"
                       and m.service in ("deviceCommunicationControl",
                                         "reinitializeDevice")}

    smsgs = s7comm.extract(packets)
    if smsgs:
        p.protocols.add("s7comm")
        p.servers["s7comm"] = {m.src for m in smsgs if m.rosctr in ("ack", "ack-data")}
        p.clients["s7comm"] = {m.src for m in smsgs if m.rosctr in ("job", "userdata")}
        for m in smsgs:
            if m.function in ("plc-stop", "plc-control"):
                p.observed.add("s7-cpu-control")
            if m.function in ("request-download", "download-block"):
                p.observed.add("s7-download")
            if m.function in ("start-upload", "upload"):
                p.observed.add("s7-upload")
            if m.szl_id is not None:
                p.observed.add("s7-szl")
            if m.function == "write-var" and m.rosctr == "job":
                p.observed.add("s7-write")

    mmsgs = modbus.extract(packets)
    if mmsgs:
        p.protocols.add("modbus")
        p.servers["modbus"] = {m.src for m in mmsgs if m.is_response}
        p.clients["modbus"] = {m.src for m in mmsgs if not m.is_response}
        for m in mmsgs:
            if not m.is_response and m.func in (5, 6, 15, 16, 22, 23):
                p.observed.add("modbus-write")
            if m.exception:
                p.observed.add("modbus-exception")
        p.suspects |= set(modbus.scan_candidates(mmsgs))

    imsgs = iec104.extract(packets)
    if imsgs:
        p.protocols.add("iec104")
        p.servers["iec104"] = {m.src for m in imsgs if m.cot == "activation confirmation"}
        p.clients["iec104"] = {m.src for m in imsgs if m.cot == "activation"}
        for m in imsgs:
            if m.fmt == "U" and m.ufunc and "STOPDT" in m.ufunc:
                p.observed.add("iec104-stopdt")
            if m.type_id in iec104.COMMAND_TYPES and m.cot == "activation":
                p.observed.add("iec104-command")
            if m.type_id == 105:
                p.observed.add("iec104-reset")

    dmsgs = dnp3.extract(packets)
    if dmsgs:
        p.protocols.add("dnp3")
        p.servers["dnp3"] = {m.src for m in dmsgs if m.app_func in ("response",
                                                                    "unsolicited-response")}
        p.clients["dnp3"] = {m.src for m in dmsgs if m.app_func not in
                             ("response", "unsolicited-response")}
        for m in dmsgs:
            if m.app_func in ("direct-operate", "direct-operate-no-ack", "operate"):
                p.observed.add("dnp3-control")
            if m.app_func in ("cold-restart", "warm-restart"):
                p.observed.add("dnp3-restart")
            if m.app_func == "disable-unsolicited":
                p.observed.add("dnp3-silence")
    return p


# ---------------------------------------------------------------------------
# Suricata
#
# Byte offsets below assume the common case: an unfragmented message, one
# message per packet, no BACnet routing header and no COTP segmentation. That
# covers the operations these rules target, and each rule says so.
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    key: str
    proto_family: str
    msg: str
    body: str
    comment: str
    severity: int = 1


def _suricata_rules(p: Profile) -> List[Rule]:
    r: List[Rule] = []

    if "bacnet" in p.protocols:
        r.append(Rule(
            "bacnet-dcc", "bacnet",
            "OT BACnet DeviceCommunicationControl from a host outside the allow-list",
            'alert udp !$BACNET_CLIENTS any -> $BACNET_DEVICES 47808 '
            '(msg:"{msg}"; content:"|81|"; offset:0; depth:1; '
            'content:"|01|"; offset:4; depth:1; content:"|00|"; offset:6; depth:1; '
            'content:"|11|"; offset:9; depth:1; '
            'classtype:attempted-dos; reference:url,attack.mitre.org/techniques/T0814/; '
            'sid:{sid}; rev:1;)',
            "DCC tells a device to stop answering the network. Legitimate use is "
            "rare and planned, so alert on all of it and tune by source.", 3))
        r.append(Rule(
            "bacnet-reinit", "bacnet",
            "OT BACnet ReinitializeDevice (device restart or config change)",
            'alert udp !$BACNET_CLIENTS any -> $BACNET_DEVICES 47808 '
            '(msg:"{msg}"; content:"|81|"; offset:0; depth:1; '
            'content:"|14|"; offset:9; depth:1; '
            'classtype:attempted-admin; '
            'reference:url,attack.mitre.org/techniques/T0858/; sid:{sid}; rev:1;)',
            "Reboots a controller or moves its configuration. Should only ever "
            "come from the commissioning workstation.", 3))
        r.append(Rule(
            "bacnet-write", "bacnet",
            "OT BACnet writeProperty from a host outside the allow-list",
            'alert udp !$BACNET_CLIENTS any -> $BACNET_DEVICES 47808 '
            '(msg:"{msg}"; content:"|81|"; offset:0; depth:1; '
            'content:"|0F|"; offset:9; depth:1; '
            'classtype:attempted-admin; '
            'reference:url,attack.mitre.org/techniques/T0836/; sid:{sid}; rev:1;)',
            "Writes change physical state. Keep $BACNET_CLIENTS to the operator "
            "workstations and this is quiet in normal operation.", 3))

    if "s7comm" in p.protocols:
        r.append(Rule(
            "s7-stop", "s7comm",
            "OT S7comm CPU STOP requested",
            'alert tcp !$S7_CLIENTS any -> $S7_PLCS 102 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|03 00|"; offset:0; depth:2; content:"|32 01|"; offset:7; depth:2; '
            'content:"|29|"; offset:17; depth:1; '
            'classtype:attempted-dos; '
            'reference:url,attack.mitre.org/techniques/T0858/; sid:{sid}; rev:1;)',
            "Halts the PLC scan cycle. There is no benign unplanned reason for "
            "this to cross the network.", 3))
        r.append(Rule(
            "s7-download", "s7comm",
            "OT S7comm block download (PLC logic being changed)",
            'alert tcp !$S7_CLIENTS any -> $S7_PLCS 102 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|32 01|"; offset:7; depth:2; content:"|1A|"; offset:17; depth:1; '
            'classtype:attempted-admin; '
            'reference:url,attack.mitre.org/techniques/T0821/; sid:{sid}; rev:1;)',
            "Logic changes belong to a change window and to the engineering "
            "station. Alert, then correlate with your change record.", 3))
        r.append(Rule(
            "s7-szl", "s7comm",
            "OT S7comm SZL diagnostic read (PLC fingerprinting)",
            'alert tcp !$S7_CLIENTS any -> $S7_PLCS 102 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|32 07|"; offset:7; depth:2; '
            'threshold:type threshold, track by_src, count 5, seconds 60; '
            'classtype:attempted-recon; '
            'reference:url,attack.mitre.org/techniques/T0888/; sid:{sid}; rev:1;)',
            "Engineering software reads SZL too, so this is thresholded: a burst "
            "from a host that is not the engineering station is the signal.", 2))

    if "modbus" in p.protocols:
        for fc, name in ((5, "write single coil"), (6, "write single register"),
                         (15, "write multiple coils"), (16, "write multiple registers")):
            r.append(Rule(
                f"modbus-fc{fc}", "modbus",
                f"OT Modbus {name} from a host outside the allow-list",
                'alert tcp !$MODBUS_CLIENTS any -> $MODBUS_DEVICES 502 '
                '(msg:"{msg}"; flow:to_server,established; '
                f'content:"|00 00|"; offset:2; depth:2; content:"|{fc:02X}|"; offset:7; depth:1; '
                'classtype:attempted-admin; '
                'reference:url,attack.mitre.org/techniques/T0855/; sid:{sid}; rev:1;)',
                "Modbus has no authentication, so the source address is the only "
                "control you have. A historian that only reads should never "
                "trigger this.", 3))
        r.append(Rule(
            "modbus-scan", "modbus",
            "OT Modbus unit-id or address enumeration",
            'alert tcp any any -> $MODBUS_DEVICES 502 '
            '(msg:"{msg}"; flow:to_server,established; content:"|00 00|"; offset:2; depth:2; '
            'threshold:type both, track by_src, count 40, seconds 60; '
            'classtype:attempted-recon; '
            'reference:url,attack.mitre.org/techniques/T0846/; sid:{sid}; rev:1;)',
            "Tune the count to your normal poll rate: a polling HMI is regular "
            "and predictable, a scanner is bursty. Check the rate in your own "
            "baseline capture before deploying.", 2))

    if "iec104" in p.protocols:
        r.append(Rule(
            "iec104-stopdt", "iec104",
            "OT IEC-104 STOPDT (station told to stop reporting)",
            'alert tcp any any -> $IEC104_RTUS 2404 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|68 04 13 00 00 00|"; offset:0; depth:6; '
            'classtype:attempted-dos; '
            'reference:url,attack.mitre.org/techniques/T0804/; sid:{sid}; rev:1;)',
            "Blinds the operator while the TCP session stays up. Normal only "
            "during a planned master changeover.", 3))
        r.append(Rule(
            "iec104-command", "iec104",
            "OT IEC-104 control command from a host that is not the master",
            'alert tcp !$IEC104_MASTERS any -> $IEC104_RTUS 2404 '
            '(msg:"{msg}"; flow:to_server,established; content:"|68|"; offset:0; depth:1; '
            'pcre:"/^\\x68.{{3}}[\\x00-\\xff]{{2}}[\\x2d\\x2e\\x2f\\x30\\x31\\x32]/s"; '
            'classtype:attempted-admin; '
            'reference:url,attack.mitre.org/techniques/T0855/; sid:{sid}; rev:1;)',
            "Matches the control type ids 45-50 (single/double command, "
            "regulating step, setpoints) in an I-format frame.", 3))
        r.append(Rule(
            "iec104-reset", "iec104",
            "OT IEC-104 reset process command",
            'alert tcp any any -> $IEC104_RTUS 2404 '
            '(msg:"{msg}"; flow:to_server,established; content:"|68|"; offset:0; depth:1; '
            'content:"|69|"; offset:6; depth:1; '
            'classtype:attempted-dos; sid:{sid}; rev:1;)',
            "C_RP_NA_1 (type id 105) resets the station. Exceptional by design.",
            3))

    if "dnp3" in p.protocols:
        r.append(Rule(
            "dnp3-operate", "dnp3",
            "OT DNP3 operate / direct-operate from a host that is not the master",
            'alert tcp !$DNP3_MASTERS any -> $DNP3_OUTSTATIONS 20000 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|05 64|"; offset:0; depth:2; '
            'pcre:"/^\\x05\\x64.{{10}}[\\x03\\x04\\x05\\x06]/s"; '
            'classtype:attempted-admin; '
            'reference:url,attack.mitre.org/techniques/T0855/; sid:{sid}; rev:1;)',
            "A single CROB can trip a breaker. Keep the master list tight.", 3))
        r.append(Rule(
            "dnp3-silence", "dnp3",
            "OT DNP3 unsolicited reporting disabled or outstation restarted",
            'alert tcp any any -> $DNP3_OUTSTATIONS 20000 '
            '(msg:"{msg}"; flow:to_server,established; '
            'content:"|05 64|"; offset:0; depth:2; '
            'pcre:"/^\\x05\\x64.{{10}}[\\x0d\\x0e\\x15]/s"; '
            'classtype:attempted-dos; '
            'reference:url,attack.mitre.org/techniques/T0804/; sid:{sid}; rev:1;)',
            "Disable-unsolicited (21), cold restart (13) and warm restart (14) "
            "all remove the operator's view.", 3))
    return r


def suricata(p: Profile, only_observed: bool = False) -> str:
    rules = _suricata_rules(p)
    if only_observed:
        rules = [r for r in rules if r.key in p.observed or
                 r.key.startswith("modbus-fc") and "modbus-write" in p.observed]
    out = [_header("Suricata rules", p),
           "# Variables - define these in suricata.yaml (vars: address-groups)",
           "#"]
    for name, hosts in _vars(p).items():
        out.append(f"#   {name:<20} {hosts}")
    out += ["#",
            "# Offsets assume one message per packet, no BACnet network-layer "
            "routing",
            "# header and no COTP segmentation. Verify against your own capture "
            "before",
            "# relying on them; the toolkit's reports tell you whether your "
            "traffic matches.",
            ""]
    sid = SID_BASE
    for r in rules:
        sid += 1
        out.append(f"# {r.comment}")
        out.append(r.body.format(msg=r.msg, sid=sid))
        out.append("")
    return "\n".join(out)


def _vars(p: Profile) -> Dict[str, str]:
    def group(ips: Set[str]) -> str:
        if not ips:
            return "[]   # nothing observed - fill this in"
        return "[" + ",".join(sorted(ips)) + "]"
    v: Dict[str, str] = {}
    if "bacnet" in p.protocols:
        v["$BACNET_DEVICES"] = group(p.servers.get("bacnet", set()))
        v["$BACNET_CLIENTS"] = group(p.clients.get("bacnet", set()) - p.suspects)
    if "s7comm" in p.protocols:
        v["$S7_PLCS"] = group(p.servers.get("s7comm", set()))
        v["$S7_CLIENTS"] = group(p.clients.get("s7comm", set()) - p.suspects)
    if "modbus" in p.protocols:
        v["$MODBUS_DEVICES"] = group(p.servers.get("modbus", set()))
        v["$MODBUS_CLIENTS"] = group(p.clients.get("modbus", set()) - p.suspects)
    if "iec104" in p.protocols:
        v["$IEC104_RTUS"] = group(p.servers.get("iec104", set()))
        v["$IEC104_MASTERS"] = group(p.clients.get("iec104", set()) - p.suspects)
    if "dnp3" in p.protocols:
        v["$DNP3_OUTSTATIONS"] = group(p.servers.get("dnp3", set()))
        v["$DNP3_MASTERS"] = group(p.clients.get("dnp3", set()) - p.suspects)
    v["$OT_NET"] = p.net_guess()
    return v


def _header(what: str, p: Profile) -> str:
    when = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return (f"# {what} generated by ics-toolkit on {when}\n"
            f"# Protocols observed: {', '.join(sorted(p.protocols)) or 'none'}\n"
            "#\n"
            "# These are a starting point, not a finished rule set. The host\n"
            "# groups were inferred from one capture: a device that was quiet\n"
            "# during it is missing, and a host that misbehaved during it may\n"
            "# have been excluded. Review every group against your asset\n"
            "# inventory before deploying.\n#")


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------
def zeek(p: Profile) -> str:
    masters = {
        "modbus": sorted(p.clients.get("modbus", set()) - p.suspects),
        "dnp3": sorted(p.clients.get("dnp3", set()) - p.suspects),
    }
    ot_ports = sorted({PROTO_PORTS[x] for x in p.protocols if x in PROTO_PORTS})
    lines = [
        _header("Zeek policy", p).replace("# ", "## ").replace("#\n", "##\n"),
        "##",
        "## Load with:  zeek -r capture.pcap ot-detections.zeek",
        "## or add to local.zeek:  @load ./ot-detections.zeek",
        "",
        "module OT;",
        "",
        "export {",
        "    redef enum Notice::Type += {",
        "        Unapproved_Modbus_Write,",
        "        Modbus_Exception_Burst,",
        "        Unapproved_DNP3_Control,",
        "        DNP3_Outstation_Restart,",
        "        New_Host_On_OT_Port,",
        "    };",
        "}",
        "",
        "# Hosts allowed to issue control. Inferred from a capture - review it.",
        "const modbus_masters: set[addr] = {",
        "    " + (", ".join(masters["modbus"]) or "# none observed") + ",",
        "} &redef;",
        "",
        "const dnp3_masters: set[addr] = {",
        "    " + (", ".join(masters["dnp3"]) or "# none observed") + ",",
        "} &redef;",
        "",
        "const ot_ports: set[port] = {",
        "    " + (", ".join(f"{x}/tcp" for x in ot_ports if x != 47808) or "502/tcp") + ",",
        "} &redef;",
        "",
        "# Modbus function codes that change the process.",
        "const modbus_write_funcs: set[count] = { 5, 6, 15, 16, 22, 23 } &redef;",
        "",
        "global seen_ot_pairs: set[addr, port] &create_expire = 1day;",
        "",
        "event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)",
        "    {",
        "    if ( ! is_orig ) return;",
        "    if ( headers$function_code !in modbus_write_funcs ) return;",
        "    if ( c$id$orig_h in modbus_masters ) return;",
        "    NOTICE([$note=Unapproved_Modbus_Write,",
        "            $conn=c,",
        "            $msg=fmt(\"Modbus write (function %d) from %s, which is not a \"",
        "                     \"listed master\", headers$function_code, c$id$orig_h),",
        "            $identifier=cat(c$id$orig_h, headers$function_code),",
        "            $suppress_for=10min]);",
        "    }",
        "",
        "event modbus_exception(c: connection, headers: ModbusHeaders, code: count)",
        "    {",
        "    NOTICE([$note=Modbus_Exception_Burst,",
        "            $conn=c,",
        "            $msg=fmt(\"Modbus exception %d to %s - address or unit-id \"",
        "                     \"enumeration looks like this\", code, c$id$orig_h),",
        "            $identifier=cat(c$id$orig_h),",
        "            $suppress_for=5min]);",
        "    }",
        "",
        "event dnp3_application_request_header(c: connection, is_orig: bool,",
        "                                      application_control: count, fc: count)",
        "    {",
        "    if ( ! is_orig ) return;",
        "    # 3 select, 4 operate, 5/6 direct operate",
        "    if ( fc in set(3, 4, 5, 6) && c$id$orig_h !in dnp3_masters )",
        "        NOTICE([$note=Unapproved_DNP3_Control,",
        "                $conn=c,",
        "                $msg=fmt(\"DNP3 control function %d from %s\", fc, c$id$orig_h),",
        "                $identifier=cat(c$id$orig_h, fc)]);",
        "",
        "    # 13 cold restart, 14 warm restart, 21 disable unsolicited",
        "    if ( fc in set(13, 14, 21) )",
        "        NOTICE([$note=DNP3_Outstation_Restart,",
        "                $conn=c,",
        "                $msg=fmt(\"DNP3 function %d removes the operator's view \"",
        "                         \"of %s\", fc, c$id$resp_h),",
        "                $identifier=cat(c$id$resp_h, fc)]);",
        "    }",
        "",
        "# Any host that has never been seen talking to an OT port before.",
        "event connection_established(c: connection)",
        "    {",
        "    if ( c$id$resp_p !in ot_ports ) return;",
        "    if ( [c$id$orig_h, c$id$resp_p] in seen_ot_pairs ) return;",
        "    add seen_ot_pairs[c$id$orig_h, c$id$resp_p];",
        "    NOTICE([$note=New_Host_On_OT_Port,",
        "            $conn=c,",
        "            $msg=fmt(\"%s spoke to %s on %s for the first time today\",",
        "                     c$id$orig_h, c$id$resp_h, c$id$resp_p),",
        "            $identifier=cat(c$id$orig_h, c$id$resp_p)]);",
        "    }",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sigma (host and log side)
# ---------------------------------------------------------------------------
SIGMA_RULES: List[Dict[str, Any]] = [
    {
        "key": "jumphost-new-account",
        "title": "Local account created on an OT jump host",
        "level": "high",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {"keywords": ["new user: name=", "add '*' to group 'sudo'",
                                   "add '*' to group 'wheel'"]},
        "why": "Accounts on a jump host are provisioned centrally. One created "
               "locally is either an emergency or an intruder establishing "
               "persistence.",
    },
    {
        "key": "jumphost-history-wipe",
        "title": "Shell history or log files cleared on an OT host",
        "level": "high",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {"keywords": ["> ~/.bash_history", "rm -f /var/log/",
                                   "shred", "history -c", "truncate -s 0 /var/log"]},
        "why": "Clearing history has no operational purpose and usually follows "
               "the activity you actually want to find.",
    },
    {
        "key": "ot-tooling",
        "title": "Scanning or protocol tooling executed inside the OT zone",
        "level": "high",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {"keywords": ["nmap", "masscan", "plcscan", "modbus-cli",
                                   "pymodbus", "snap7", "hydra", "responder"]},
        "why": "Engineering work uses vendor software. A port scanner or a raw "
               "protocol client on a plant host is worth a phone call.",
    },
    {
        "key": "ot-service-stopped",
        "title": "Monitoring or historian service stopped on an OT host",
        "level": "high",
        "logsource": {"product": "linux", "service": "systemd"},
        "detection": {"keywords": ["Stopped Historian", "systemctl stop",
                                   "systemctl disable", "systemctl mask"]},
        "why": "Stopping collection is the host-side equivalent of a STOPDT: it "
               "removes the record before the action.",
    },
    {
        "key": "ssh-brute-then-success",
        "title": "Successful SSH login after repeated failures from one address",
        "level": "medium",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {"keywords": ["Accepted password for"],
                      "timeframe": "10m",
                      "condition_note": "correlate with 5+ 'Failed password' "
                                        "events from the same source"},
        "why": "The pattern that precedes most of the OT incidents in this "
               "repository's scenarios.",
    },
]


def sigma(p: Profile) -> str:
    docs = []
    when = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    for i, r in enumerate(SIGMA_RULES, start=1):
        keywords = "\n".join(f"      - '{k}'" for k in r["detection"]["keywords"])
        extra = ""
        if "timeframe" in r["detection"]:
            extra = (f"  timeframe: {r['detection']['timeframe']}\n"
                     f"# note: {r['detection']['condition_note']}\n")
        docs.append(f"""# {r['why']}
title: {r['title']}
id: ics-toolkit-{r['key']}
status: experimental
description: >
  Generated by ics-toolkit on {when} from an observed OT incident pattern.
  Review the keyword list against your own estate before enabling.
logsource:
  product: {r['logsource']['product']}
  service: {r['logsource']['service']}
detection:
  keywords:
{keywords}
  condition: keywords
{extra}falsepositives:
  - planned maintenance performed by a named engineer during a change window
level: {r['level']}
tags:
  - attack.persistence
  - attack.defense_evasion
""")
    return ("# Sigma rules generated by ics-toolkit\n"
            "# One YAML document per rule; split them if your pipeline needs "
            "separate files.\n\n" + "\n---\n\n".join(docs))


def readme(p: Profile) -> str:
    v = _vars(p)
    lines = [
        "# Detection rules generated from a capture",
        "",
        "These were derived from what one capture actually shows. They are a "
        "starting point for an engineer who knows the estate, not a finished "
        "rule set.",
        "",
        "## Before you deploy anything",
        "",
        "1. **Check the host groups.** They were inferred from a single capture. "
        "A device that happened to be quiet is missing; a host that misbehaved "
        "during the capture was deliberately left out of the allow-lists.",
        "2. **Check the thresholds.** The enumeration rules are tuned to a "
        "guess. Measure your own normal poll rate first - the toolkit's "
        "overview report gives it to you.",
        "3. **Test against a known-good capture.** `suricata -r baseline.pcap "
        "-S ot-rules.rules` should be silent. If it is not, fix the rule, not "
        "the baseline.",
        "4. **Decide alert versus drop.** In OT, dropping a control packet can "
        "be as damaging as the attack. Start in alert mode.",
        "",
        "## Suggested variables",
        "",
        "```yaml",
        "vars:",
        "  address-groups:",
    ]
    for name, value in v.items():
        lines.append(f"    {name.lstrip('$')}: \"{value}\"")
    lines += [
        "```",
        "",
        "## Files",
        "",
        "| File | Where it goes |",
        "|---|---|",
        "| `ot-rules.rules` | Suricata rules directory, then reload |",
        "| `ot-detections.zeek` | `@load` from `local.zeek`, or `zeek -r cap.pcap ot-detections.zeek` |",
        "| `sigma/*.yml` | your SIEM's Sigma pipeline |",
        "",
        "## What was observed in the source capture",
        "",
    ]
    if p.observed:
        for key in sorted(p.observed):
            lines.append(f"- `{key}`")
    else:
        lines.append("- nothing of note")
    lines += [
        "",
        "Rules for operations that were **not** observed are still included: "
        "the point of a detection is to catch what has not happened yet.",
        "",
    ]
    if p.suspects:
        lines += ["## Hosts excluded from the allow-lists", "",
                  "These behaved like a tool rather than a device during the "
                  "capture, so they were deliberately left out:", ""]
        lines += [f"- `{h}`" for h in sorted(p.suspects)]
        lines.append("")
    return "\n".join(lines)
