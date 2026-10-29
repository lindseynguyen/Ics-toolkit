"""Cleartext credential and secret harvesting from a capture.

Covers the protocols that keep showing up in OT-DMZ captures: FTP, Telnet,
HTTP Basic / form posts, SNMP communities, SMTP/POP/IMAP AUTH, LDAP simple
bind, MySQL and MS SQL Server (TDS LOGIN7, including the nibble-swap+XOR
password obfuscation that is not encryption).
"""
from __future__ import annotations

import base64
import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import pcapio

# ports this module knows how to mine; used to pre-filter very large captures
CLEARTEXT_HINT_PORTS = (21, 23, 25, 80, 110, 143, 161, 162, 389, 587,
                        1433, 2121, 3306, 8000, 8080, 8081)


@dataclass
class Finding:
    frame: int
    ts: float
    src: str
    dst: str
    proto: str
    kind: str
    value: str
    context: str = ""


def tds_decode_password(blob: bytes) -> str:
    """TDS LOGIN7 passwords are obfuscated: XOR 0xA5 then swap nibbles."""
    out = bytearray()
    for b in blob:
        b ^= 0xA5
        out.append(((b & 0x0F) << 4) | (b >> 4))
    try:
        return out.decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:
        return out.hex()


def _tds_login7(data: bytes) -> Dict[str, str]:
    """Pull the useful offset/length fields out of a LOGIN7 packet."""
    res: Dict[str, str] = {}
    if len(data) < 8 or data[0] != 0x10:
        return res
    body = data[8:]
    if len(body) < 94:
        return res
    fields = [("hostname", 36), ("username", 40), ("password", 44),
              ("appname", 48), ("servername", 52), ("library", 60),
              ("database", 68)]
    for name, off in fields:
        if off + 4 > len(body):
            continue
        ofs, ln = struct.unpack_from("<HH", body, off)
        raw = body[ofs:ofs + ln * 2]
        if not raw:
            continue
        if name == "password":
            res[name] = tds_decode_password(raw)
        else:
            res[name] = raw.decode("utf-16-le", "replace")
    return res


_HTTP_BASIC = re.compile(rb"[Aa]uthorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
_HTTP_FORM = re.compile(rb"(?:user(?:name)?|login|pass(?:word|wd)?|pwd)=[^&\s\"]{1,64}", re.I)
_FTP = re.compile(rb"^(USER|PASS|ACCT)\s+(.+?)\r?$", re.I | re.M)
_MAIL = re.compile(rb"^(AUTH\s+\w+|USER|PASS|LOGIN)\s*(.*)$", re.I | re.M)
_SQL_TEXT = re.compile(rb"(SELECT|INSERT|UPDATE|DELETE|EXEC)\s+[\x20-\x7e]{5,160}", re.I)


def harvest(packets: List[pcapio.Packet]) -> List[Finding]:
    out: List[Finding] = []

    def add(p, proto, kind, value, ctx=""):
        out.append(Finding(frame=p.index, ts=p.ts, src=p.src or "", dst=p.dst or "",
                           proto=proto, kind=kind, value=value, context=ctx))

    for p in packets:
        d = p.payload
        if not d:
            continue
        # --- FTP / Telnet-ish line protocols
        if p.dport in (21, 2121) or p.sport in (21, 2121):
            for m in _FTP.finditer(d):
                add(p, "ftp", m.group(1).decode().upper(),
                    m.group(2).decode("latin-1").strip())
        if p.dport in (23,) or p.sport in (23,):
            txt = bytes(b for b in d if 32 <= b < 127)
            if txt:
                add(p, "telnet", "data", txt.decode("latin-1")[:120])
        # --- HTTP
        if p.dport in (80, 8080, 8000, 8081) or p.sport in (80, 8080, 8000, 8081):
            for m in _HTTP_BASIC.finditer(d):
                try:
                    dec = base64.b64decode(m.group(1)).decode("latin-1")
                except Exception:
                    dec = m.group(1).decode()
                add(p, "http", "basic-auth", dec)
            for m in _HTTP_FORM.finditer(d):
                add(p, "http", "form-field", m.group(0).decode("latin-1"))
        # --- mail
        if p.dport in (25, 110, 143, 587) or p.sport in (25, 110, 143, 587):
            for m in _MAIL.finditer(d):
                val = m.group(2).decode("latin-1").strip()
                if val and re.fullmatch(r"[A-Za-z0-9+/=]{4,}", val):
                    try:
                        val += "  (b64: " + base64.b64decode(val).decode("latin-1") + ")"
                    except Exception:
                        pass
                add(p, "mail", m.group(1).decode().upper(), val)
        # --- SNMP community string
        if p.dport in (161, 162) or p.sport in (161, 162):
            comm = _snmp_community(d)
            if comm:
                add(p, "snmp", "community", comm)
        # --- LDAP simple bind
        if p.dport == 389 or p.sport == 389:
            cred = _ldap_bind(d)
            if cred:
                add(p, "ldap", "simple-bind", cred)
        # --- MySQL
        if p.dport == 3306 or p.sport == 3306:
            txt = bytes(b for b in d[:120] if 32 <= b < 127).decode("latin-1")
            if txt and ("mysql_native_password" in txt or "caching_sha2" in txt):
                add(p, "mysql", "handshake", txt[:80])
        # --- MS SQL Server / TDS
        if p.dport == 1433 or p.sport == 1433:
            if d[:1] == b"\x10":
                info = _tds_login7(d)
                if info:
                    desc = " ".join(f"{k}={v!r}" for k, v in info.items())
                    add(p, "tds", "login7", desc)
            if d[:1] == b"\x01":
                for m in _SQL_TEXT.finditer(d.replace(b"\x00", b"")):
                    add(p, "tds", "query", m.group(0).decode("latin-1")[:160])
    return out


def _snmp_community(d: bytes) -> Optional[str]:
    # SEQUENCE { version INTEGER, community OCTET STRING, ... }
    try:
        if d[0] != 0x30:
            return None
        i = 2
        if d[1] & 0x80:
            i = 2 + (d[1] & 0x7F)
        if d[i] != 0x02:
            return None
        i += 2 + d[i + 1]
        if d[i] != 0x04:
            return None
        ln = d[i + 1]
        return d[i + 2:i + 2 + ln].decode("latin-1")
    except Exception:
        return None


def _ldap_bind(d: bytes) -> Optional[str]:
    try:
        idx = d.find(b"\x80")           # simple authentication choice
        if idx < 0 or idx + 2 > len(d):
            return None
        ln = d[idx + 1]
        pw = d[idx + 2:idx + 2 + ln]
        dn_match = re.search(rb"(?:CN|cn|uid|DC)=[\x20-\x7e]{2,120}", d)
        dn = dn_match.group(0).decode("latin-1") if dn_match else "?"
        if pw and all(32 <= b < 127 for b in pw):
            return f"dn={dn} password={pw.decode('latin-1')!r}"
    except Exception:
        return None
    return None
