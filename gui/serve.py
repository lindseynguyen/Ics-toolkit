#!/usr/bin/env python3
"""Local web interface for the toolkit - no dependencies, no internet.

    python3 gui/serve.py

Starts a small HTTP server on 127.0.0.1 and opens a browser. Drop an artefact
on the page, and the interface identifies it, proposes an ordered list of
analysis steps in plain language, runs the real CLI tools for you, and shows
the exact command it ran so you can learn to run it yourself.

Options:
    --port N            listen port (default 8765)
    --host ADDR         bind address (default 127.0.0.1 - keep it local)
    --workspace DIR     where uploaded artefacts and outputs live
                        (default ./workspace)
    --no-browser        do not open a browser automatically
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "gui", "static")
TOOLS = os.path.join(ROOT, "tools")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from icsctf import detect, explain  # noqa: E402

MAX_UPLOAD = 512 * 1024 * 1024          # 512 MB
RUN_TIMEOUT = 300                       # seconds per tool invocation

# Only these scripts may be executed, and only with flags listed here.
TOOL_CATALOG: Dict[str, Dict[str, Any]] = {
    "pcap-overview.py": {
        "title": "Capture overview",
        "blurb": "Hosts, conversations, which industrial protocol is present, "
                 "scan heuristics. The first thing to run on any capture.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--top": "int"},
        "views": [],
    },
    "bacnet-triage.py": {
        "title": "BACnet/IP triage",
        "blurb": "Building-management traffic: device inventory, password "
                 "attempts, property writes.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--port": "int", "--src": "str", "--dst": "str",
                  "--service": "str", "--limit": "int"},
        "views": [
            ("", "Full report"),
            ("--devices", "Device inventory - find the host that does not belong"),
            ("--dcc", "Password attempts, accepted vs refused"),
            ("--writes", "Everything that was written to a device"),
            ("--timeline", "Every message in order"),
        ],
    },
    "s7-triage.py": {
        "title": "Siemens S7comm triage",
        "blurb": "PLC traffic: fingerprinting, logic transfers, CPU state "
                 "changes, tag writes.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--port": "int", "--src": "str", "--dst": "str", "--limit": "int"},
        "views": [
            ("", "Full report"),
            ("--szl", "SZL diagnostic reads (fingerprinting)"),
            ("--blocks", "Block upload / download (logic change)"),
            ("--control", "CPU STOP and restart attempts"),
            ("--writes", "Tag reads and writes with decoded values"),
            ("--timeline", "Every message in order"),
        ],
    },
    "modbus-triage.py": {
        "title": "Modbus/TCP triage",
        "blurb": "Register and coil activity, writes, exception trails, "
                 "float decoding.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--port": "int", "--unit": "int", "--src": "str", "--limit": "int"},
        "views": [
            ("", "Full report"),
            ("--map", "Register and coil map"),
            ("--writes", "Write operations only"),
            ("--floats", "Register pairs decoded as floating point"),
            ("--strings", "ASCII hidden in registers"),
            ("--timeline", "Request/response pairs in order"),
        ],
    },
    "iec104-triage.py": {
        "title": "IEC 60870-5-104 triage",
        "blurb": "Telecontrol traffic: session state, command timeline, "
                 "select-before-operate audit.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--port": "int", "--limit": "int"},
        "views": [
            ("", "Full report"),
            ("--commands", "Control commands and their confirmations"),
            ("--sbo", "Select-before-operate audit"),
            ("--ioa", "Point map (information objects)"),
            ("--timeline", "Every APDU in order"),
        ],
    },
    "dnp3-triage.py": {
        "title": "DNP3 triage",
        "blurb": "Outstation traffic: function codes, status flags, control "
                 "operations.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--port": "int", "--limit": "int"},
        "views": [("", "Full report"),
                  ("--controls", "Control operations only"),
                  ("--timeline", "Every frame in order")],
    },
    "cleartext-creds.py": {
        "title": "Cleartext credentials",
        "blurb": "Credentials and secrets the protocols send in the clear, "
                 "including MS SQL Server login fields.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--proto": "str"},
        "views": [("", "All findings")],
    },
    "stream-carve.py": {
        "title": "TCP streams",
        "blurb": "Conversations you can read end to end, and file carving.",
        "accepts": ["pcap"],
        "flags": {"--max-packets": "int", "--since": "str", "--until": "str", "--stream": "int", "--max": "int", "--out": "path",
                  "--carve": "path"},
        "views": [("", "Stream index"), ("--ascii", "Readable text of a stream")],
    },
    "pcap-merge.py": {
        "title": "Merge captures",
        "blurb": "Stitch a fragmented capture set into one time-ordered file.",
        "accepts": ["pcap"],
        "flags": {"--keep-order": "bool"},
        "views": [],
        "multi": True,
        "output_first": True,
    },
    "gb-cart-inspect.py": {
        "title": "Game Boy cartridge image",
        "blurb": "Firmware-style artefact: header, mapper, checksums, bank "
                 "profile, embedded archives.",
        "accepts": ["gbrom", "archive"],
        "flags": {"--strings": "int", "--bank": "int", "--min-len": "int",
                  "--dump": "path", "--extract": "path"},
        "views": [("", "Header and bank profile"),
                  ("--blobs", "Embedded container scan"),
                  ("--vectors", "Interrupt vectors")],
    },
    "dos-bin-inspect.py": {
        "title": "Legacy DOS binary",
        "blurb": "16-bit HMI or utility: layout, strings, interrupts, "
                 "setpoint constants.",
        "accepts": ["dosbin", "archive"],
        "flags": {"--min-str": "int", "--disasm": "str", "--length": "int",
                  "--hexdump": "str"},
        "views": [("", "Full static report"),
                  ("--screens", "Operator-visible text"),
                  ("--floats", "Setpoint-like constants"),
                  ("--ints", "Interrupt call sites")],
    },
    "blob-carve.py": {
        "title": "Generic blob analysis",
        "blurb": "Any binary: container scan, decompression, entropy profile, "
                 "XOR recovery.",
        "accepts": ["archive", "gbrom", "dosbin", "pcap"],
        "flags": {"--window": "int", "--xor-key": "str", "--slice": "str",
                  "--length": "int", "--strings": "int", "--extract": "path",
                  "--out": "path"},
        "views": [("", "Container scan"),
                  ("--entropy", "Entropy profile"),
                  ("--xor", "Single-byte XOR sweep")],
    },
    "timeline.py": {
        "title": "Incident timeline (all artefacts)",
        "blurb": "Merges captures and logs into one UTC timeline: who did what, "
                 "to which device, in what order.",
        "accepts": ["pcap", "text", "archive"],
        "flags": {"--min-severity": "str", "--log-year": "int", "--gaps": "int",
                  "--csv": "path", "--md": "path", "--json": "path",
                  "--max-packets": "int", "--since": "str", "--until": "str"},
        "views": [("", "Everything"),
                  ("--detail", "With the raw line behind each event"),
                  ("--keep-unmatched", "Keep log lines that match no rule")],
        "multi": True,
    },
    "make-rules.py": {
        "title": "Generate detection rules",
        "blurb": "Turns what a capture shows into Suricata, Zeek and Sigma rules, "
                 "with the host allow-lists filled in.",
        "accepts": ["pcap"],
        "flags": {"--out": "path", "--format": "str", "--max-packets": "int",
                  "--since": "str", "--until": "str"},
        "views": [("", "Summary and preview"),
                  ("--only-observed", "Only rules for what was seen here")],
        "multi": True,
    },
    "file-inspect.py": {
        "title": "What is this file?",
        "blurb": "Type, hashes, entropy, embedded containers and the strings "
                 "worth a look - the first command for anything unfamiliar.",
        "accepts": ["pcap", "gbrom", "dosbin", "archive", "text"],
        "flags": {"--min-len": "int"},
        "views": [("", "Full report"),
                  ("--summary", "One row per file"),
                  ("--strings", "Also list every string")],
        "multi": True,
    },
    "strings-plus.py": {
        "title": "Strings, classified",
        "blurb": "Text inside a binary with offsets and UTF-16 support, grouped "
                 "into addresses, paths, commands, OT vocabulary.",
        "accepts": ["gbrom", "dosbin", "archive", "pcap"],
        "flags": {"--min-len": "int", "--grep": "str", "--only": "str",
                  "--at": "str", "--length": "str", "--limit": "int"},
        "views": [("", "All strings"), ("--ascii-only", "ASCII only (faster)")],
    },
    "hexview.py": {
        "title": "Hex view and byte search",
        "blurb": "Look at the bytes at any offset, or find where a value lives.",
        "accepts": ["gbrom", "dosbin", "archive", "pcap", "text"],
        "flags": {"--at": "str", "--length": "str", "--find": "str",
                  "--find-hex": "str", "--context": "str", "--width": "int"},
        "views": [("", "Hex dump")],
    },
    "bin-diff.py": {
        "title": "Compare two files",
        "blurb": "What changed between two builds: a relabelled message, a "
                 "changed setpoint, a rebuilt checksum.",
        "accepts": ["gbrom", "dosbin", "archive", "text"],
        "flags": {"--context": "int", "--merge-gap": "int", "--limit": "int"},
        "views": [("", "Changed regions"), ("--hexdump", "With the bytes")],
        "multi": True,
        "needs_two": True,
    },
    "decode.py": {
        "title": "Decode an encoded blob",
        "blurb": "Tries base64, hex, gzip, zlib, URL, ROT13, UTF-16 and XOR, and "
                 "shows what comes out.",
        "accepts": ["archive", "text", "gbrom", "dosbin"],
        "flags": {"--text": "str", "--at": "str", "--length": "str",
                  "--out": "path"},
        "views": [("", "Best candidates"), ("--chain", "Follow nested encodings"),
                  ("--no-xor", "Skip the XOR sweep")],
    },
    "triage-plan.py": {
        "title": "Suggested plan",
        "blurb": "Identify an artefact and print the recommended order of "
                 "analysis.",
        "accepts": ["pcap", "gbrom", "dosbin", "archive", "text"],
        "flags": {},
        "views": [("", "Plan")],
    },
}

BOOL_FLAGS = {"--all-ports", "--quiet-size", "--detail", "--keep-unmatched",
              "--only-observed", "--summary", "--ascii-only", "--chain",
              "--no-xor", "--hexdump", "--dcc", "--writes", "--devices", "--timeline", "--szl",
              "--blocks", "--control", "--map", "--floats", "--strings",
              "--commands", "--sbo", "--ioa", "--controls", "--ascii",
              "--blobs", "--vectors", "--screens", "--ints", "--entropy",
              "--xor", "--keep-order"}


class Workspace:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(self.path, exist_ok=True)
        self.out = os.path.join(self.path, "extracted")
        os.makedirs(self.out, exist_ok=True)

    def safe(self, name: str) -> str:
        """Resolve a user-supplied name to a path inside the workspace."""
        base = os.path.basename(name.replace("\\", "/")).strip()
        if not base or base.startswith("."):
            raise ValueError("invalid file name")
        full = os.path.abspath(os.path.join(self.path, base))
        if os.path.dirname(full) != self.path:
            raise ValueError("path escapes the workspace")
        return full

    def listing(self) -> List[Dict[str, Any]]:
        rows = []
        for name in sorted(os.listdir(self.path)):
            full = os.path.join(self.path, name)
            if not os.path.isfile(full):
                continue
            rows.append({"name": name, "size": os.path.getsize(full),
                         "mtime": os.path.getmtime(full)})
        return rows


WS: Optional[Workspace] = None


def build_args(tool: str, files: List[str], flags: Dict[str, Any]) -> List[str]:
    """Validate a run request and return the argv for the subprocess."""
    spec = TOOL_CATALOG.get(tool)
    if spec is None:
        raise ValueError("unknown tool")
    assert WS is not None
    argv = [sys.executable, os.path.join(TOOLS, tool)]

    paths = [WS.safe(f) for f in files]
    for p in paths:
        if not os.path.isfile(p):
            raise ValueError(f"no such file: {os.path.basename(p)}")
    if not paths:
        if tool == "decode.py" and flags.get("--text"):
            argv.append("--text")
            argv.append(str(flags.pop("--text")))
            return argv
        raise ValueError("no input file selected")
    if spec.get("needs_two") and len(paths) != 2:
        raise ValueError("select exactly two files to compare "
                         "(Ctrl/Cmd-click in the file list)")
    if not spec.get("multi") and len(paths) > 1 and tool not in (
            "pcap-overview.py", "triage-plan.py"):
        paths = paths[:1]

    if spec.get("output_first"):
        out_name = str(flags.pop("__out__", "merged.pcap"))
        argv.append(WS.safe(out_name))

    argv += paths

    allowed = dict(spec.get("flags", {}))
    for name, _label in spec.get("views", []):
        if name:
            allowed[name] = "bool"
    for key, value in flags.items():
        if key.startswith("__"):
            continue
        if key not in allowed and key not in BOOL_FLAGS:
            raise ValueError(f"flag not permitted: {key}")
        kind = allowed.get(key, "bool")
        if kind == "bool" or key in BOOL_FLAGS:
            if value:
                argv.append(key)
            continue
        if value in (None, ""):
            continue
        sval = str(value)
        if kind == "int":
            int(sval, 0)                       # raises on junk
            argv += [key, sval]
        elif kind == "path":
            argv += [key, WS.safe(sval) if not sval.startswith("extracted")
                     else os.path.join(WS.path, sval)]
        else:
            if len(sval) > 128 or any(c in sval for c in ";|&`$<>\n"):
                raise ValueError(f"invalid value for {key}")
            argv += [key, sval]
    return argv


def run_tool(argv: List[str]) -> Tuple[str, int]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=RUN_TIMEOUT, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return (f"The analysis exceeded {RUN_TIMEOUT} seconds and was stopped. "
                "Try a narrower view, or a smaller capture."), 1
    out = proc.stdout
    if proc.stderr.strip():
        out += "\n[stderr]\n" + proc.stderr
    return out, proc.returncode


def pretty_command(argv: List[str]) -> str:
    parts = ["python3"]
    for a in argv[1:]:
        if a.startswith(ROOT + os.sep):
            a = os.path.relpath(a, ROOT)
        parts.append(f'"{a}"' if " " in a else a)
    return " ".join(parts)


def artefact_payload(name: str) -> Dict[str, Any]:
    assert WS is not None
    path = WS.safe(name)
    art = detect.identify(path)
    return {
        "name": name,
        "size": art.size,
        "kind": art.kind,
        "summary": art.summary,
        "details": art.details,
        "protocols": art.protocols,
        "warnings": art.warnings,
        "steps": [{"label": s.label, "tool": s.tool, "args": s.args,
                   "why": s.why, "primary": s.primary} for s in art.steps],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "icsctf-gui"

    # ---------------------------------------------------------------- helpers
    def log_message(self, fmt: str, *args) -> None:       # quieter console
        if "/api/" in (args[0] if args else ""):
            sys.stderr.write("  %s\n" % (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str,
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _error(self, msg: str, code: int = 400) -> None:
        self._json({"error": msg}, code)

    def _local_only(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]", "::1") or \
            self.client_address[0] in ("127.0.0.1", "::1")

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            raise ValueError("upload too large")
        remaining = length
        chunks = []
        while remaining > 0:
            chunk = self.rfile.read(min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _json_body(self) -> Dict[str, Any]:
        raw = self._body()
        return json.loads(raw.decode("utf-8")) if raw else {}

    # -------------------------------------------------------------------- GET
    def do_GET(self) -> None:          # noqa: N802
        if not self._local_only():
            return self._error("this interface only serves localhost", 403)
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route in ("/", "/index.html"):
            return self._static("index.html")
        if route.startswith("/static/"):
            return self._static(route[len("/static/"):])
        if route == "/api/files":
            assert WS is not None
            return self._json({"workspace": WS.path, "files": WS.listing()})
        if route == "/api/tools":
            return self._json({"tools": [
                {"tool": k, **{kk: vv for kk, vv in v.items()}}
                for k, v in TOOL_CATALOG.items()]})
        if route == "/api/glossary":
            return self._json({"glossary": explain.GLOSSARY})
        if route == "/api/download":
            q = urllib.parse.parse_qs(parsed.query)
            name = (q.get("name") or [""])[0]
            try:
                assert WS is not None
                path = WS.safe(name)
                with open(path, "rb") as fh:
                    data = fh.read()
            except Exception as exc:
                return self._error(str(exc), 404)
            return self._send(200, data, "application/octet-stream",
                              {"Content-Disposition":
                               f'attachment; filename="{os.path.basename(path)}"'})
        return self._error("not found", 404)

    def _static(self, rel: str) -> None:
        rel = rel.split("?")[0].lstrip("/")
        full = os.path.abspath(os.path.join(STATIC, rel))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._error("not found", 404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as fh:
            self._send(200, fh.read(), ctype)

    # ------------------------------------------------------------------- POST
    def do_PUT(self) -> None:          # noqa: N802
        if not self._local_only():
            return self._error("this interface only serves localhost", 403)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/upload":
            return self._error("not found", 404)
        q = urllib.parse.parse_qs(parsed.query)
        name = (q.get("name") or [""])[0]
        try:
            assert WS is not None
            path = WS.safe(urllib.parse.unquote(name))
            data = self._body()
        except Exception as exc:
            return self._error(str(exc))
        if not data:
            return self._error("empty upload")
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            return self._json({"ok": True, "artefact": artefact_payload(
                os.path.basename(path))})
        except Exception as exc:
            return self._json({"ok": True, "artefact": None, "warning": str(exc)})

    def do_POST(self) -> None:         # noqa: N802
        if not self._local_only():
            return self._error("this interface only serves localhost", 403)
        route = urllib.parse.urlparse(self.path).path
        try:
            payload = self._json_body()
        except Exception as exc:
            return self._error(f"bad request body: {exc}")

        if route == "/api/identify":
            try:
                return self._json(artefact_payload(payload.get("name", "")))
            except FileNotFoundError:
                return self._error("that file is not in the workspace folder "
                                   "any more - add it again", 404)
            except Exception as exc:
                return self._error(str(exc))

        if route == "/api/add-path":
            src = str(payload.get("path", "")).strip()
            if not src or not os.path.isfile(src):
                return self._error("no such file on this machine")
            assert WS is not None
            dst = WS.safe(os.path.basename(src))
            if os.path.abspath(src) != dst:
                shutil.copy2(src, dst)
            try:
                return self._json({"ok": True,
                                   "artefact": artefact_payload(os.path.basename(dst))})
            except Exception as exc:
                return self._error(str(exc))

        if route == "/api/plan-group":
            assert WS is not None
            names = [str(n) for n in payload.get("names", [])]
            try:
                paths = [WS.safe(n) for n in names]
                steps = detect.plan_group(paths)
            except Exception as exc:
                return self._error(str(exc))
            return self._json({"steps": [
                {"label": s.label, "tool": s.tool, "args": s.args,
                 "why": s.why, "primary": s.primary} for s in steps]})

        if route == "/api/run":
            tool = str(payload.get("tool", ""))
            files = [str(f) for f in (payload.get("files") or [])]
            flags = payload.get("flags") or {}
            args = payload.get("args") or []
            for a in args:                       # view flags come as a list
                flags[str(a)] = True
            try:
                argv = build_args(tool, files, dict(flags))
            except Exception as exc:
                return self._error(str(exc))
            out, rc = run_tool(argv)
            notes = explain.interpret(tool, [a for a in argv if a.startswith("--")], out)
            return self._json({
                "command": pretty_command(argv),
                "output": out,
                "returncode": rc,
                "notes": notes,
                "glossary": explain.glossary_terms(out + " " + " ".join(notes)),
                "produced": sorted(os.listdir(WS.out)) if WS else [],
            })

        if route == "/api/delete":
            try:
                assert WS is not None
                os.remove(WS.safe(str(payload.get("name", ""))))
            except Exception as exc:
                return self._error(str(exc))
            return self._json({"ok": True})

        return self._error("not found", 404)


def main() -> None:
    global WS
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--workspace", default=os.path.join(ROOT, "workspace"))
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    WS = Workspace(args.workspace)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print("ics-toolkit GUI")
    print(f"  interface : {url}")
    print(f"  workspace : {WS.path}")
    print("  artefacts you drop on the page are stored there; nothing leaves "
          "this machine.")
    print("  press Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
