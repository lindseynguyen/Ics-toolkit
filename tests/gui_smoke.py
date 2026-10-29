#!/usr/bin/env python3
"""Start the GUI server on a free port, exercise its API, and shut it down.

    python3 tests/gui_smoke.py fixtures/
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def call(base: str, path: str, payload=None, method: str = "GET"):
    url = base + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method if data is None else "POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def main() -> int:
    fx = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    ws = tempfile.mkdtemp(prefix="icsgui-")
    for name in ("bacnet_bms.pcap", "rig.gb", "SETPT16.COM"):
        src = os.path.join(fx, name)
        if os.path.isfile(src):
            shutil.copy2(src, ws)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "gui", "serve.py"),
         "--port", str(port), "--workspace", ws, "--no-browser"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    failures = []
    try:
        for _ in range(50):                       # wait for the listener
            try:
                call(base, "/api/files")
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("server did not start")
            return 1

        files = call(base, "/api/files")
        assert files["files"], "workspace listing empty"
        print(f"files: {[f['name'] for f in files['files']]}")

        tools = call(base, "/api/tools")
        assert len(tools["tools"]) >= 10, "tool catalog too small"

        art = call(base, "/api/identify", {"name": "bacnet_bms.pcap"})
        assert art["kind"] == "pcap" and art["steps"], "identification failed"
        print(f"identified: {art['summary']} / {len(art['steps'])} steps")

        run = call(base, "/api/run", {"tool": "bacnet-triage.py",
                                      "files": ["bacnet_bms.pcap"],
                                      "args": ["--dcc"]})
        assert run["returncode"] == 0 and "password-failure" in run["output"], \
            "bacnet run produced unexpected output"
        assert run["notes"], "no plain-language notes returned"
        print(f"run ok, {len(run['notes'])} explanatory notes")

        rom = call(base, "/api/identify", {"name": "rig.gb"})
        assert rom["kind"] == "gbrom", "ROM not identified"

        # ---- negative cases: the allow-lists must hold
        for bad in (
            {"tool": "/bin/sh", "files": ["rig.gb"]},
            {"tool": "bacnet-triage.py", "files": ["../../etc/passwd"]},
            {"tool": "bacnet-triage.py", "files": ["bacnet_bms.pcap"],
             "flags": {"--evil": "1"}},
        ):
            try:
                call(base, "/api/run", bad)
                failures.append(f"request should have been refused: {bad}")
            except urllib.error.HTTPError:
                pass
        print("allow-lists refused every malformed request")
    except AssertionError as exc:
        failures.append(str(exc))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(ws, ignore_errors=True)

    if failures:
        for f in failures:
            print("FAIL:", f)
        return 1
    print("gui smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
