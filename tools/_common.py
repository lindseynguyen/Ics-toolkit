"""Shared CLI plumbing: capture-size controls used by every capture tool.

A real plant capture is often hundreds of megabytes. These helpers make every
tool read it as a stream and keep only the packets it will actually decode,
and they give the user one consistent set of options for narrowing a capture.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
from typing import Iterable, List, Optional

import _bootstrap  # noqa: F401
from icsctf import pcapio

BIG_CAPTURE = 64 * 1024 * 1024          # bytes: warn above this


def add_capture_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("capture size controls")
    g.add_argument("--max-packets", type=int, default=0, metavar="N",
                   help="stop after N packets that match the filters "
                        "(use on a very large capture to get a first look)")
    g.add_argument("--since", metavar="TIME",
                   help="ignore packets before this time "
                        "(2024-03-14T10:47:28Z, 10:47:28, or an epoch value)")
    g.add_argument("--until", metavar="TIME", help="ignore packets after this time")
    g.add_argument("--all-ports", action="store_true",
                   help="do not pre-filter by this protocol's port "
                        "(slower; use when the protocol runs on an odd port)")
    g.add_argument("--quiet-size", action="store_true",
                   help="suppress the note about how much of the capture was read")


def parse_time(value: Optional[str], reference: Optional[float] = None) -> Optional[float]:
    """Accept an ISO timestamp, a bare clock time, or an epoch value."""
    if not value:
        return None
    v = value.strip()
    if v.replace(".", "", 1).isdigit() and len(v) > 8:
        try:
            return float(v)                      # epoch seconds
        except ValueError:
            pass
    iso = v.replace("Z", "+00:00")
    try:
        d = _dt.datetime.fromisoformat(iso)
        if d.tzinfo is None:
            d = d.replace(tzinfo=_dt.timezone.utc)
        return d.timestamp()
    except ValueError:
        pass
    for fmt in ("%H:%M:%S", "%H:%M:%S.%f", "%H:%M"):
        try:
            t = _dt.datetime.strptime(v, fmt).time()
        except ValueError:
            continue
        base = _dt.datetime.fromtimestamp(reference or 0, _dt.timezone.utc).date() \
            if reference else _dt.date(1970, 1, 1)
        return _dt.datetime.combine(base, t, tzinfo=_dt.timezone.utc).timestamp()
    raise SystemExit(f"could not read the time value {value!r}")


def load_capture(args: argparse.Namespace, paths: Iterable[str],
                 ports: Optional[Iterable[int]] = None,
                 keep_raw: bool = False,
                 protos: Optional[Iterable[str]] = None) -> List[pcapio.Packet]:
    """Read captures with the user's size controls applied.

    `ports` is the set this tool decodes; it is dropped when --all-ports is
    given. Nothing outside the filters is ever built, so memory stays bounded
    by what the tool reports on, not by the file size.
    """
    paths = list(paths)
    reference = None
    big = [p for p in paths if os.path.getsize(p) > BIG_CAPTURE]
    if (args.since or args.until) and paths:
        try:
            for ts, _lt, _f in pcapio.iter_frames(paths[0]):
                reference = ts
                break
        except Exception:
            reference = None
    since = parse_time(getattr(args, "since", None), reference)
    until = parse_time(getattr(args, "until", None), reference)
    use_ports = None if getattr(args, "all_ports", False) else (list(ports) if ports else None)
    limit = getattr(args, "max_packets", 0) or None

    packets = pcapio.read_many(paths, ports=use_ports, protos=protos,
                               since=since, until=until, limit=limit,
                               keep_raw=keep_raw)
    if not getattr(args, "quiet_size", False):
        notes = []
        if use_ports:
            notes.append("port-filtered (--all-ports to disable)")
        if limit and len(packets) >= limit:
            notes.append(f"stopped at --max-packets {limit}; "
                         "the capture continues past this point")
        if since or until:
            notes.append("time-windowed")
        if big and not use_ports and not limit:
            notes.append(f"large capture ({os.path.getsize(big[0]) // (1024 * 1024)} MB) "
                         "read in full - consider --max-packets for a first look")
        if notes:
            print(f"[{len(packets)} packets loaded: " + "; ".join(notes) + "]",
                  file=sys.stderr)
    return packets
