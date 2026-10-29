# Working with large captures

A plant capture is routinely hundreds of megabytes, and a mirror port left
running overnight produces gigabytes. Every capture tool here reads a file as a
stream and keeps only the packets it will actually decode, so size is a time
problem rather than a memory one.

## The controls

Every tool that reads a capture accepts the same options:

| Option | Effect |
|---|---|
| `--max-packets N` | stop after N matching packets - a first look at a huge file |
| `--since TIME` | ignore packets before a time (`2024-03-14T10:47:28Z`, `10:47:28`, or an epoch value) |
| `--until TIME` | ignore packets after a time |
| `--all-ports` | do not pre-filter by the protocol's port (slower; for a protocol on a non-standard port) |
| `--quiet-size` | suppress the note about how much was read |

A tool prints one line saying what it loaded:

```
[47 packets loaded: port-filtered (--all-ports to disable)]
```

## Why the port filter matters

`bacnet-triage.py` only decodes UDP/47808. Filtering at parse time means a
2 GB capture that contains 30 MB of BACnet costs you 30 MB of memory, not
2 GB. That filter is on by default and is the single reason these tools work on
real captures.

The cost: a protocol relocated to a non-standard port is invisible until you
pass `--all-ports`, or `--port` where the tool has it. The overview report
lists "unrecognised ports carrying payload", which is where you find out.

## A workable order on a big file

```bash
# 1. shape of the file, cheaply
python3 tools/pcap-overview.py huge.pcap --max-packets 200000

# 2. narrow to the window that matters
python3 tools/timeline.py huge.pcap --since 10:40 --until 11:10

# 3. cut that window out once, then work on the small file
python3 tools/pcap-merge.py window.pcap huge.pcap --since 10:40 --until 11:10
python3 tools/bacnet-triage.py window.pcap --dcc
```

Step 3 is the one people skip. Cutting the window once and analysing the result
is faster than re-filtering a large file for every question, and the smaller
file is what you attach to the report.

## What is still linear in file size

- `stream-carve.py` reassembles TCP streams, so it holds the payload bytes of
  the streams it keeps. Narrow it with `--since/--until` on a big capture.
- `pcap-merge.py` keeps full frames, because it rewrites them. Merging
  gigabytes needs the memory; merge a window instead.
- `capture_profile()` in the library streams without keeping anything and is
  safe at any size - that is what the GUI uses to describe a file.

## Timestamps

`--since` and `--until` accept a full ISO timestamp, a bare clock time
(interpreted on the capture's first day) or an epoch value. Captures are in
UTC. If your incident report is in local time, convert once, at the start, and
write the UTC time in your notes - mixing the two is the most common way to
build a timeline that quietly disagrees with itself.
