# The graphical interface

A local web interface that identifies an artefact, proposes the analysis steps
in the order a responder would run them, runs the real CLI tools for you, and
explains each result in plain language.

It exists so that someone who has never touched an industrial protocol can
start producing correct findings on day one - and so that the same person
stops needing it, because every result shows the exact command that produced
it.

## Starting it

```bash
cd ics-toolkit
python3 gui/serve.py
```

That prints something like:

```
ics-ctf-toolkit GUI
  interface : http://127.0.0.1:8765/
  workspace : /home/analyst/ics-toolkit/workspace
```

and opens your browser. Nothing else is needed: no pip install, no Node, no
internet. Stop it with Ctrl+C.

| Option | Effect |
|---|---|
| `--port 9000` | listen on another port (use this if 8765 is taken) |
| `--workspace /case/042` | keep artefacts and extracted files in a case folder |
| `--no-browser` | do not open a browser (useful over SSH) |
| `--host 127.0.0.1` | bind address; **leave it as the default** |

### Over SSH, on a headless analysis box

Do not bind to `0.0.0.0`. Forward the port instead:

```bash
ssh -L 8765:127.0.0.1:8765 analyst@box
# on the box:
python3 gui/serve.py --no-browser
# then open http://127.0.0.1:8765/ on your laptop
```

## The three tabs

### Guided

The default, and the one to use when you are learning.

1. **Add an artefact.** Drag the file onto the left panel, or click *Choose a
   file*. If the file is already on that machine - the usual case on an
   analysis box - open *File already on this machine?* and paste its path.
2. **Read the identification card.** It names the file type in ordinary words,
   says how much traffic a capture holds, lists the industrial protocols found
   inside, and warns you about the things that silently ruin an analysis: IPv4
   fragmentation, a tampered ROM checksum, data appended past the end of an
   executable.
3. **Work down the suggested steps.** They are ordered, and the highlighted
   one is the recommended next click. Each card states *why* that step matters
   before you run it, and shows the command it will run.
4. **Read the result.** Each result card has three parts: the command line
   (with a *Copy command* button), a **What this means** block translating the
   tables into plain language, and the full report.

Select several files with Ctrl/Cmd-click and the panel offers cross-file
actions, such as merging a fragmented capture set into one timeline.

### All tools

Every script with every option exposed: pick a tool, pick a view, pick the
files, fill in any flags. Use it once you know what you want - it is the same
execution path, so the command line is still printed.

### How to use

The built-in quick reference: the five-step method, the four questions every
OT analysis comes down to, and a glossary of the terms that appear in the
reports. Terms used in a specific result are also listed under that result,
under *Terms used here*.

## Where files go

Everything lives in the workspace folder printed at startup:

```
workspace/
  capture.pcap         artefacts you added
  rig.gb
  merged.pcap          outputs the tools produce
  extracted/           carved files and extracted blobs
```

Use `--workspace` to keep one folder per case. Removing a file from the list
deletes it from that folder, nothing else.

## What it does and does not do

- It **runs only the scripts in `tools/`**, with a fixed allow-list of flags.
  There is no free-text command field, and nothing is passed through a shell.
- File names are confined to the workspace folder; `../` paths are refused.
- It **binds to 127.0.0.1** and rejects requests that did not arrive over
  loopback. Treat it as a single-user tool on your own machine.
- It is an **analysis** interface. It reads files. It never sends a packet to a
  device, never connects to anything, and never alters a controller.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Address already in use` | another copy is running, or the port is taken - use `--port 8766` |
| Browser does not open | run with `--no-browser` and open the printed URL yourself |
| "Could not reach the local server" toast | the server stopped; check the terminal you started it in |
| A file over 512 MB will not upload | copy it into the workspace folder directly, or use *File already on this machine?* |
| An analysis runs for minutes then stops | each run is capped at 300 seconds; use a narrower view, or filter with `--src` / `--unit` |
| "no BACnet/IP messages found" | that capture does not carry that protocol, or it is on a non-standard port - run the overview, then pass `--port` in *All tools* |
| Tables look misaligned | the raw report is monospaced and scrolls sideways; widen the window or scroll the report box |

## Learning to drop the GUI

The point of the printed command line is that it is the same command you would
type. When a case is finished, your notes should contain a list like:

```
python3 tools/pcap-overview.py  case.pcap
python3 tools/bacnet-triage.py  case.pcap --dcc
python3 tools/bacnet-triage.py  case.pcap --writes
```

That list is reproducible by anyone, reviewable, and scriptable. The terminal
equivalent of the guided mode is:

```bash
python3 tools/triage-plan.py evidence/*
```

which prints the same identification and the same ordered plan, with the
commands ready to paste.
