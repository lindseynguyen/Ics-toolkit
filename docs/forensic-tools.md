# The general-purpose helpers

Five commands that are not about any one protocol. They replace the classic
Unix tools (`file`, `md5sum`, `strings`, `xxd`, `diff`, `base64 -d`) with
versions that know what an OT artefact looks like and that say what the output
means.

If you already live in `xxd` and `binwalk`, keep using them. These exist so
that someone who does not can still get the answer.

---

## `file-inspect.py` - what is this file?

The first command for anything unfamiliar.

```bash
python3 tools/file-inspect.py evidence/unknown.bin
python3 tools/file-inspect.py evidence/* --summary
```

It reports the type by content (not by extension), the size, md5/sha1/sha256,
the entropy with a plain reading of it, any container embedded inside, the
strings worth a look grouped by category, and the suggested next commands.

Two things to notice:

- **The hashes belong in your notes.** They are how you prove later that you
  analysed this exact file.
- **A size that is a whole number of 16 KiB banks** is reported, because that
  is what firmware and cartridge images look like, and it changes how you read
  every offset afterwards.

Entropy reads like this: below 1.5 is padding, 4-5 is text, around 6 is
ordinary code, above 7.2 is compressed or encrypted.

---

## `strings-plus.py` - strings with offsets and meaning

```bash
python3 tools/strings-plus.py firmware.bin
python3 tools/strings-plus.py firmware.bin --only "ot vocabulary"
python3 tools/strings-plus.py HMI.EXE --grep "setpoint|alarm"
```

Three differences from plain `strings`:

1. **Every string carries its offset**, so you can jump straight to it with the
   hex view instead of searching again.
2. **UTF-16 is scanned**, in both byte orders. Windows binaries and a lot of
   firmware store text two bytes per character, and plain `strings` misses all
   of it - which is why text can appear to be "missing" from a file that
   obviously displays it.
3. **Results are classified**: addresses, hostnames, file paths, commands,
   credential-like text, OT vocabulary, Siemens block names, base64 blobs,
   flag-like markers.

The OT vocabulary group is usually the fastest way to tell what process a
binary belongs to: units (`MG/L`, `GPM`, `PSI`), equipment names and alarm
wording all come from the plant it was written for.

Credential-like strings are a pattern match, not a finding. Confirm each one in
context before calling it a password.

---

## `hexview.py` - look at the bytes

```bash
python3 tools/hexview.py firmware.bin --at 0x4000 --length 256
python3 tools/hexview.py firmware.bin --find "SETPOINT"
python3 tools/hexview.py firmware.bin --find-hex "78 9c"
```

A hex dump at any offset, and a search that shows every hit in context with the
matched bytes in `[brackets]`.

When a text search finds nothing, the tool checks whether the same text exists
as UTF-16 and tells you the hex to search for instead. That one check saves
beginners a lot of time.

---

## `bin-diff.py` - what changed between two builds

```bash
python3 tools/bin-diff.py original.gb patched.gb
python3 tools/bin-diff.py original.gb patched.gb --hexdump
```

Byte-level comparison that **interprets** each changed region rather than only
locating it:

```
0x0000400a   6 bytes  text: 'FCV-2' -> 'MOD'
0x00005002   2 bytes  inside the 4-byte value at 0x00005000: float 1.5 -> 9.75
0x0000014e   2 bytes  (header checksum)
```

That is the whole review of a firmware change in three lines: a relabelled
message, a setpoint moved from 1.5 to 9.75, and a rebuilt checksum. For text
files it falls back to a unified diff.

Rules of thumb: a change inside a text region is a relabelled message; a
four-byte change in a data region is usually a constant - a setpoint, a limit
or a timer; a change in the header area alone just means the image was rebuilt.

---

## `decode.py` - decode without guessing

```bash
python3 tools/decode.py --text "SGVsbG8gZnJvbSB0aGUgUExD"
python3 tools/decode.py blob.bin --at 0x8000 --length 400 --chain
```

Tries base64, base32, URL-safe base64, hex, URL encoding, gzip, zlib, raw
deflate, ROT13, UTF-16 and every single-byte XOR, scores each result by how
much it looks like real text, and shows the best candidates. `--chain` follows
nested encodings, so base64 wrapping a gzip stream decodes in one step.

If nothing decodes, that itself is information: the data is already plain, it
is packed with something unusual (try `blob-carve.py`), or it is genuinely
encrypted - and then the key has to come from somewhere else.

Worth saying plainly: **single-byte XOR is obfuscation, not encryption.** If
that is what worked, the "key" is one byte and the data was never protected.

---

## How they fit the workflow

```
file-inspect.py        →  what am I holding, and what is inside it
strings-plus.py        →  what is it about, and where
hexview.py             →  look at a specific offset
blob-carve.py          →  extract what is packed inside
decode.py              →  make an encoded chunk readable
bin-diff.py            →  what changed against a known-good build
```

Container, then regions, then data, then code - the same order as the firmware
method in [`firmware-artifacts.md`](firmware-artifacts.md). Reading data
answers more questions than disassembly, and answers them faster.
