# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`disk-forensics-and-artifacts`](SKILL.md) | Family: **Digital Forensics**

Read-only entry points for parsing storage media. Never invent undocumented flags — confirm with `<tool> --help` on the installed build, because TSK's offset handling and MFTECmd's output options change between releases. Nothing here writes to the evidence, repairs an image, or mounts a source read-write.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mmls` (TSK) | `mmls -B <image>` | Partition layout with start sector and byte sizes; the offset source for every later command | Cross-platform |
| `fsstat` / `istat` / `icat` (TSK) | `istat -o <sector> <image> <inode>` | Filesystem parameters, per-record metadata, and content extraction by inode without mounting | Cross-platform |
| `fls` + `mactime` (TSK) | `fls -r -m / -o <sector> <image> > body.txt` then `mactime -b body.txt -d -y` | Filesystem timeline including deleted entries, rendered in UTC | Cross-platform |
| `ewfmount` / `ewfverify` (libewf) | `ewfmount <image.E01> <dir>` then `mmls <dir>/ewf1` | Expose an EWF container read-only, and verify its stored hash | Linux, macOS |
| `MFTECmd` | `MFTECmd.exe -f <$MFT> --csv <out> --at` | Parse `$MFT` into per-record rows with both attribute timestamp sets | Windows |
| `dc3dd` | `dc3dd if=<device> of=<image> hash=sha256 log=<log>` | Image with on-the-fly hashing and an error log | Linux |

## Minimal Script Shape

The shape below refuses to guess a filesystem offset and produces a hash-verified, UTC-rendered timeline from the image without ever mounting it.

```bash
#!/usr/bin/env bash
# mmls-timeline.sh — read-only filesystem timeline from an image; no mount, no writes.
set -euo pipefail

IMG="${1:?usage: mmls-timeline.sh <image> [start-sector]}"
OUT="${2:-./out}"
mkdir -p "$OUT"

sha256sum "$IMG" > "$OUT/image.sha256"

# Locate the largest data partition rather than assuming the first slot.
START="${3:-$(mmls "$IMG" | awk '$2 ~ /^[0-9]+:/ {print $3, $5}' | sort -k2 -nr | head -1 | cut -d' ' -f1)}"
echo "using sector offset: $START"

fsstat -o "$START" "$IMG" > "$OUT/fsstat.txt"
fls -r -m / -o "$START" "$IMG" > "$OUT/body.txt"
mactime -b "$OUT/body.txt" -d -y > "$OUT/timeline-utc.csv"

printf 'entries=%s timeline_rows=%s\n' \
  "$(wc -l < "$OUT/body.txt")" "$(wc -l < "$OUT/timeline-utc.csv")"
echo "wrote $OUT; source image untouched"
```

## Notes That Prevent Wrong Runs

- `-o` takes the **sector** number printed by `mmls`; `mount -o loop,offset=` takes **bytes** (`sector * 512`). Mixing them produces an empty listing rather than an error, which reads exactly like a wiped filesystem.
- `fls` lists deleted entries only with `-d` or by including them in a recursive bodyfile; a plain `ls` of a mounted image never sees them.
- `mactime -y` renders ISO dates in UTC. Without it the output follows local time and cannot be correlated with log sources.
- `MFTECmd --at` is required to emit both `0x10` and `0x30` timestamp sets; without it matching values are collapsed.
- `ewfmount` exposes a read-only node but does not enforce read-only access to the underlying container for every tool; verify your downstream tool opens it `O_RDONLY` before trusting the setup.
- If the image has bad sectors, record the acquisition tool's error map beside the image hash. Two differing images of the same failing device is a hardware fact, not an integrity failure.
