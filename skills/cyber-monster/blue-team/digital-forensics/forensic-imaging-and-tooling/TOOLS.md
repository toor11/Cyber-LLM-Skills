# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`forensic-imaging-and-tooling`](SKILL.md) | Family: **Digital Forensics**

Acquisition tooling with verified invocation shapes. Never invent undocumented flags — confirm with `<tool> --help` on the installed build, because `ewfacquire`'s compression and format tokens and `dc3dd`'s operand names differ across releases. Every command writes to a case output volume and never to the source device.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dc3dd` | `dc3dd if=<dev> of=<img> hash=sha256 log=<log> bufsz=1M retry=2` | Raw imaging with on-the-fly hashing and an error log | Linux |
| `ewfacquire` | `ewfacquire -u -t <target> -C <case> -D <desc> -f encase6 -d sha256 <dev>` | EWF acquisition with embedded case metadata and hashes | Linux, macOS |
| `ewfverify` | `ewfverify -d sha256 <image.E01>` | Verify a completed EWF segment set against its stored hashes | Linux, macOS |
| `ddrescue` | `ddrescue -d -r3 <src> <img> <mapfile>` | Failing-media acquisition with a resumable error map | Cross-platform |
| `aff4imager` | `aff4imager -i <dev> -o <volume.aff4>` | AFF4 container acquisition with verifiable storage | Linux, macOS |

## Minimal Script Shape

The shape below refuses to start without a recorded device identity and read-only state, keeps the hash pair from the acquisition itself, and re-verified the result — the minimum for an acquisition that will survive a challenge.

```bash
#!/usr/bin/env bash
# acquire.sh — defensible raw acquisition with an explicit provenance record.
set -euo pipefail

SRC="${1:?usage: acquire.sh <device> <case-dir>}"
CASE="${2:?usage: acquire.sh <device> <case-dir>}"
mkdir -p "$CASE"

ro=$(blockdev --getro "$SRC")
[ "$ro" = "1" ] || { echo "ABORT: $SRC is not read-only; attach a write blocker"; exit 2; }

lsblk -o NAME,SERIAL,MODEL,SIZE,RO "$SRC" | tee "$CASE/device-identity.txt"
printf 'start=%s\n' "$(date -u +%FT%TZ)" | tee "$CASE/window.txt"

dc3dd if="$SRC" of="$CASE/disk.img" hash=sha256 log="$CASE/dc3dd.log" bufsz=1M retry=2
printf 'end=%s\n' "$(date -u +%FT%TZ)" >> "$CASE/window.txt"

sha256sum "$CASE/disk.img" | tee "$CASE/disk.img.sha256"
grep -Ei 'sha256|error' "$CASE/dc3dd.log" | tail -10
echo "acquisition complete; verify the hash pair before analysis"
```

## Notes That Prevent Wrong Runs

- `blockdev --getro` is necessary but not sufficient: it reflects the kernel's view and a software read-only mount sets it too. Record separately whether a hardware blocker was used and when it was validated.
- `dc3dd` prints the input and output hashes in its log. Keep the log with the image; a hash in the image directory alone does not show that the source was hashed.
- `ewfacquire -u` enables unattended mode and suppresses prompts — in a script this is required, but it also means a wrong device path is never confirmed by a human. Print the device identity before starting.
- `ddrescue` map files are resumable state. Never delete one mid-case; a resumed run without the map re-reads from a different starting assumption.
- A logical acquisition (`--logical` in most suites) preserves file content but not unallocated space, slack or sometimes timestamps. State it explicitly in the report rather than letting the word "image" imply a physical copy.
