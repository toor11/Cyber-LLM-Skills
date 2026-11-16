# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`evidence-handling-and-chain-of-custody`](SKILL.md) | Family: **Incident Response**

Verified acquisition, hashing and verification entry points. The hashing and verification commands are strictly read-only; the acquisition commands are shown with the write-blocker and device-identification steps that must precede them, because acquiring the wrong device destroys the evidence you meant to collect. Never invent flags — `dc3dd`, `ewfacquire` and `dd` differ across distributions.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `lsblk` / `Get-Disk` | `lsblk -o NAME,SIZE,SERIAL,MODEL,MOUNTPOINT` or `Get-Disk` with a `Select-Object` projection | Identify the exact source device and serial before acquisition, so the wrong disk is never imaged | Linux, Windows |
| `dc3dd` | `dc3dd if=/dev/sdb of=/evidence/FS-01.dd hash=sha256 log=/evidence/FS-01.log` | Acquisition with an in-stream digest and a tool log that records errors | Linux |
| `dd` | `dd if=/dev/sdb of=/evidence/FS-01.dd bs=4M conv=noerror,sync status=progress` | Fallback acquisition; `noerror` records bad sectors instead of aborting | Linux, macOS |
| `ewfacquire` | `ewfacquire -t /evidence/FS-01 -C "INC-2026-1114" -d sha256 /dev/sdb` | Container-format acquisition with case metadata and a digest embedded in the file header | Linux, Windows |
| `sha256sum` / `Get-FileHash` | `sha256sum /evidence/FS-01.dd > /evidence/FS-01.sha256` | Compute and store the copy digest in a manifest that later verification reads | Linux, macOS, Windows |
| `sha256sum -c` | `sha256sum -c /evidence/SHA256SUMS --ignore-missing` | Re-verify the stored artefact against the acquisition manifest at each access | Linux, macOS |
| `volatility3` | `vol -f /evidence/memory.raw windows.info` and `windows.pslist` | Confirm a memory capture is readable and identify the profile before deeper analysis | Any host |

## Minimal Script Shape

The shape below is a read-only pre-acquisition verification: it identifies the candidate device, confirms it is not the running system disk, confirms a write blocker is attached, and writes a manifest stub. It acquires nothing.

```bash
#!/usr/bin/env bash
# acquisition-precheck.sh - read-only. Refuses unsafe acquisition conditions.
set -euo pipefail

CASE="${CASE_ID:?case identifier}"
SRC="${SRC_DEV:?source device, e.g. /dev/sdb}"
OUT="${OUT_DIR:?output directory}"
WB="${WRITE_BLOCKER_MODEL:?record the write blocker model, do not assume one}"

mkdir -p "$OUT/$CASE"
report="$OUT/$CASE/precheck.json"

root_dev=$(findmnt -no SOURCE / | sed 's/[0-9]*$//')
echo "root device: ${root_dev}"

if [ "$SRC" = "$root_dev" ]; then
  echo "REFUSE: source is the running system disk" >&2
  exit 2
fi

if ! lsblk -no MODEL,SERIAL "$SRC" >/dev/null 2>&1; then
  echo "REFUSE: cannot read device identity for ${SRC}" >&2
  exit 3
fi

size=$(lsblk -bno SIZE "$SRC")
mounted=$(lsblk -no MOUNTPOINT "$SRC" | grep -c . || true)

cat >"$report" <<JSON
{
  "case": "$CASE",
  "source_device": "$SRC",
  "source_model_serial": "$(lsblk -no MODEL,SERIAL "$SRC" | tr -s ' ')",
  "source_bytes": ${size:-0},
  "mounted_filesystems": ${mounted:-0},
  "write_blocker_model": "$WB",
  "precheck_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "operator": "${OPERATOR:-unspecified}",
  "next_step": "acquire with dc3dd hash=sha256 log=<case>/<item>.log"
}
JSON

echo "precheck written: $report"
[ "$mounted" -eq 0 ] || echo "WARN: device appears mounted; confirm the write blocker actually blocks writes"
```

## Notes That Prevent Wrong Runs

- `lsblk` and `Get-Disk` are the only acceptable ways to identify the source. A device letter or `/dev/sdX` guessed from habit images the wrong disk, and no later hash repairs that.
- `dd` progress output goes to stderr and is frequently captured into the evidence log, mixing telemetry with the acquisition record. Redirect it away from the item log.
- `conv=noerror,sync` records unreadable sectors as zeroed blocks and keeps going. Record the error count in the case file; an image with silent bad sectors supports narrower claims than one without.
- `ewfacquire` embeds a digest in the container header, which is convenient but is not the same as an external manifest. Keep both, since a single artefact carrying its own integrity claim is weaker evidence than an independent record.
- `sha256sum -c` against a mounted or restored copy fails by design. Verify the stored image only, and record the mount options whenever analysis touches it.
- Memory capture changes the running system. If the capture is refused for production or safety reasons, record the refusal and the reason in the case file rather than leaving the omission to be inferred later.
