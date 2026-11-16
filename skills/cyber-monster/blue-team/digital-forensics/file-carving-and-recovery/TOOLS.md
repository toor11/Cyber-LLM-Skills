# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-carving-and-recovery`](SKILL.md) | Family: **Digital Forensics**

Recovery tooling with verified invocation shapes. Never invent undocumented flags — confirm with `<tool> --help` on the installed build, because Scalpel's config syntax and PhotoRec's option letters differ across releases. Every command reads an image copy and writes to a separate output volume.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `foremost` | `foremost -c <conf> -t jpg -i <image> -o <outdir> -q` | Signature carving from an auditable config, one type at a time | Linux, macOS |
| `scalpel` | `scalpel -c <conf> -o <outdir> <image>` | Faster carving with a concise signature config and parallel-friendly design | Linux |
| `photorec` | `photorec /log /d <outdir> <image>` | Structure-aware recovery across many formats, including some multi-fragment cases | Cross-platform |
| `bulk_extractor` | `bulk_extractor -o <outdir> -e jpeg_carved -x all <image>` | Feature inventory over unallocated space, independent of filesystem | Cross-platform |
| `MFTECmd --dr` | `MFTECmd.exe -f <$MFT> --csv <out> --at --dr` | Recover resident NTFS data directly from MFT records | Windows |
| `unzip` / `pdfinfo` | `unzip -t <carved.zip>` / `pdfinfo <carved.pdf>` | Independent structural validation of container formats | Cross-platform |

## Minimal Script Shape

The shape below recovers what metadata can give first, carves only the remaining type, and validates every candidate before it is counted — the difference between a recovery report and a list of byte offsets.

```python
#!/usr/bin/env python3
"""carve-validate.py — validate carved images and emit a reportable verdict per candidate."""
import hashlib
import pathlib
import sys

from PIL import Image

CARVED_DIR = pathlib.Path(sys.argv[1])

def verdict(path: pathlib.Path) -> tuple[str, str]:
    try:
        with Image.open(path) as im:
            im.verify()              # structural pass
        with Image.open(path) as im:
            im.load()                # decode pass
            dims = f"{im.width}x{im.height}"
        return "VALID", dims
    except Exception as exc:         # fragment or wrong signature
        return "FRAGMENT", type(exc).__name__

ok = frag = 0
for p in sorted(CARVED_DIR.rglob("*")):
    if not p.is_file():
        continue
    status, detail = verdict(p)
    if status == "VALID":
        ok += 1
    else:
        frag += 1
    print(f"{status}\t{detail}\t{p.stat().st_size}\t"
          f"{hashlib.sha256(p.read_bytes()).hexdigest()}\t{p.name}")

print(f"\nvalidated={ok} fragments={frag} total={ok + frag}")
```

## Notes That Prevent Wrong Runs

- Carve from the image, not from a mounted filesystem: a mount exposes only what the filesystem currently believes exists, so deleted data is invisible to a carver pointed at it.
- A narrow signature config is the single biggest precision gain. `-t jpg` with a one-line config beats `-x all` on any report you have to defend.
- Carvers write a `report.xml` or audit file beside the output. Keep it — it records the byte offsets, which is how you corroborate a fragment against allocation evidence later.
- `photorec` and `foremost` can disagree on the same image; run two carvers when a candidate will be cited, and report where they agree.
- Treat every recovered executable, script or document as untrusted: never run it, never let an office suite open it, and never extract it onto a host with network access.
