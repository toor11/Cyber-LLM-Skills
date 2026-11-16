# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`memory-forensics`](SKILL.md) | Family: **Digital Forensics**

Acquisition and analysis entry points for volatile memory. Never invent undocumented flags — confirm with `vol -h` and `<tool> --help` on the installed build, because plugin namespaces moved in the 2.26 line and acquisition tools differ by release. Acquisition writes to external media only; analysis is read-only against the image.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| WinPmem | `winpmem_mini_x64.exe E:\HOST01_mem.raw` | Driver-based physical memory capture on Windows | Windows |
| `velociraptor` | `winpmem()` VQL function or the `winpmem` accessor | Remote or scripted memory capture with the binary built in | Windows |
| AVML | `avml /evidence/mem.lime` | Userspace `/proc/kcore` capture that avoids per-kernel modules | Linux |
| LiME | `insmod lime.ko "path=/evidence/mem.lime format=lime"` | Kernel-module capture, must match the running kernel exactly | Linux |
| Volatility 3 | `vol -f <img> windows.psscan --output csv` | Structure-based process recovery and comparison against `pslist` | Cross-platform |
| Volatility 3 (malware ns) | `vol -f <img> windows.malware.malfind` | Injection heuristics under the post-2.26.2 namespace; old names still resolve with a deprecation reminder | Cross-platform |

## Minimal Script Shape

The shape below captures, hashes, and records the provenance a report needs — including the plugin namespace — and refuses to analyse an image whose layer did not resolve.

```bash
#!/usr/bin/env bash
# mem-capture-analyse.sh — capture to external media, hash, gate on layer detection.
set -euo pipefail

OUT="${1:?usage: mem-capture-analyse.sh <output dir>}"
IMG="$OUT/host_mem.raw"; mkdir -p "$OUT"

# 1. Capture (Windows example; substitute AVML or LiME on Linux).
#    Write to EXTERNAL media: never to the target's own disk or pagefile volume.
winpmem_mini_x64.exe "$IMG"

# 2. Provenance at capture time, not later.
sha256sum "$IMG" | tee "$OUT/host_mem.raw.sha256"
date -u +%FT%TZ | tee "$OUT/capture-window.txt"
vol -f "$IMG" windows.info > "$OUT/info.txt" 2>&1 || true

# 3. Gate: refuse to interpret plugins if the layer did not resolve.
if ! grep -qiE 'layer|symbol' "$OUT/info.txt"; then
  echo "GAP: layer/symbol detection failed -> INCONCLUSIVE (Layer Failure)"; exit 3
fi

# 4. Namespaced plugin run; record which namespace was used.
vol -f "$IMG" windows.pslist --output csv > "$OUT/pslist.csv"
vol -f "$IMG" windows.psscan  --output csv > "$OUT/psscan.csv"
vol -f "$IMG" windows.malware.malfind --output csv > "$OUT/malfind.csv" 2>/dev/null \
  || vol -f "$IMG" windows.malfind --output csv > "$OUT/malfind.csv"
echo "plugin namespace: windows.malware.* (2.26.2+) with deprecated fallback"
```

## Notes That Prevent Wrong Runs

- Volatility 3 selects symbols itself; there is no `--profile`. If a plugin reports an unresolved symbol, that is a build coverage issue — record it and try a neighbouring Volatility release rather than inventing a profile name.
- The malware plugin namespace moved in 2.26.2: `windows.malfind`, `windows.hollowprocesses`, `windows.psxview`, `windows.suspicious_threads`, `windows.svcdiff`, `windows.processghosting` and the syscall plugins now live under `windows.malware.*`, with the old names deprecated but functional for about a year and a reminder printed.
- `--output csv` is essential for comparing plugin outputs programmatically; the default text tree is for reading, not for differential work.
- `--swap` resolves pagefile-backed pages during analysis, but only for a pagefile you actually collected. Without it, a "missing" structure may have been paged out.
- Write the image to external or network storage. Writing to the target's own disk sends it through the page cache you are trying to preserve and puts the image on the evidence volume.
- Hash at completion and record the capture window. A live capture is smeared across that window; a claim about simultaneous state is a claim the image may not support.
