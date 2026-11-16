# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`memory-forensics-process-and-injection-analysis`](SKILL.md) | Family: **Digital Forensics**

Verified entry points for process and injection analysis against a Windows memory image. Confirm plugin names on the installed build: Volatility 3 2.26.2 (2025-09-25) relocated the malware family to `windows.malware.*` and the legacy names emit a deprecation reminder until roughly 2026-06-07.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Volatility 3 (enumeration) | `vol -f host.dmp windows.psscan` beside `windows.pslist` | Pool-scanned versus list-walked processes; the delta is the unlinked population | Cross-platform |
| Volatility 3 (regions) | `vol -f host.dmp windows.malware.malfind --pid <PID>` | Committed executable regions with MZ or shellcode prologues | Cross-platform |
| Volatility 3 (loader lists) | `vol -f host.dmp windows.ldrmodules --pid <PID>` | `InLoad` / `InInit` / `InMem` membership per mapped module | Cross-platform |
| Volatility 3 (address space) | `vol -f host.dmp windows.vadinfo --pid <PID>` | Protection bits, private-versus-mapped flag, backing file per region | Cross-platform |
| Volatility 3 (ghosting and identity) | `vol -f host.dmp windows.malware.processghosting` then `windows.pebmasquerade` | `DeletePending` on the image file object, and PEB-reported path versus VAD-backed path (2.27.0, 2026-01-29) | Cross-platform |
| Volatility 3 (rendering) | `vol -f host.dmp --renderer json <plugin>` | Machine-readable output for differential scripting; a failed plugin exits non-zero rather than printing nothing | Cross-platform |

## Minimal Script Shape

The shape below produces the only defensible answer: for every process with a loader discrepancy, print whether the discrepancy is expected for that runtime and whether the region is backed by a file. It is read-only against the image.

```python
#!/usr/bin/env python3
"""injection_matrix.py — per-PID VAD-vs-PEB discrepancy matrix. Read-only."""
import json, subprocess, sys

IMG = sys.argv[1] if len(sys.argv) > 1 else "host.dmp"
VOL = ["vol", "-f", IMG, "--renderer", "json"]
JIT_HOSTS = {"chrome.exe", "msedge.exe", "firefox.exe", "java.exe", "node.exe", "dotnet.exe"}

def rows(plugin, *args):
    p = subprocess.run(VOL + [plugin, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"GAP: {plugin} failed -> INCONCLUSIVE: {p.stderr.strip()[:200]}")
    return [json.loads(l) for l in p.stdout.splitlines() if l.strip()]

for proc in rows("windows.pslist"):
    pid, name = proc["PID"], proc["ImageFileName"]
    mods = rows("windows.ldrmodules", "--pid", str(pid))
    gaps = [m for m in mods if m.get("MappedPath")
            and not (m.get("InLoad") and m.get("InInit"))]
    if not gaps:
        continue
    branch = "JIT" if name.lower() in JIT_HOSTS else "STRICT"
    for m in gaps:
        print(f"[{branch}] pid={pid} {name} path={m['MappedPath']} "
              f"InLoad={m.get('InLoad')} InInit={m.get('InInit')} InMem={m.get('InMem')}")
```

## Notes That Prevent Wrong Runs

- `windows.malfind --dump` writes extracted regions to disk. Point `--dump-dir` at a new directory, never the acquisition tree, and hash the dumps before analysis.
- The `--pid` requirement exists on `malfind`, `ldrmodules`, `vadinfo` and `threads`; running without it across a large image is slow and produces output too broad to review.
- `windows.vadregexscan` (2.26.0) scans VAD regions for regex matches and is the right tool when you have a byte pattern rather than a protection-bit hypothesis; `windows.vadyarascan` was improved in 2.27.0 for YARA over VAD-backed regions.
- A minidump contains little user-mode page content; `vadinfo` will list regions while `--dump` yields truncated data. Declare the dump class before quoting region contents.
