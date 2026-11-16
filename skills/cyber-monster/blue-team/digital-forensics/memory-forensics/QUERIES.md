# Artifacts and Queries

> Sub-skill: [`memory-forensics`](SKILL.md) | Family: **Digital Forensics**

Extraction and comparison queries owned by `memory-forensics`, grouped by question class. Each class states the expected hit and the false-positive note that must be cleared before the hit is treated as a finding. Nothing here modifies a captured image or injects into a live process; acquisition writes to external media only.

## Class 1 — Image gate: layer, symbols and coverage

Expected hit: a detected layer, resolved symbols and a build identifier. Without these, plugin output is uninterpretable, and a symbol miss is a coverage limit rather than an absence of activity.

```bash
IMG=/cases/52/memory.raw
vol -f "$IMG" windows.info > info.txt 2>&1 || vol -f "$IMG" banners
grep -Ei 'layer|symbol|ntbuildlab|is64bit|memory_layer' info.txt | head -15
sha256sum "$IMG" | tee "$IMG.sha256"
```

False-positive note: layer detection failures on some Windows 11 images are a known limitation of specific Volatility 3 releases, not evidence about the host. Record the version and try the neighbouring release before drawing conclusions.

## Class 2 — Process population, active list versus pool scan

Expected hit: a small scan-only set explained by recent process exits, and nothing unexplained. A scan-only PID with no exit time in an otherwise idle image is the candidate.

```bash
vol -f "$IMG" windows.pslist --output csv > pslist.csv
vol -f "$IMG" windows.psscan  --output csv > psscan.csv
python3 - <<'PY_MEMDIFF'
import csv
def rows(p):
    with open(p) as fh:
        return {r["PID"]: r for r in csv.DictReader(fh)}
a, s = rows("pslist.csv"), rows("psscan.csv")
for pid in sorted(set(s) - set(a), key=lambda x: int(x)):
    r = s[pid]
    print(pid, r.get("ImageFileName"), "exit:", r.get("ExitTime") or "-")
PY_MEMDIFF
```

False-positive note: `psscan` finds structures for processes that exited normally, so a busy host always shows scan-only entries. The signal is a scan-only process whose parent is expected to be running, or whose exit time is implausible for the image's capture time.

## Class 3 — Parent/child and image-path anomalies

Expected hit: process trees that match the host's role, and image paths that resolve to the directory they claim. A mismatch between the PEB path and the mapped image is the finding.

```bash
vol -f "$IMG" windows.pstree --output csv > pstree.csv
vol -f "$IMG" windows.cmdline --output csv > cmdline.csv
vol -f "$IMG" windows.pebmasquerade --output csv > pebmasquerade.csv 2>/dev/null || \
  echo "NOTE: plugin absent in this release; record the version"
head -3 pebmasquerade.csv 2>/dev/null

awk -F, 'NR>1 && $0 ~ /svchost|lsass/ {print $1, $2, $3}' pstree.csv | head -10
```

False-positive note: `cmdline` is read from the target process's own memory, so a process can alter what it reports. Treat a clean-looking command line as consistent with innocence only when the image path and parent also agree.

## Class 4 — Injection candidates with region corroboration

Expected hit: `malfind` hits whose `vadinfo` region has no file backing and whose protection is executable-writable, ideally with an MZ header at the region start. A hit without that corroboration stays a candidate.

```bash
vol -f "$IMG" windows.malfind --output csv > malfind.csv
vol -f "$IMG" windows.vadinfo --output csv > vadinfo.csv
vol -f "$IMG" windows.ldrmodules --output csv > ldrmodules.csv

awk -F, 'NR>1 {print $1, $2, $4, $5}' malfind.csv | head -10
awk -F, 'NR>1 && $0 ~ /False/ {print $2, $3}' ldrmodules.csv | head -10
```

False-positive note: `malfind` flags JIT and browser heaps as a matter of course, and `ldrmodules` shows legitimate transient mappings as "missing" from one list. Both require a second structure — content, or a region that should not exist in that process — before they constitute a finding.

## Class 5 — Sessions, desktops and suspended threads

Expected hit: window stations and desktops that match the host's role (none interactive on a server), and threads that are suspended for a reason the process explains.

```bash
vol -f "$IMG" windows.windowstations --output csv > windowstations.csv 2>/dev/null
vol -f "$IMG" windows.desktops      --output csv > desktops.csv 2>/dev/null
vol -f "$IMG" windows.deskscan      --output csv > deskscan.csv 2>/dev/null
vol -f "$IMG" windows.suspended_threads --output csv > suspended.csv 2>/dev/null
head -5 deskscan.csv suspended.csv 2>/dev/null
```

False-positive note: these plugins do not exist in older releases, so an empty result may be a version limit. RDP sessions, console logons and service desktops are normal on workstations; they are anomalous only against the host's documented role.

## Class 6 — Pagefile- and hibernation-backed content

Expected hit: additional structures or strings that the RAM image alone did not contain, when the swap file was collected.

```bash
vol -f "$IMG" --swap /cases/52/pagefile.sys windows.strings --output-file strings.txt 2>/dev/null || \
  echo "NOTE: swap attach unsupported in this build; record the limitation"
ls -la /cases/52/hiberfil.sys 2>/dev/null
vol -f /cases/52/hiberfil.sys windows.hibernation.Info 2>/dev/null | head -20 || \
  echo "NOTE: hibernation layer unavailable or unsupported for this build"
```

False-positive note: a hibernation image from Fast Startup holds the kernel session only, so a process list derived from it is not comparable with a live capture. State which acquisition produced the image before comparing populations.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the acquisition tool, Volatility version and plugin namespace beside every memory finding; a report that omits them cannot be reproduced.
