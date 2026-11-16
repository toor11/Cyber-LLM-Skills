---
name: memory-forensics
description: "Analyses volatile memory: acquisition, profile selection, process and injection detection, network artifacts and credential recovery with Volatility and similar tools. Use when live memory is available and fileless activity is suspected."
family: digital-forensics
tier: flagship
triggers: ["memory forensics", "volatility", "ram analysis", "memory dump analysis"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [memory-forensics-process-and-injection-analysis, memory-forensics-network-and-credential-artifacts, disk-forensics-and-artifacts, windows-artifact-forensics]
---

# Memory Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **flagship** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

Memory is the only evidence class that expires on the host's schedule: processes, network connections and decrypted secrets exist nowhere else, and every action taken on the host — including the acquisition tool itself — allocates pages that overwrite what was there. Acquisition is therefore first in the volatility order, and its quality decides everything downstream. A live tool loads a kernel driver to read physical memory and produces a raw image, and the image is smeared across the minutes the capture took, so structures captured early can disagree with structures captured late; a hypervisor snapshot with memory is atomic and preferable where available, and hibernation files and pagefiles hold pages that were evicted from RAM and are absent from the live image. Once an image exists, parsing it is a process of reconstruction with known failure modes. Volatility 3 derives its own symbols and layers, so there is no profile to select — but layer detection matters, and recent releases specifically improved Windows 11 Intel layer detection, with a known issue remaining on certain Windows 11 images. Plugin namespaces moved: from 2.26.2 the injection and process-hiding plugins live under `windows.malware.*` (including `hollowprocesses`, `malfind`, `psxview`, `suspicious_threads`, `svcdiff`, `processghosting`, `direct_system_calls`, `indirect_system_calls`) with the old names deprecated but functional for roughly a year, and the same split applies to `linux.malware.*`. 2.26.0 added scanners that answer questions the classic set could not — `windows.deskscan`, `windows.desktops`, `windows.windowstations`, `windows.windows`, `windows.suspended_threads`, `windows.vadregexscan`, and the syscall-argument plugins `windows.direct_system_calls` and `windows.indirect_system_calls` — while 2.27.0 added `windows.pebmasquerade` for processes whose PEB does not match their image, and improved `windows.dlllist` and `windows.vadyarascan`. What memory cannot tell you is equally important: a process in `psscan` but not `pslist` is either terminated or unlinked and the exit time distinguishes them, `malfind` flags private executable regions that legitimate JIT engines also allocate, `cmdline` is read from the process's own memory and can be altered by it, and anything paged out to a pagefile you did not collect is simply absent.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves injected code, hollowing or hidden processes **THEN** switch to [`memory-forensics-process-and-injection-analysis`](../memory-forensics-process-and-injection-analysis/SKILL.md) (1 hop); **IF** it involves connections, credentials or hashes **THEN** switch to [`memory-forensics-network-and-credential-artifacts`](../memory-forensics-network-and-credential-artifacts/SKILL.md) (1 hop). This page covers acquisition, tooling and the decision between them.
2. **IF** the host is still running **THEN** acquire before containment, before antivirus, and before any tool that kills processes, because every program you run overwrites free pages where terminated processes and closed connections still sit; **IF** the host is already contained **THEN** say so, because the image now reflects post-containment state and cannot show what the malware did before.
3. **IF** acquisition is possible through the hypervisor **THEN** prefer a snapshot with memory, since it is atomic; **IF** only a live capture is possible **THEN** record the capture window and treat cross-structure disagreements as expected.
4. **IF** the image came with a pagefile or hibernation file **THEN** attach them (`--swap` for pagefile-backed pages, or the hibernation layer for modern hiberfil) before concluding that data is absent; **IF** they were not collected **THEN** state that paged-out content is unreachable.
5. **IF** a plugin returns nothing surprising **THEN** run its scanning counterpart before concluding: `pslist` versus `psscan`, `dlllist` versus `ldrmodules`, `netscan` versus the raw connection structures. The active-list plugin hides exactly what an unlinker wants hidden.
6. **IF** a `malfind` hit appears in a process that runs a JIT, a browser or a security product **THEN** require corroboration — an MZ header, shellcode-like prologue, or a matching `vadinfo` region — before calling it injected.
7. **IF** telemetry source covering `Volatility` / `memory dump` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `memory-forensics-process-and-injection-analysis` | [`memory-forensics-process-and-injection-analysis`](../memory-forensics-process-and-injection-analysis/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `memory-forensics-network-and-credential-artifacts` | [`memory-forensics-network-and-credential-artifacts`](../memory-forensics-network-and-credential-artifacts/SKILL.md) | Dedicated variant-specific workflow |
| Need acquisition commands and plugin sequence | [`QUERIES.md`](QUERIES.md) | One class per question |
| Need plugin and acquisition tool flags | [`TOOLS.md`](TOOLS.md) | WinPmem, AVML, LiME, `vol`, volshell |
| Need the disk artifacts that complement memory | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | Prefetch, registry and event context |
| Need to place memory findings on a timeline | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Normalisation and ordering |
| Need scripted plugin runs | [`volatility3-plugin-and-memory-triage-scripting`](../../security-automation-and-tool-development/volatility3-plugin-and-memory-triage-scripting/SKILL.md) | Automation ownership |
| Need real case shapes for fileless intrusions | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record the acquisition tool and version, the UTC start and end of capture, the image SHA-256, and whether the source was a live driver-based capture, a hypervisor snapshot, a hibernation file or a crash dump. An image without that provenance cannot be distinguished from a partial or a stale capture.
2. **Choose the branch from the artifact type and the question.** Driver-captured raw image with pagefile goes to the full plugin set including swap-aware plugins; a hibernation file goes to the hibernation layer first; a crash dump may lack user-mode pages entirely. Write the branch into the output, because a crash-dump image and a full physical image support different claims.
3. **Establish a baseline-versus-probe differential.** Baseline is a memory image from a peer host of the same build or the host's own pre-incident capture. Probe is the incident image. The finding is the difference in populations — an extra process in `pstree`, a region type that should not exist in that process, a connection no service should hold.
4. **Name the stop condition.** Declare `Inconclusive` when the image is smeared beyond the tolerance a cross-structure claim needs, when the pagefile and hibernation file were not collected so paged-out data is unreachable, when layer or symbol detection failed for that build, when memory compression means "not found" cannot be read as "not present", or when the relevant structure was already overwritten by post-incident activity.
5. **State what counts as proof.** Proof is two independent structures agreeing: a process found by scanning *and* a thread or handle structure that belongs to it; an injected region *and* a VAD entry with the matching protection and no file backing; a connection *and* the owning process resolved from the pool header. One plugin's output is a lead — and `malfind` in particular is a heuristic, not a finding.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Process present in `windows.psscan` but absent from `windows.pslist`, with no exit time | EPROCESS pool scan versus active list | A process structure exists that the active list does not reference; either it terminated or it was unlinked |
| `windows.malfind` region with `PAGE_EXECUTE_READWRITE` and no file backing, containing an MZ header | VAD region and page protection | Executable private memory holding a PE image exists in that process; corroborate before calling it injection |
| `windows.ldrmodules` showing a module mapped but missing from one or more loader lists | PEB loader list comparison | A module is mapped in the process while hidden from the loader's own bookkeeping |
| `windows.pebmasquerade` reporting a process whose PEB image path disagrees with its image | PEB versus section/image comparison | The process misrepresents its own path, which normal execution does not do |
| `windows.deskscan` and `windows.windowstations` output showing an interactive desktop on a session that should be service-only | Window station and desktop structures | An interactive session exists where the host's role says none should; a strong pivot on servers |
| `windows.suspended_threads` listing a thread created suspended and never resumed | Thread structures and suspend counts | A process was created and held before execution, a pattern used to stage code without running it |
| Connection in `netscan` owned by a process whose image is not a network service | TCP/UDP endpoint structures with owner resolution | That process held a network endpoint at capture time; combined with the image path it identifies the owner |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Runs one plugin, on an old namespace, and treats its output as the process list.
vol -f memory.raw windows.malfind
vol -f memory.raw windows.pslist
# malfind is a heuristic with JIT false positives and no corroboration here; the
# plugin names predate the windows.malware.* move; and pslist alone cannot show
# a process that was unlinked from the active list.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
IMG=/cases/52/memory.raw; OUT=/cases/52/out; mkdir -p "$OUT"

vol -f "$IMG" windows.info > "$OUT/info.txt"
grep -Ei 'layer|symbol|build' "$OUT/info.txt" | head -10

# Active list and pool scan, compared rather than read separately.
vol -f "$IMG" windows.pslist --output csv > "$OUT/pslist.csv"
vol -f "$IMG" windows.psscan  --output csv > "$OUT/psscan.csv"
python3 - <<'PY'
import csv
def pids(p):
    with open(p) as fh:
        return {r["PID"]: r["ImageFileName"] for r in csv.DictReader(fh)}
a, s = pids("/cases/52/out/pslist.csv"), pids("/cases/52/out/psscan.csv")
for pid in sorted(set(s) - set(a), key=int):
    print("scan-only:", pid, s[pid])
PY

# Injection candidates with the region detail behind each hit.
vol -f "$IMG" windows.malfind --output csv > "$OUT/malfind.csv"
vol -f "$IMG" windows.vadinfo --output csv > "$OUT/vadinfo.csv"
wc -l "$OUT/malfind.csv" "$OUT/vadinfo.csv"
```

**Why this matters:** the strong form records layer and symbol detection first, compares the active list against the pool scan instead of trusting either, and pulls `vadinfo` so every `malfind` hit has the region detail needed to judge it — which is the difference between a heuristic and a finding.

## When It Is NOT This Issue

- **Smear from a long live capture:** structures acquired minutes apart can disagree, producing phantom processes, truncated lists and plugins that crash. A single odd result on a large live image is expected; rerun and cross-check before drawing a conclusion.
- **JIT and browser memory:** .NET, Java, V8 and some security products allocate executable private memory by design, so `malfind` hits in those processes are normal. Require content or VAD corroboration.
- **Memory compression on modern Windows:** pages evicted to the compression store are compressed and standard string or structure searches will miss them. "Not found" in a compressed region is not absence.
- **Paged-out content:** anything in `pagefile.sys` or `swapfile.sys` is outside a RAM image unless those files were collected. A missing credential or connection may simply have been paged out.
- **Hibernation and Fast Startup images:** a `hiberfil.sys` from a Fast Startup shutdown holds the kernel session only, not the full user-mode picture, so a process list from it is not comparable to a live capture.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Volatility` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** acquisition tool and version, UTC capture window, image SHA-256 and acquisition type are recorded, and the output states whether pagefile and hibernation files were collected.
- [ ] **Branch stated:** the image type (live capture, hypervisor snapshot, hibernation, crash dump) and the plugin namespace used are named, including any `windows.malware.*` versus deprecated-name choice.
- [ ] **Differential defined:** a peer image or pre-incident capture was compared, or the finding is explicitly labelled as an absolute observation rather than a delta.
- [ ] **Stop condition cleared or declared:** smear, layer or symbol failure, compression, paged-out data and overwritten structures were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: memory-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`memory-forensics-process-and-injection-analysis`](../memory-forensics-process-and-injection-analysis/SKILL.md) - Digital Forensics (leaf)
- [`memory-forensics-network-and-credential-artifacts`](../memory-forensics-network-and-credential-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `memory-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — acquisition writes to external media only, never to the target's own disk, and no plugin is used to modify or inject into the captured image.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 43 |
| Distinct dataset sources | 11 |
| Top sources | CYBER_CPT/ctf_search (10), CYBER_CPT/L5/ctf_search (9), Forensic_Toolkit_Dataset (8), OffsecCyber (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 8 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
