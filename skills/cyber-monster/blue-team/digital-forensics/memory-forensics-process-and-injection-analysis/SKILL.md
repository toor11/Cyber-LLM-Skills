---
name: memory-forensics-process-and-injection-analysis
description: Process and injection analysis in memory. Covers enumerating processes, identifying hollowing and injected code, and validating suspicious memory regions. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["memory injection detection", "process hollowing memory", "volatility process"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [memory-forensics, memory-forensics-network-and-credential-artifacts, disk-forensics-and-artifacts, windows-artifact-forensics]
parent: memory-forensics
---

# Memory Forensics Process and Injection Analysis - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`process-injection-techniques`](../../../red-team/network-ad-and-endpoint/process-injection-techniques/SKILL.md)

## Mechanism and Preconditions

A Windows process is described twice in memory, and the gap between the two descriptions is what injection analysis actually measures. The forward description is the kernel's `_EPROCESS` list plus the `_PEB` loader lists (`InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`), which enumerate what the process *claims* is mapped. The backward description is the address space itself: `_EPROCESS.VadRoot` holds the VAD tree of every committed region with its protection bits, its private-versus-mapped flag, and the `_FILE_OBJECT` backing each mapped image. `windows.pslist` walks the forward list, `windows.psscan` pool-scans for `_EPROCESS` signatures and therefore also finds unlinked and terminated-but-resident processes, `windows.malfind` walks the VAD tree for committed regions carrying `PAGE_EXECUTE_READWRITE` or `PAGE_EXECUTE_WRITECOPY` whose first bytes are an MZ header or a shellcode prologue, `windows.ldrmodules` compares the three PEB lists against the VAD-backed mapped images to find modules hidden from the loader, and `windows.processghosting` checks `DeletePending` on the image `_FILE_OBJECT` for the delete-on-close trick. What none of them can tell you: `malfind` cannot distinguish malicious code from a JIT compiler's code cache, .NET's dynamic methods, V8's executable pages, or an unpacking installer; a VAD protection bit is a statement about page permissions, never about intent; and `psscan` will happily report a process that exited an hour ago because its pool page has not been reused. In Volatility 3 2.26.2 (2025-09-25) these plugins moved to `windows.malware.*` (`malfind`, `hollowprocesses`, `psxview`, `suspicious_threads`, `svcdiff`, `processghosting`, `direct_system_calls`, `indirect_system_calls`) with the old names deprecated for about a year; 2.26.0 added `windows.suspended_threads`, `windows.vadregexscan`, `windows.direct_system_calls` and `windows.indirect_system_calls`, and 2.27.0 (2026-01-29) added `windows.pebmasquerade` for a forged PEB image path plus improved `windows.vadyarascan`.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `memory-forensics-process-and-injection-analysis` **THEN** start at parent class [`memory-forensics`](../memory-forensics/SKILL.md) first.
2. **IF** the artefact is a live host **THEN** acquire before enumerating, because `psscan` and `malfind` read pool pages that a reboot or a driver unload frees; **IF** the artefact is an image **THEN** gate on `windows.info` resolving a kernel base first.
3. **IF** the image is a minidump or a crash dump rather than a full physical capture **THEN** expect user-mode VAD contents to be largely absent and restrict conclusions to `pslist`/`psscan` metadata, declaring the limitation.
4. **IF** the plugin name does not resolve **THEN** try the `windows.malware.*` namespace before the legacy `windows.*` name, since 2.26.2 relocated the whole family.
5. **IF** the candidate process is a managed-runtime or browser host (`.NET`, `java`, `node`, `chrome`, `msedge`, `Teams`) **THEN** take the JIT-first branch and require an additional corroborating artefact before calling any RWX region injected.
6. **IF** telemetry source covering `malfind` or `process scan` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`process-injection-techniques`](../../../red-team/network-ad-and-endpoint/process-injection-techniques/SKILL.md).
8. **IF** required preconditions for `memory-forensics-process-and-injection-analysis` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`memory-forensics`](../memory-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to know which host talked to what from that process | [`memory-forensics-network-and-credential-artifacts`](../memory-forensics-network-and-credential-artifacts/SKILL.md) | Socket-to-PID attribution and credential residency |

## Procedure

1. **Confirm the evidence source, and confirm it twice.** Record the acquisition tool, hash and whether the capture was live or post-mortem, then require `windows.info` to resolve kernel base and build. Next confirm that the plugin family you intend to use resolves under this build — with the 2.26.2 relocation, "unknown plugin" and "no injected regions" both surface as an unhelpful empty run and must not be confused.
2. **Choose the branch from the process's runtime, not from the alert.** Native, non-JIT processes take the strict branch: an executable private VAD with an MZ header and no backing file is the signal. Managed-runtime and browser hosts take the JIT branch: the same protection bits are normal there, so the branch shifts to PEB-list discrepancy, image-path mismatch and thread-start-address resolution.
3. **Establish the baseline-versus-probe differential at image level.** For every candidate PID, compare the VAD-backed mapped image set against the PEB loader lists and against the same binary's header on disk. The probe is the candidate process; the baseline is the same binary on a clean host of the same build, plus every other instance of that binary in the same image. A region type that appears in all instances is a runtime property; a region type confined to one instance is the anomaly.
4. **Name the stop condition before scoring anything.** Stop and declare `Inconclusive` when symbols do not resolve, when the migration to `windows.malware.*` has not been applied and the legacy name silently returns nothing on your build, when VAD contents are absent because the dump is a minidump, or when the only evidence is a protection bit in a runtime that legitimately produces executable private pages.
5. **State what counts as proof.** Proof of injection is two independent structures disagreeing in a way that has no benign explanation: a mapped image present in the VAD tree but absent from all three PEB lists, or a private executable VAD containing an MZ header whose mapped file object is `DeletePending`, or a thread whose start address lies outside every mapped image. Proof of hollowing additionally needs the on-disk image header of the same path to differ from the in-memory mapped header — a hash comparison, not a string comparison.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Mapped image in the VAD tree absent from all three `windows.ldrmodules` PEB lists | `_EPROCESS` VAD versus PEB loader list | Proves a module was mapped into the process address space while hidden from the loader enumeration on Windows; the gap itself is the finding, not the module |
| Private `PAGE_EXECUTE_READWRITE` VAD beginning with `MZ` and backed by no file object | VAD tree plus region header bytes | Proves reflective loading or manual mapping on Windows when the host runtime does not JIT; a JIT cache region carries the same protection without the MZ header |
| `_EPROCESS` found by `windows.psscan` but absent from `windows.pslist`, with a live thread | Pool-scanned versus list-walked process enumeration | Proves an unlinked process still resident in memory on Windows; proves it was hidden, not that it was malicious |
| Image `_FILE_OBJECT.DeletePending` set, or `ImageFilePointer` null, in `windows.processghosting` | `_EPROCESS` image file object state | Proves the delete-on-close / ghosting pattern on NTFS-backed Windows: the image was unlinked from disk before or during execution |
| PEB image path disagreeing with the VAD-backed image path for the same process | `windows.pebmasquerade` plus VAD backing | Proves the process is reporting a forged path to user-mode callers on Windows; the real backing file is the identity that matters |
| Thread start address outside every mapped image and outside every known unbacked region | Thread enumeration versus VAD map | Proves a thread was started at an address with no legitimate image origin on Windows, i.e. shellcode in a private region |

## Worked Contrast

**Flawed Triage Practice — Reading Protection Bits as Intent:**

```yaml
# ANTI-PATTERN: every RWX VAD is called injection.
triage_shortcut:
  plugin: windows.malfind
  decision: if any region is PAGE_EXECUTE_READWRITE then injected
  ignored:
    - runtime_class          # .NET CLR, JVM, V8, node, Electron all emit RWX code caches
    - peb_list_comparison    # no ldrmodules run at all
    - backing_file           # never asks which file object the region maps
    - second_instance        # never compares to another instance of the same binary
# Outcome: every browser and every managed service trips the rule; analysts
# then whitelist the plugin wholesale and lose the signal entirely.
```

**Verified Practice — Runtime-Aware Differential Across Independent Structures:**

```python
# injection_differential.py — compare VAD-backed images against PEB lists, per PID.
# Every plugin below is read-only against the image; nothing is written back.
import json, subprocess

IMG = "host.dmp"
VOL = ["vol", "-f", IMG, "--renderer", "json"]          # 2.27.0+ ships a JSON renderer

def run(plugin, *args):
    out = subprocess.run(VOL + [plugin, *args], capture_output=True, text=True, check=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]

jits = {"chrome.exe", "msedge.exe", "firefox.exe", "java.exe", "node.exe", "TeamViewer.exe"}

for proc in run("windows.pslist"):
    pid, name = proc["PID"], proc["ImageFileName"]
    vad  = {r["File output"] for r in run("windows.vadinfo", "--pid", str(pid)) if r.get("File output")}
    ldr  = run("windows.ldrmodules", "--pid", str(pid))
    hidden = [m["MappedPath"] for m in ldr
              if m.get("MappedPath") and not (m.get("InLoad") and m.get("InInit"))]
    if not hidden:
        continue                                    # agreement: nothing to reconcile
    tag = "JIT-branch" if name in jits else "STRICT"
    print(f"[{tag}] pid={pid:<6} {name:<20} hidden_from_loader={len(hidden)}")
    for path in hidden:
        print(f"    vad_mapped={path} in_vad_pool={'yes' if path in vad else 'NO'}")
```

**Why this matters:** the weak form converts a page permission into a verdict and then has to be disabled because it fires on every managed runtime. The strong form branches on the process runtime first, then reports a specific structural disagreement — a VAD-mapped image the loader cannot see — and prints the corroborating detail beside each row so a reviewer can tell a genuine gap from a parser artefact.

## When It Is NOT This Issue

- **Managed-runtime and browser code caches:** the CLR, JVM, V8 and Node all commit private executable pages and rewrite them constantly. In these processes a `malfind` hit is the expected steady state; the finding only exists if a PEB-list or image-path discrepancy accompanies it.
- **`psscan`-only processes that are simply gone:** a process absent from `pslist` but present in `psscan` with an `ExitTime` set is a terminated process whose pool page has not been reused. Hidden and exited look identical in the PID column alone; the exit time and thread liveness separate them.
- **Legitimate manual mapping and protected processes:** anti-cheat, DRM and some EDR components map images outside the loader, and protected-process images are readable but not enumerable in the usual way. Establish whether a security product owns the process before treating the gap as adversarial.
- **Installer and unpacker staging regions:** self-extracting installers and packers allocate executable private memory during startup and release it. A region with a short lifetime, seen once, in a process whose on-disk image matches its in-memory header, is staging rather than injection.
- **A plugin run under the wrong name:** after the 2.26.2 relocation, invoking the legacy `windows.malfind` on a build where only `windows.malware.malfind` is present returns nothing that reads like a clean process. Confirm the plugin resolved before interpreting any zero.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `malfind` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Plugin family resolved:** every plugin cited in the finding executed successfully under this Volatility build, with the `windows.malware.*` relocation accounted for and the resolved plugin name recorded.
- [ ] **Runtime branch declared:** each candidate process is labelled strict or JIT, and no JIT-host hit is reported as injection without a second independent structure disagreeing.
- [ ] **Second-instance baseline run:** the anomalous region or loader gap was compared against another instance of the same binary in the same image, not only against intuition.
- [ ] **Identity reconciled:** the in-memory mapped image header or hash was compared against the on-disk binary, so a path string is never treated as identity.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: memory-forensics-process-and-injection-analysis
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`process-injection-techniques`](../../../red-team/network-ad-and-endpoint/process-injection-techniques/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)
- [`memory-forensics-network-and-credential-artifacts`](../memory-forensics-network-and-credential-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Structure before signal:** a protection bit is one structure's opinion. A finding needs two structures disagreeing, and the report should name both.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; dumping a region for analysis writes a new file and must never overwrite the image or the acquisition directory.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/atomic_red_team (1), CYBER_CPT/ired_team (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
