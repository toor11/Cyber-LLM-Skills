---
name: windows-artifact-forensics-file-system-artifacts
description: Windows filesystem artefacts. Covers MFT, USN journal, $LogFile and recycle bin analysis for file creation, deletion and timestomping evidence. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["mft forensics", "usn journal analysis", "recycle bin forensics"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [windows-artifact-forensics, windows-artifact-forensics-registry-artifacts, windows-artifact-forensics-execution-artifacts, windows-artifact-forensics-event-log-artifacts]
parent: windows-artifact-forensics
---

# Windows Artifact Forensics File System Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

NTFS records file metadata in three places that disagree in useful ways. The `$MFT` holds one 1 KB record per file with two timestamp sets: `$STANDARD_INFORMATION` (0x10), which any process with write access can change, and `$FILENAME` (0x30), which is updated by the system on rename and on volume-local move. When `$SI` times precede `$FN` times, something wrote the older set deliberately — the classic timestomp — and when a timestamp's subsecond field is exactly zero, the writing tool had second-level precision, which user-mode APIs rarely produce. `$UsnJrnl:$J` is an append-only change journal: every record carries a USN, a file reference, a parent reference, a reason bitmask and a timestamp, so it records the *fact* of a metadata change independently of what the metadata now says. A `BasicInfoChange` with no accompanying data write or rename in the same handle session is the timestomping signature, and the record's timestamp is when the rewrite happened. `$LogFile` is a write-ahead log of metadata transactions that can reconstruct operations evicted from the journal. The recycle bin (`$Recycle.Bin\<SID>\$I*` and `$R*`) preserves the original path, size and deletion time of a deleted item per user. What these cannot tell you: the journal is bounded and wraps, so a busy volume can lose a week of records while keeping a month-old tail; `$SI`-versus-`$FN` comparison produces false positives on files written by installers, archive extractors and any tool that truncates timestamps to the second; and the recycle bin holds nothing for deletions that bypassed the shell.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `windows-artifact-forensics-file-system-artifacts` **THEN** start at parent class [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) first.
2. **IF** you have a disk image **THEN** parse `$MFT`, `$J` and `$LogFile` from the same volume, captured at the same time, and keep them together; **IF** you have only a triage export **THEN** confirm which of the three was actually collected before claiming a timeline.
3. **IF** the finding depends on a timestamp comparison **THEN** state which attribute pair you compared and whether the file was ever renamed or moved, because rename copies `$SI` into `$FN` and destroys the comparison.
4. **IF** the volume is busy or has been running long **THEN** record the earliest journal USN you hold and treat anything older as out of coverage rather than absent.
5. **IF** the artefact is a live host **THEN** capture `$MFT`, `$J` and the recycle bins before any cleanup or reboot, and record whether the volume was mounted read-write during collection.
6. **IF** telemetry source covering `MFT` or `USN` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `windows-artifact-forensics-file-system-artifacts` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the process that performed the file operation | [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) | Prefetch and SRUM place a process at that time |
| Need the persistence entry the file belongs to | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Run keys and services reference the path |

## Procedure

1. **Confirm which of the three metadata sources you actually hold, and their coverage boundaries.** Record the `$MFT` record count and the highest USN, then identify the oldest retained journal record. A journal whose oldest record postdates the incident cannot support a statement about the incident, and a `$LogFile` that wrapped says nothing about earlier transactions.
2. **Choose the branch from the question's tense.** "What exists now" takes the `$MFT` branch. "What changed and when" takes the `$J` branch. "What was the on-disk state before the journal wrapped" takes the `$LogFile` branch. "What did the user delete" takes the recycle-bin branch. Record the branch, because these four have different retention and cannot be substituted for one another.
3. **Establish the differential between the two timestamp sets and between the two sources.** Compare `$SI` against `$FN` per record to identify deliberate rewriting, then compare the journal's own account of the same file reference to see whether a data write preceded the metadata change. A timestamp anomaly with a matching data write is normal; a timestamp anomaly with a bare `BasicInfoChange` is the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the journal's oldest USN postdates the activity, when the file was renamed after the suspected rewrite (which copies `$SI` into `$FN` and erases the differential), when the volume was mounted read-write during collection, or when `$LogFile` had already wrapped past the window.
5. **State what counts as proof.** Proof is the journal's `BasicInfoChange` timestamp and the `$SI`-versus-`$FN` delta agreeing on the same file reference, or an `$MFT` creation time and a recycle-bin `$I` record agreeing on the same original path. Two derived columns from the same parse are one source; the journal and the MFT are two.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `$SI` created time earlier than `$FN` created time on the same `$MFT` record | `$STANDARD_INFORMATION` versus `$FILENAME` timestamps | Proves one of the two timestamp sets was rewritten on NTFS; proves the direction of the discrepancy, not which actor caused it |
| `$J` record with reason exactly `BasicInfoChange` plus `Close` and no preceding `DataOverwrite`, `DataExtend`, `FileCreate` or rename on the same file reference | USN journal record with reason bitmask | Proves a metadata-only write occurred at that timestamp on NTFS, which is how timestomping and attribute toggles both appear |
| `$MFT` record whose created time has all subsecond digits zero while its sibling records do not | FILETIME subsecond precision | Proves the timestamp was written by a tool with second-level precision, which user-mode file APIs do not produce on NTFS |
| `$Recycle.Bin\<SID>\$I` record whose original path and deletion time match a `$MFT` entry that is now unallocated | Recycle-bin metadata plus MFT record state | Proves that user deleted that path through the shell at that time; proves nothing about deletions that bypassed the shell |
| `$J` `FileDelete` followed by a `FileCreate` on the same parent with a new file reference and an identical name | USN journal sequence | Proves the name was reused after deletion, which is how log or implant rotation hides the original file's identity |
| `$MFT` entry whose allocation size and resident data contradict the file's apparent size in a directory listing | MFT attribute layout | Proves the on-disk record is inconsistent with the shell's view, which is how sparse or manipulated records surface |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: parse the MFT, sort by created time, call the oldest entry suspicious.
MFTECmd.exe -f "$MFT" --csv out
# Filter "Created < 2020" and report every hit as timestomping.
# No $FN comparison, no journal, no rename history, no subsecond check.
# Result: every installer payload, every archive extraction and every
# file copied with a preserved timestamp is reported as anti-forensics.
```

**High-Signal Grounded Artifact:**

```bash
#!/usr/bin/env bash
# timestomp-differential.sh — journal reason mask against the SI/FN delta.
set -euo pipefail
MFT="${1:?usage: $0 \$MFT \$J}"; J="${2:?journal stream required}"
OUT="${3:-./derived}"; mkdir -p "$OUT"

# 1. MFT side: the two timestamp sets and their subsecond precision.
MFTECmd -f "$MFT" --csv "$OUT" --csvf mft.csv >/dev/null
awk -F, 'NR==1 || $0 ~ /\.0000000/ {print}' "$OUT/mft.csv" | head -3   # subsecond-zeroed rows

# 2. Journal side: exact-mask BasicInfoChange with no accompanying data write.
MFTECmd -f "$J" -m "$MFT" --csv "$OUT" --csvf usn.csv >/dev/null
awk -F, 'NR>1 && $0 ~ /BasicInfoChange/ && $0 !~ /DataOverwrite|DataExtend|FileCreate/ {print $2,$4,$5}' \
  "$OUT/usn.csv" | sort -u > "$OUT/bare_basicinfochange.txt"

# 3. Join on file reference: a journal rewrite time plus an MFT delta on the same record.
awk -F, 'NR>1 {print $0}' "$OUT/mft.csv" > "$OUT/mft_rows.txt"
while read -r ts ref rest; do
  grep -m1 -- "$ref" "$OUT/mft_rows.txt" >/dev/null 2>&1 && \
    printf '%s ref=%s journal_rewrite=%s\n' "$(basename "$MFT")" "$ref" "$ts"
done < "$OUT/bare_basicinfochange.txt" | head -40
```

**Why this matters:** the weak form turns a single timestamp column into an accusation and sweeps in every installer and extractor. The strong form requires the journal's reason mask to show a metadata-only change, then joins that record to the MFT row for the same file reference, so the output carries both the fact of rewriting and the record it happened to — and the subsecond-zero column separates genuine tool-level rewriting from ordinary second-precision file creation.

## When It Is NOT This Issue

- **Installer and archive-extractor payloads:** many installers and extractors set timestamps from the archive's stored values, producing `$SI` times far in the past with zeroed subseconds. Check whether the parent directory shows a matching install burst before calling it timestomping.
- **Files copied with timestamp preservation:** `robocopy` and backup restores preserve source timestamps, so a file can legitimately have a creation time older than its parent directory. The journal shows a create without a preceding metadata rewrite in that case.
- **A journal that has wrapped:** on a busy volume the journal retains days, not months. An absent record for an old file is a coverage boundary; record the oldest retained USN before treating absence as evidence.
- **Recycle bin emptied by policy:** many estates clear the bin on logoff or by retention policy, and files deleted by an application bypass the shell entirely. An empty bin is a configuration outcome, not proof that nothing was deleted.
- **`$FN` timestamps altered indirectly by rename:** renaming or moving a file within a volume copies `$SI` `MAB` values into `$FN`, destroying the very comparison the detection relies on. Check the journal for a rename before concluding the timestamps were never tampered with.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `MFT` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Source set declared:** `$MFT`, `$J` and `$LogFile` are each recorded as collected or missing, with the volume they came from and whether they were captured together.
- [ ] **Coverage boundary quoted:** the highest USN and the oldest retained journal record are stated, and every absence claim is checked against them.
- [ ] **Rename history checked:** any file used in a timestamp comparison was checked for a rename or volume-local move that would copy `$SI` into `$FN`.
- [ ] **Two sources joined:** the finding joins a journal record to an MFT record on the same file reference, rather than deriving both columns from one parse.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: windows-artifact-forensics-file-system-artifacts
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-execution-artifacts`](../windows-artifact-forensics-execution-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`windows-artifact-forensics-event-log-artifacts`](../windows-artifact-forensics-event-log-artifacts/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Coverage before conclusion:** the journal's retention boundary, not its content, decides which absences mean anything. Print the boundary first and keep it in the report.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; parse from a read-only image or a copy, and never run recovery tools against a mounted evidence volume.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/github_security_md (1), CYBER_CPT/vmware_security (1), CYBER_CPT/cisa_kev (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
