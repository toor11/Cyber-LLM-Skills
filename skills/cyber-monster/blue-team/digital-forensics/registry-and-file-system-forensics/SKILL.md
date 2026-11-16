---
name: registry-and-file-system-forensics
description: "Analyses registry and filesystem structures: hive parsing, key timestamps, MFT and $LogFile analysis, and timeline correlation. Use when precise file and configuration history is needed."
family: digital-forensics
tier: core
triggers: ["registry analysis", "mft analysis", "hive parsing", "filesystem timeline"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Registry and File System Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

This skill is about joining two independently-maintained metadata systems into one defensible timeline. The registry side is a tree of 4 KB bins and cells: each key cell carries a `LastWrite` timestamp updated when that key's own contents change, and since Windows 8.1 each hive has `.LOG1`/`.LOG2` transaction logs that absorb writes before the primary file is flushed, which is why a hive copied from a running system is often dirty and behind its logs. The filesystem side on NTFS is the `$MFT` with two timestamp sets per record — `$STANDARD_INFORMATION` writable by any process, `$FILENAME` updated by the system on rename and volume-local move — plus the `$UsnJrnl:$J` change journal, which appends a record per change with a reason bitmask, a file reference and a timestamp, and `$LogFile`, a small circular write-ahead log of metadata transactions. The join is where the value lives: a registry `LastWrite` says a key changed, the journal says a file changed, and neither alone says which process did either. What these structures cannot tell you: `LastWrite` is not a creation date and does not move when a subkey's contents change; the journal wraps and its earliest record is a hard coverage boundary; `$LogFile` wraps faster still; and a hive without its logs presents a state that may predate the incident by an unknown interval. On non-NTFS volumes the journal and `$MFT` equivalents differ, so state the filesystem before applying any of this.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you have a Windows image or triage set **THEN** confirm the filesystem is NTFS before applying `$MFT` or `$J` logic; **IF** it is FAT, exFAT or ReFS **THEN** stop and declare that these structures do not exist rather than parsing an absent artefact.
2. **IF** a hive is dirty and you hold no `.LOG1`/`.LOG2` **THEN** declare the hive stale and refuse any "value absent" claim; **IF** the logs are present **THEN** replay into a clean copy and hash both.
3. **IF** the case asks when a file appeared **THEN** use `$MFT` creation times and check for a matching journal `FileCreate`; **IF** the two disagree **THEN** treat the journal as the record of the event and the MFT as the record of the current state.
4. **IF** the case asks when a key changed **THEN** use `LastWrite` and pivot to Sysmon 12/13/14 or Security 4657 for the process; **IF** neither exists **THEN** report the change without an actor.
5. **IF** the volume is a system volume that has been running for weeks **THEN** print the journal's oldest and newest USN before drawing any conclusion from an absence.
6. **IF** telemetry source covering `NTUSER.DAT` or `MFT` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `registry-and-file-system-forensics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need Windows-artefact-specific interpretation of a hive key | [`windows-artifact-forensics-registry-artifacts`](../windows-artifact-forensics-registry-artifacts/SKILL.md) | Key semantics, device history, per-user attribution |
| Need the timestomp differential in depth | [`windows-artifact-forensics-file-system-artifacts`](../windows-artifact-forensics-file-system-artifacts/SKILL.md) | `$SI` vs `$FN` against journal reason masks |

## Procedure

1. **Confirm the volume's filesystem, the hive set and the log presence before parsing.** Record the filesystem type, the hive hashes with `.LOG1`/`.LOG2` presence, the `$MFT` record count and the `$J` USN range. On a non-NTFS volume, the journal and `$MFT` branches do not exist at all, and continuing anyway produces empty output that reads like a quiet volume.
2. **Choose the branch from the question's subject.** Configuration history takes the hive branch (replay, then read keys with `LastWrite`). File lifecycle takes the journal branch. Pre-change state takes the `$LogFile` branch. Cross-source sequence takes the join branch, in which every row carries both its registry and filesystem provenance.
3. **Establish the differential against the artefact's own boundary and against a peer.** For each candidate, print the oldest record the artefact retains and the corresponding entry on a same-build peer host. A key or record present identically on the peer and inside both retention windows is baseline; only what is new to this host and inside coverage is a finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the hive is dirty without logs, when the journal's oldest USN postdates the activity, when `$LogFile` has wrapped past the window, when the volume is not NTFS and the branch does not apply, or when the file was renamed after the suspect timestamp so the `$SI`/`$FN` comparison is destroyed.
5. **State what counts as proof.** Proof is a registry `LastWrite` and a journal record or an event-log registry-write event naming the same key or path inside one stated tolerance, with the process identified from the event rather than inferred from the timestamp. Two rows derived from one hive parse are one source.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Key `LastWrite` inside the incident window joined to a Sysmon 12/13 or Security 4657 record for the same key path | Registry key timestamp plus registry-write event | Proves the key changed at that time on Windows and names the writing process, which `LastWrite` alone cannot |
| Journal `FileCreate` for a path whose `$MFT` record carries a creation time within a second of the journal timestamp | NTFS journal plus MFT record | Proves the file was created on that NTFS volume at that time and that both metadata systems agree, which rules out a copy with preserved times |
| Directory `$MFT` record whose `$FN` timestamps predate every child record's creation | MFT attribute comparison within one directory | Proves the directory's name timestamps were carried from another volume or rewritten, because a genuinely new directory cannot predate its own contents |
| `$LogFile` transaction reconstructing a rename that the current journal no longer holds | NTFS write-ahead log | Proves the rename occurred before the journal's retained window, extending the timeline backwards into a period the journal cannot cover |
| Hive key present in the replayed state but absent from the primary file | Transaction-log delta on a dirty hive | Proves the value was written after the last flush of the primary hive — the state an unreplayed parse would have reported as absent |
| Journal record count for one file reference exceeding the baseline for its directory class by an order of magnitude | USN record density per reference | Proves repeated metadata manipulation on one file, which is how incremental tampering appears without a single decisive record |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: two parses, one spreadsheet, timestamps sorted together.
RECmd.exe -d E:\case\config --bn Kroll_Batch.reb --csv E:\csv
MFTECmd.exe -f E:\case\$MFT --csv E:\csv
# Concatenate both CSVs, sort by timestamp, and read the result as a timeline.
# The registry timestamps are key-change times, the MFT timestamps are current
# attribute state, neither has a retention boundary recorded, no hive was
# checked for dirtiness, and nothing distinguishes a change from a creation.
```

**High-Signal Grounded Artifact:**

```bash
#!/usr/bin/env bash
# reg-fs-join.sh — replay gate, boundary print, then a provenance-tagged join.
set -euo pipefail
CFG="${1:?usage: $0 <config-dir> <\$MFT> <\$J>}"
MFT="${2:?}"; J="${3:?}"; OUT="${4:-./derived}"; mkdir -p "$OUT"

# 0. Each source states its own boundary before any row is quoted.
for h in SYSTEM SOFTWARE; do
  [ -f "$CFG/$h" ] || continue
  if [ ! -f "$CFG/$h.LOG1" ] && [ ! -f "$CFG/$h.LOG2" ]; then
    echo "STALE: $h has no transaction logs; newest values may be absent" | tee -a "$OUT/gaps.txt"
  fi
done
MFTECmd -f "$J" -m "$MFT" --csv "$OUT" --csvf usn.csv -q
USN_MIN=$(awk -F, 'NR>1 {print $2}' "$OUT/usn.csv" | sort -n | head -1)
USN_MAX=$(awk -F, 'NR>1 {print $2}' "$OUT/usn.csv" | sort -n | tail -1)
echo "journal coverage: USN $USN_MIN .. $USN_MAX" | tee "$OUT/coverage.txt"

# 1. Registry side: keys with LastWrite, provenance tagged.
RECmd.exe -d "$CFG" --bn "BatchExamples/Kroll_Batch.reb" --csv "$OUT" -q
awk -F, 'NR>1 && $0 ~ /CurrentVersion\\Run/ {print "REG|"$NF"|"$(NF-1)}' "$OUT"/*.csv 2>/dev/null \
  | sort -u > "$OUT/reg_rows.txt"

# 2. Filesystem side: created files with their MFT identity.
awk -F, 'NR>1 && $0 ~ /FileCreate/ {print "NTFS|"$2"|"$5}' "$OUT/usn.csv" | sort -u > "$OUT/fs_rows.txt"

# 3. Join report: each line carries which system asserted it.
{ sed 's/^/registry: /' "$OUT/reg_rows.txt"; sed 's/^/filesystem: /' "$OUT/fs_rows.txt"; } \
  | sort -t'|' -k2 > "$OUT/provenance_tagged.txt"
head -40 "$OUT/provenance_tagged.txt"
```

**Why this matters:** the weak form merges two CSVs into one sorted list, which silently equates a key-change time with a live attribute value and loses every retention boundary in the process. The strong form makes each source declare its own coverage, tags every row with the system that asserted it, and keeps the journal range visible — so a reviewer can see that a registry row and a filesystem row are different kinds of claim and whether either was inside the window it purports to describe.

## When It Is NOT This Issue

- **A non-NTFS volume:** FAT, exFAT and ReFS do not have `$MFT`, `$UsnJrnl` or `$LogFile` in the NTFS sense. An empty parse on such a volume is a category error, not evidence of a clean filesystem.
- **A hive parsed without its transaction logs:** the reported state predates the incident by an unknown interval. Any "value absent" conclusion from such a parse is unsupported, and the parse itself will look perfectly normal.
- **A `LastWrite` older than the current control set:** the key belongs to an abandoned control set and never applied to the running system. Confirm `Select\Current` before treating any `Services` metadata as live configuration.
- **A directory whose timestamps predate its contents:** this is normal for directories created by copying, restoring from archive, or extracted from an installer that preserves stored times. Require a journal record showing the directory was created locally before calling it tampering.
- **Journal absence on a freshly formatted volume:** the journal may be disabled or newly created, so a tiny USN range reflects the volume's age rather than deliberate clearance. Check the volume's creation metadata first.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `NTUSER.DAT` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Filesystem type stated:** the volume's filesystem is recorded, and the `$MFT`/`$J`/`$LogFile` branches were only applied to NTFS.
- [ ] **Replay state recorded:** each hive's `.LOG1`/`.LOG2` presence is documented, and any hive parsed without them is flagged as stale.
- [ ] **Boundaries printed:** the journal's USN range and the `$LogFile` earliest entry are quoted beside every absence claim.
- [ ] **Provenance tagged per row:** each timeline row names whether it came from a key timestamp, an MFT attribute, a journal record or a logfile transaction.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: registry-and-file-system-forensics
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)
- [`macos-forensics`](../macos-forensics/SKILL.md) - Digital Forensics (core)
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)

## Operating Notes

- **Two systems, two claim types:** a key timestamp and a file timestamp are not interchangeable and must never be merged into one sorted column without a provenance tag.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; parse from an image or a copy behind a write blocker, and never mount an evidence volume read-write.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (3), CYBER_CPT/hacktricks (1), CYBER_CPT/ctf_search (1), CYBER_CPT/netlab_360 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
