---
name: log-and-timeline-analysis
description: "Builds and analyses timelines across multiple sources: normalization, super-timelining and correlating events to establish sequence. Use when reconstructing what happened and in what order."
family: digital-forensics
tier: core
triggers: ["timeline analysis", "super timeline", "log correlation", "event sequencing"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Log and Timeline Analysis - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

A timeline is a set of events from heterogeneous sources placed on one axis, and every source on that axis has its own clock, epoch and precision — which is why a timeline is an argument rather than a table. NTFS stores 100-nanosecond FILETIME as UTC; HFS+ and APFS store seconds since 2001-01-01 UTC; most Unix sources store epoch seconds, while some store microseconds and the journal stores microseconds with a boot ID; WebKit stores microseconds since 1601. Mixing any two of these without conversion produces a plausible-looking order that is wrong by centuries, and the error is invisible in the output because every row still renders as a date. The tooling matters less than the semantics: a bodyfile-based filesystem timeline records MACB flags per record but has documented limits and, on Linux, TSK's support for creation time depends on the filesystem and version, so a `crtime` that appears as zero may mean "not recorded" rather than "not created". Plaso extracts once into a storage file and filters many times, which makes it the right tool for a super timeline but also means the quality of the result is fixed at extraction; `pinfo.py` reporting parser warnings is part of the evidence, not boilerplate. Two further properties constrain what a timeline can claim: ordering is only as precise as the least precise source, so a second-resolution syslog line cannot be ordered against a microsecond journal entry beyond "before or after by less than a second"; and simultaneous-looking events are often causally ordered by something the timestamp does not carry, such as a USN or an LSN, which is why the ordered record number of the source is often better evidence than the clock. A timeline proves sequence and co-occurrence. It never proves causation, and it cannot repair a missing source.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sources span more than one OS or format **THEN** convert everything to UTC first and record the conversion for each source class (FILETIME, Mac absolute, epoch seconds, epoch microseconds, WebKit); **IF** a source has no zone information at all **THEN** treat its place in the order as inferred and mark it.
2. **IF** the question is "what happened in order" **THEN** build a super timeline with extraction kept separate from filtering, so the same extraction can answer a second question without a second run; **IF** the question is "was this file touched" **THEN** a filesystem bodyfile plus the specific log source is cheaper and more precise than a full super timeline.
3. **IF** a source records an ordered identifier (USN, `EventRecordID`, LSN, journal `__SEQNUM`) **THEN** use it to resolve same-second ties and say that you did; **IF** it does not **THEN** present same-second events as unordered relative to each other.
4. **IF** two sources disagree **THEN** check clock state before anything else: read NTP or `systemd-timesyncd` adjustments in the journal, the boot time from multiple sources, and whether the host's clock jumped during the window.
5. **IF** an event's timestamp is implausible (before the OS install, after acquisition, or exactly midnight on many rows) **THEN** treat it as a parsing or epoch error until proven otherwise — bulk identical timestamps are a converter artifact, not mass activity.
6. **IF** the timeline is built from a bodyfile **THEN** state its limits: no content, filesystem-dependent creation time, and MACB collapsing that hides which timestamp set a value came from.
7. **IF** telemetry source covering `super timeline` / `normalization` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extraction and filter commands | [`QUERIES.md`](QUERIES.md) | One class per timeline source |
| Need Plaso, TSK and journald flag reference | [`TOOLS.md`](TOOLS.md) | Extraction, filtering, slicing |
| Need the per-OS artifact semantics underneath | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md), [`linux-forensics`](../linux-forensics/SKILL.md), [`macos-forensics`](../macos-forensics/SKILL.md) | Source-specific meaning |
| Need the disk structures the timeline came from | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | MFT, inodes, offsets |
| Need the SIEM-side equivalent for a live feed | [`siem-query-and-log-analysis`](../../detection-and-monitoring/siem-query-and-log-analysis/SKILL.md) | Index-time vs event-time reasoning |
| Need IR triage ordering | [`ir-triage-and-timeline`](../../incident-response/ir-triage-and-timeline/SKILL.md) | Response-side timeline ownership |
| Need scripted timeline post-processing | [`super-timeline-and-plaso-postprocessing-scripting`](../../security-automation-and-tool-development/super-timeline-and-plaso-postprocessing-scripting/SKILL.md) | Automation ownership |
| Need case shapes where ordering decided the finding | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Every source in the timeline traces to a hashed image, export or log copy, and the output names which sources were extracted and from which artifact. A timeline that mixes a verified image with an unverified export cannot be reviewed as a whole.
2. **Choose the branch from the question and the sources.** Filesystem timeline, log-only timeline, or full super timeline. Extraction is fixed at that choice; filtering is not. Write the branch and the tool versions into the output, because Plaso storage files and bodyfile semantics differ across versions.
3. **Establish a baseline-versus-probe differential.** Baseline is a quiet window of the same duration, ideally on the same host or a peer, to establish the normal event density and the normal mix of sources. Probe is the incident window. A burst of events means nothing without the baseline density beside it.
4. **Name the stop condition.** Declare `Inconclusive` when a source needed for ordering was not extracted, when clock skew between sources exceeds the precision the claim requires, when a parser reported warnings for the artifacts in question, when a bodyfile collapsed the timestamp set that mattered, or when the only ordering evidence is a source that records no ordered identifier.
5. **State what counts as proof.** Proof of sequence is two sources agreeing on order with an explicit tolerance, or one source's ordered identifier bounding a second source's clock. Proof of co-occurrence is two independent sources naming the same object inside one stated interval. Neither establishes causation, and the report must not imply that it does.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `timestamp_desc` and `macb` fields in a Plaso dynamic export | Plaso storage event attributes | Which timestamp an event represents; without it a row's time is uninterpretable because creation and modification are different claims |
| Bodyfile line with `MACB` flags and four epoch values | TSK bodyfile | Filesystem times as the filesystem reported them; creation time is filesystem- and version-dependent and may be zero |
| `__SEQNUM` and `__REALTIME_TIMESTAMP` in a journal export | systemd journal JSON | Order within the journal independent of clock, plus the recorded UTC time |
| `UpdateSequenceNumber` and `UpdateTimestamp` in a USN export | NTFS change journal | Order of filesystem changes on that volume, which resolves same-second ties from other sources |
| `EventRecordId` monotonic within a channel | Windows EVTX | Order of events in that channel, and the presence of gaps that a timestamp cannot show |
| Events whose timestamps are identical to the second across unrelated sources | Normalisation artifact | A converter collapsed precision rather than the events being simultaneous; check the source's real resolution |
| `pinfo.py` warning count and parser list for a storage file | Plaso extraction metadata | Which artifacts were parsed and which produced warnings, i.e. the extraction's coverage and its known weak points |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# Sorts mixed sources by their rendered strings and reads the order off the page.
grep -hE '2026-1[01]-' *.csv | sort | head -40
# Different sources carry different epochs, precisions and zones; string sorting
# of rendered dates orders them by text, not time, and hides a whole-century
# epoch error because every row still looks like a date.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
SRC=/cases/31; OUT=$SRC/timeline; mkdir -p "$OUT"

# 1. Extract once; keep the storage file so later questions need no re-run.
log2timeline.py --storage-file "$OUT/case.plaso" "$SRC/disk.dd"
pinfo.py "$OUT/case.plaso" | tee "$OUT/extraction-report.txt"

# 2. Filter many times, always in UTC, always with the timestamp semantics kept.
psort.py -q -o dynamic --output_time_zone UTC --fields datetime,timestamp_desc,source,message \
  -w "$OUT/window.csv" "$OUT/case.plaso" \
  "date > '$START' AND date < '$END'"

# 3. Density baseline for the same duration, outside the incident window.
psort.py -q -o dynamic --output_time_zone UTC --fields datetime,source \
  -w "$OUT/baseline.csv" "$OUT/case.plaso" \
  "date > '$BASE_START' AND date < '$BASE_END'"

awk -F, 'NR>1 {c[$2]++} END {for (s in c) print c[s], s}' "$OUT/baseline.csv" | sort -rn | head
echo "compare per-source density in window.csv against this baseline"
```

**Why this matters:** the strong form extracts once and filters in UTC with `timestamp_desc` retained, records the extraction report so parser warnings travel with the evidence, and produces a same-length baseline density — the differential that turns "a lot of events" into a finding.

## When It Is NOT This Issue

- **Clock skew and boot-time disagreement:** a host whose clock jumped during the window, or a VM whose clock follows the hypervisor, will place correct events at wrong times. Read the time service's own log before treating a two-minute inversion as tampering.
- **Epoch and precision confusion:** WebKit, FILETIME, Mac absolute and epoch seconds render as plausible dates when converted with the wrong base, and a whole-decade offset is the signature. Check one known event on each source class against an independent record.
- **Timezone rendering in the exporter:** a tool that renders local time without recording the offset produces a uniform shift that looks like a real gap when compared against a UTC source. The report must state the rendering for each column.
- **Retention and rotation boundaries:** each source starts and stops at its own configured limit, so a timeline's edges are ragged by design. An absent source at the start of the window is a retention fact until proven otherwise.
- **Normal filesystem maintenance at boot:** package upgrades, `updatedb`, log rotation and antivirus scans produce dense bursts at predictable times. Compare against the baseline window before treating a burst as activity.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `super timeline` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** every contributing source traces to a hashed artifact, and the extraction report is stored with the timeline.
- [ ] **Normalisation stated:** each source class's epoch and precision is named, and the output says whether any timestamp had to be inferred.
- [ ] **Differential defined:** a same-length baseline window was extracted and its per-source density compared against the incident window.
- [ ] **Stop condition cleared or declared:** clock skew, parser warnings, collapsed timestamp sets and missing sources were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: log-and-timeline-analysis
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `log-and-timeline-analysis` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — extraction runs against image copies, storage files are written outside the evidence volume, and no source log is ever edited to improve a timeline.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (3), Forensic_Toolkit_Dataset (2), CYBER_CPT/ctf_search (2), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 2 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
