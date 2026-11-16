---
name: macos-forensics
description: "Analyses macOS hosts: unified logging, launch services persistence, quarantine events, FSEvents and TCC database artefacts. Use when examining a macOS system."
family: digital-forensics
tier: core
triggers: ["macos forensics", "unified log", "fsevents", "launchd forensics"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, memory-forensics]
---

# Macos Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

macOS spreads its evidence across structures with incompatible time bases and very different retention, which is why a macOS timeline built without per-artifact conversion is almost always wrong at the edges. The unified log is a compressed `tracev3` store under `/private/var/db/diagnostics/` written by `logd`; reading it requires Apple's tooling or a parser that understands the format, and its retention is governed by a configuration profile rather than by a simple file cap, so a short log is a policy fact and not necessarily deletion. `FSEvents` under `.fseventsd` at the volume root records file-system change batches with a path, flags and a monotonically increasing 64-bit event ID — and crucially **no wall-clock time per event**, only the flush time of the gzip file that holds it, so anchoring an FSEvents record to a clock requires another source. KnowledgeC and the newer Biome streams hold passive app-focus, Safari and device-activity records at sub-second precision, retained for weeks. Quarantine is a pairing of two artifacts: the `com.apple.quarantine` extended attribute (`flags;hex-time;agent;UUID`) and a row in `QuarantineEventsV2` keyed by the same UUID, so a downloaded file whose xattr is missing has either had it stripped or never went through a quarantining path such as `curl` or `git`. TCC grants live in two SQLite databases — per-user under `~/Library/Application Support/com.apple.TCC/` and system-wide under `/Library/Application Support/com.apple.TCC/` — with `last_modified` in Unix epoch, and a grant written outside a consent prompt (for example while SIP was disabled) is a loud signal. Launch persistence is plist-based in `/Library/LaunchDaemons`, `/Library/LaunchAgents` and per-user `~/Library/LaunchAgents`, and APFS makes all of this harder: snapshots, clones and the sealed system volume mean a file may exist in several states, and an unsigned or ad-hoc-signed binary may run through Rosetta 2 with its execution recorded only in the unified log and, historically, in the AOT cache directory structure visible via FSEvents.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the host is live **THEN** collect a `sysdiagnose`, copy the unified log with `log collect`, and capture memory-bearing state before any reboot, since `logd`'s store rolls and shutdown rewrites several databases; **IF** the host is an APFS image **THEN** check for local snapshots first, because an older snapshot may hold the pre-incident state.
2. **IF** the question involves a file's arrival **THEN** join the `com.apple.quarantine` xattr to `QuarantineEventsV2` by UUID and convert `LSQuarantineTimeStamp` from Mac absolute time (seconds since 2001-01-01 UTC), while remembering the xattr's own second field is a hex Unix-epoch value — two different epochs in one artifact.
3. **IF** the question involves ordering filesystem changes **THEN** use FSEvents event IDs for order and another source for time, and never write "FSEvents at 14:23" without naming the anchor that produced that time.
4. **IF** the question involves execution **THEN** read the unified log for process and Rosetta 2 events, the AOT cache directory for translated binaries, and launchd plists for persistence; a binary that ran once and left no other trace may exist only in the unified log, which makes log retention the deciding factor.
5. **IF** the question involves privacy grants **THEN** read both TCC databases and compare `last_modified` against the consent prompt history in the unified log; a grant with no prompt entry is the finding.
6. **IF** the artifact is a SQLite database (TCC, knowledgeC, QuarantineEventsV2) **THEN** copy it with its `-wal` and `-shm` and open the copy `immutable=1`, exactly as on any other platform.
7. **IF** telemetry source covering `unified log` / `FSEvents` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need log, FSEvents and TCC commands | [`QUERIES.md`](QUERIES.md) | One class per artifact family |
| Need parser and collection tool flags | [`TOOLS.md`](TOOLS.md) | `log`, mac_apt, APOLLO, TSK |
| Need persistence technique context | [`host-persistence-linux-and-macos-persistence`](../../../red-team/network-ad-and-endpoint/host-persistence-linux-and-macos-persistence/SKILL.md) | Red counterpart |
| Need the filesystem structures underneath | [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) | APFS, offsets and carving |
| Need cross-source ordering | [`log-and-timeline-analysis`](../log-and-timeline-analysis/SKILL.md) | Normalisation ownership |
| Need volatile process evidence | [`memory-forensics`](../memory-forensics/SKILL.md) | Memory acquisition on macOS |
| Need scripted database extraction | [`sqlite-wal-and-browser-artifact-scripting`](../../security-automation-and-tool-development/sqlite-wal-and-browser-artifact-scripting/SKILL.md) | Automation ownership |
| Need real macOS intrusion case shapes | [`SCENARIOS.md`](SCENARIOS.md) | Case cards |

## Procedure

1. **Confirm the evidence source and its integrity.** Record whether the source is a live host, a `sysdiagnose`, a log archive, an APFS image or a Time Machine snapshot, and hash whatever you copy. On APFS, record which volume and which snapshot the artifacts came from, because the same path can have several states.
2. **Choose the branch from the artifact family and the question.** Unified log for process and system events; FSEvents for change history; knowledgeC/Biome for user activity; TCC for privacy grants; quarantine for downloads; launchd plists for persistence. Write the branch and the retention facts into the output.
3. **Establish a baseline-versus-probe differential.** Baseline is a peer Mac of the same OS build and management profile, or the host's own earlier period. Probe is the incident window. A launch agent is a finding when the baseline set does not contain it and no installer receipt owns it.
4. **Name the stop condition.** Declare `Inconclusive` when the unified log's retention profile does not reach the window, when FSEvents has no anchor for the period, when the SQLite sidecars were lost so recent rows are unrecoverable, when an APFS snapshot covering the window is absent, or when the artifact is a projected or synced state rather than local.
5. **State what counts as proof.** Proof is two independent artifacts agreeing inside a stated tolerance: a quarantine row plus the file's creation time from the filesystem; a TCC grant plus its consent prompt in the unified log; an FSEvents path change plus a knowledgeC app-focus record naming the same application. One artifact proves its own existence, not the activity around it.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| `com.apple.quarantine` value of `flags;hex-time;agent;UUID` on a downloaded file | Extended attribute (APFS/HFS+) | The file came through a quarantining path at the hex-encoded Unix time, by that agent; a missing xattr suggests stripping or a non-quarantining fetch |
| `QuarantineEventsV2` row with matching UUID and `LSQuarantineTimeStamp` | SQLite at `~/Library/Preferences/` | The same download with its originating URL and agent; the two epochs must both be converted before comparison |
| FSEvents batch containing a path with create and rename flags, at a known event ID | `.fseventsd` gzip batch files | The change occurred at that point in the volume's change sequence; the time comes from the batch's flush time, not the event |
| TCC row with `last_modified` and no matching consent prompt in the unified log | TCC.db (user and system) | A privacy grant exists that no user prompt explains, which on macOS is a high-signal indicator |
| launchd plist in `~/Library/LaunchAgents` with `RunAtLoad` and a path in a temp directory | Property list on APFS | A per-user persistence mechanism exists; whether it ran is a separate claim needing log or execution evidence |
| Unified log entries from the Rosetta 2 daemon for a binary translation event | `tracev3` unified log | An x86-64 binary was translated and launched at that time, which is often the only execution evidence for such a binary |
| knowledgeC `/app/inFocus` and `/app/usage` records spanning the incident window | `knowledgeC.db` (Mac absolute time) | Which application was focused and for how long, passively recorded by CoreDuet |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`unified log`):**

```text
# Reads only the newest entries from a live host, with no retention statement.
log show --last 10m | grep -i malware
# Ten minutes of a store whose retention is policy-driven; a grep over message
# text rather than predicate fields; and no statement of what the retention
# profile actually keeps, so absence reads as innocence.
```

**High-Signal Grounded Artifact:**

```bash
set -euo pipefail
CASE=/cases/41; mkdir -p "$CASE"

# 1. Retention and coverage first: what does this host actually keep?
log show --style syslog --last 1d --predicate 'subsystem == "com.apple.quarantine"' \
  > "$CASE/quarantine-audit.log" 2>/dev/null || echo "GAP: quarantine subsystem silent"

# 2. Query by predicate fields, UTC, with the timestamp preserved.
log show --start "$START" --end "$END" --style json \
  --predicate 'process == "runningboardd" OR process == "launchd"' \
  > "$CASE/exec.json"
jq -r '.[] | [.timestamp, .processImagePath, .eventMessage] | @tsv' "$CASE/exec.json" | head -30

# 3. Corroborate with the on-disk artifacts that outlive the log.
sqlite3 "file:$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2?immutable=1" \
  "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineDataURLString
   FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 20;"
xattr -p com.apple.quarantine /Applications/Suspicious.app 2>/dev/null || echo "xattr absent"
```

**Why this matters:** the strong form states coverage before it queries, filters on predicate fields rather than message text, preserves timestamps for correlation, and pairs the log with the on-disk quarantine artifacts that survive log retention.

## When It Is NOT This Issue

- **Spotlight, Time Machine and iCloud activity:** these touch files, update their own databases and produce FSEvents and knowledgeC churn on a schedule. A burst of file changes with a backup window around it is expected.
- **Rosetta 2 and JIT translations:** a translated binary's AOT cache writes and the daemon's log entries are normal on Apple silicon. They become interesting only alongside another execution indicator for the same path.
- **Quarantine flag rewriting on Gatekeeper approval:** approving a downloaded app rewrites the flag (`0081` to `00c1`) and leaves the xattr in place, and a file fetched by `curl`, `git` or `scp` never gets one. Neither is evidence of stripping.
- **Retention profiles and log rollover:** a short unified log is a configuration profile fact. Read the profile before treating a gap as tampering, and note that some subsystems are far noisier than others and therefore roll faster.
- **Synced state from another device:** iCloud Drive and managed profiles place files and preferences on the host without local user action, and a TCC grant can be deployed by MDM. Check the management profile before attributing a grant to the user.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `unified log` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the acquisition form (live, sysdiagnose, log archive, APFS image, snapshot) is stated, and every copy carries a recorded SHA-256.
- [ ] **Retention stated:** the unified log's retention profile and each database's role are described, so absences can be attributed to policy rather than to deletion.
- [ ] **Epochs converted:** Mac absolute time, the quarantine xattr's hex Unix time and any Unix-epoch column were each converted and checked against a known event.
- [ ] **Stop condition cleared or declared:** log retention, FSEvents anchor absence, lost SQLite sidecars and missing APFS snapshots were each resolved or named as the reason for `Inconclusive`.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: macos-forensics
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
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)
- [`network-forensics-and-pcap`](../network-forensics-and-pcap/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `macos-forensics` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope — never boot a suspect Mac into a modified environment, never disable SIP on evidence, and never run a suspect binary to "see what it does".

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/hacktricks (2), CYBER_CPT/expku (2), CYBER_CPT/ctftime (2), CYBER_CPT/awesome_list (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
