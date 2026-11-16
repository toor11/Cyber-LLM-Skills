---
name: mobile-device-forensics
description: "Acquires and analyses mobile device evidence: logical versus full filesystem acquisition, app data parsing and communication artefacts. Use when a phone or tablet is evidence."
family: digital-forensics
tier: core
triggers: ["mobile forensics", "android forensics", "ios forensics", "phone acquisition"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [disk-forensics-and-artifacts, windows-artifact-forensics, linux-forensics, macos-forensics]
---

# Mobile Device Forensics - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **core** | Paired Counterpart: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md)

## Mechanism and Preconditions

A modern phone is a file-based-encryption device, and that single fact organises the whole discipline. With file-based encryption the credential-derived key hierarchy is unlocked per file class, so what is readable depends on the device's lock state at acquisition time rather than on which extraction tool was used. After first unlock (AFU, also called hot), the keys for most data classes are in memory and an extraction can read user data; before first unlock (BFU, also called cold), the great majority of user data is inaccessible and even a full file system request returns mostly system and cache content. The extraction classes are therefore claims about what was reachable, not about how thorough the examiner was: physical acquisition reads the storage directly with encrypted content as its result; full file system returns all accessible active files and folders; partial file system returns a subset; logical asks the operating system to interpret and return data, typically through a backup protocol, an app agent or manual review. On iOS, checkm8-class bootloader extraction applies only to A7 through A11 hardware and cannot serve newer devices, while agent-based extraction covers a wider but still bounded model and OS range. On Android, full file system availability is vendor and model dependent and often requires an unlocked bootloader or a privileged agent. What none of this tells you: a logical acquisition is a filtered view chosen by the operating system, so absence in it is never absence on the device; an unallocated-space claim requires a physical or full file system image and cannot be inferred from a backup; and app data schemas change between app versions, so a parser that finds no messages in a database may be reading the wrong table rather than a device with no messages.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the device is powered on and has been unlocked since boot **THEN** take the AFU branch and acquire immediately, because lock state is the dominant variable; **IF** the device is locked and has not been unlocked since boot **THEN** take the BFU branch and state up front which data classes will be unavailable.
2. **IF** the device is iOS and the model is newer than A11 **THEN** checkm8 is not available and the acquisition must be agent-based or logical; **IF** the device is Android **THEN** check the vendor-specific full-file-system support for that exact build before promising an extraction class.
3. **IF** the requested evidence is messages, call logs or app content **THEN** require an extraction class that actually reaches app data, and state which class you obtained; **IF** only a logical backup is available **THEN** report the class and never describe missing items as deleted.
4. **IF** the device is powered off **THEN** do not power it on without deciding whether a BFU or AFU state is more useful, since powering on a previously-unlocked-and-then-powered-off device changes what is reachable.
5. **IF** the case involves cloud-backed app data **THEN** treat the cloud account as a separate acquisition with its own legal process, not as a fallback for a failed device extraction.
6. **IF** telemetry source covering `logical acquisition` or `full filesystem` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).
8. **IF** required preconditions for `mobile-device-forensics` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the host-side artefacts of a synced device | [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) | Backup folders, LNK and jump-list evidence of a sync |
| Need deleted-content recovery from a filesystem image | [`file-carving-and-recovery`](../file-carving-and-recovery/SKILL.md) | Carving unallocated space from a physical or full file system image |

## Procedure

1. **Confirm the device state, the extraction class and the tool's coverage for that exact build before acquiring.** Record the model, the OS build, whether the device had been unlocked since boot, whether it is powered on, and which extraction classes the tool claims for that model and build. Then hash the resulting image and record the tool version. Without the lock state and the class, the resulting image cannot be interpreted later, because the same tool on the same device produces wildly different content across states.
2. **Choose the branch from the lock state and the question.** AFU takes the user-data branch. BFU takes the system-and-metadata branch, where you can still obtain device logs and installed-app inventory but not message content. A powered-off device takes the decision branch: whether to attempt bootloader extraction (where supported) or to preserve the state for a later AFU acquisition. Record the branch, since every absence claim downstream depends on it.
3. **Establish the baseline-versus-probe differential against a same-build reference device and against the app's own database schema.** For each app database, confirm the schema version, then compare row counts and date ranges against a reference device of the same app version. A parser returning zero rows from a valid database is a schema mismatch; a database whose newest row is days before the seizure is a sync or retention boundary, not a deletion.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the extraction class cannot reach the data class the question concerns (a logical backup for a deleted-message question), when the app database schema is newer than the parser supports, when the device is BFU and user data is encrypted, or when the tool's coverage matrix does not include that model and build.
5. **State what counts as proof.** Proof is two independent sources agreeing on the same event: a message row in the app database and a matching notification or call-log record, or a media file with its embedded capture time and a database row referencing the same path. A single app database is one source, and a backup that excludes a data class cannot corroborate anything about that class.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| AFU full file system image containing app sandbox databases, versus a BFU image of the same device type lacking them | Extraction class versus lock state | Proves the reachable data set is a function of lock state on file-based-encryption devices, so an empty result is a state property before it is a device property |
| App database table with rows whose timestamps run to the seizure time | SQLite database inside the app sandbox | Proves the app was active and writing up to that point on iOS or Android; a table stopping earlier proves a boundary, not a deletion |
| Media file whose embedded capture time precedes its filesystem creation time by hours | EXIF or container metadata versus filesystem timestamp | Proves the file was captured earlier and written later, which is normal for camera-to-gallery moves and is not timestomping |
| Backup manifest listing an app whose data directory is absent from the extraction | Logical backup manifest versus extracted tree | Proves the OS excluded that app's data from the backup class on that device, which is a protocol limit rather than concealment |
| Unallocated space carved from a physical image yielding message fragments absent from the live database | Physical or full file system image plus carving | Proves deleted content survived on the storage medium; it does not prove the user deleted it deliberately |
| Device log bundle showing repeated unlock failures followed by a success inside the incident window | System log bundle from the extraction | Proves authentication attempts against the device at those times; it does not identify the person holding it |

## Worked Contrast

**Weak / Noisy Practice:**

```text
# ANTI-PATTERN: run the tool, export everything, and describe the export.
# Tool GUI: logical acquisition, "all data", then export to PDF/CSV.
# Then: "the device contains no deleted messages, so the suspect deleted them."
# No lock state recorded, no extraction class recorded, no reference device,
# no schema check, and the conclusion is drawn from an OS-filtered view.
```

**High-Signal Grounded Artifact:**

```python
#!/usr/bin/env python3
"""mobile-scope.py — record class and state, then measure schema and recency."""
import hashlib, sqlite3, sys, os
from datetime import datetime, timezone

EXTRACT_DIR = sys.argv[1] if len(sys.argv) > 1 else "./extraction"
MANIFEST = os.path.join(EXTRACT_DIR, "case_manifest.yaml")

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# 1. State and class are recorded before content is read: they bound every claim.
print("=== scope (must be filled from the acquisition record) ===")
for field in ("model", "os_build", "lock_state", "extraction_class", "tool_version"):
    print(f"{field:18} = <from acquisition record>")

# 2. Content: schema version and newest row, per database. A zero-row read from
#    a present database is reported as a schema mismatch, never as no data.
for root, _, files in os.walk(EXTRACT_DIR):
    for name in files:
        if not name.endswith((".db", ".sqlite", ".sqlite3")):
            continue
        path = os.path.join(root, name)
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            rows = sum(con.execute(f"SELECT COUNT(*) FROM \"{t}\"").fetchone()[0]
                       for t in tables)
            print(f"{sha256(path)[:16]}  tables={len(tables):3d} rows={rows:8d}  {path}")
            con.close()
        except sqlite3.DatabaseError as exc:
            print(f"UNREADABLE (WAL or encryption?) {path}: {exc}")
```

**Why this matters:** the weak form reads an OS-filtered logical view and draws a deletion conclusion from it, with no record of the class that produced the view. The strong form prints the five fields that bound every possible claim before reading content, opens each database read-only with `immutable=1` so the WAL is not replayed into the evidence, reports schema and row counts so a zero-row result is visible as a schema or table-choice problem, and refuses to conflate an unreadable database with an empty one.

## When It Is NOT This Issue

- **A logical backup missing an app's data:** the backup class is chosen by the operating system and excludes many app sandboxes, caches and system logs by design. Report the class; do not report the missing content as deleted or concealed.
- **A BFU extraction with little user data:** file-based encryption means the data is not readable, not absent. The correct statement is that the acquisition could not reach the data class, and the recovery path is a later AFU acquisition if lawful.
- **An app database parser returning zero messages:** app schemas change between versions and messages are often split across tables with attachments in separate files. Confirm the schema and the table names before concluding the app held nothing.
- **Media files whose creation time trails their capture time:** camera imports, cloud downloads and messaging apps all write files after capturing them. Embedded metadata and filesystem timestamps measuring different events is normal, not timestomping.
- **Deleted items absent from a physical image:** modern devices run continuous TRIM and background garbage collection, so unallocated content may be gone within hours of deletion. Absence from unallocated space is a maintenance outcome, not proof of a wipe.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `logical acquisition` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **State recorded:** model, OS build, lock state at acquisition and whether the device was powered on are documented before any content claim.
- [ ] **Class recorded:** the extraction class obtained is named, and no claim exceeds what that class can reach.
- [ ] **Tool coverage verified:** the tool's published coverage for that model and build was checked, and any gap is stated rather than assumed away.
- [ ] **Schema confirmed:** each app database's schema was checked against the parser's supported version before a zero-row result was interpreted.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: mobile-device-forensics
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

- **Lock state is the variable:** two acquisitions of the same device can differ by an order of magnitude in content purely because of whether it had been unlocked since boot. Record it before anything else.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; acquisition of a personal device requires lawful authority, and any network-isolation step must be taken before the device can sync or remote-wipe.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 7 |
| Top sources | Forensic_Toolkit_Dataset (5), CYBER_CPT/ctf_search (3), CYBER_CPT/hacktricks (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 5 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
