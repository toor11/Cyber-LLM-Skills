---
name: ransomware-response-recovery-and-restore
description: Ransomware recovery and restore. Covers validating backup integrity, restore ordering, and confirming the entry vector is closed before restore. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["ransomware recovery", "backup restore", "restore validation"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ransomware-response, ransomware-response-containment-and-scoping, ransomware-response-strain-and-actor-identification, incident-response-playbooks]
parent: ransomware-response
---

# Ransomware Response Recovery and Restore - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Recovery is where a contained ransomware incident is either resolved or quietly replayed. Three properties decide which: whether the restore point predates the earliest pre-impact artifact rather than merely the earliest encryption, whether that point is immutable and physically separated so the credentials the operator held could not have reached it, and whether the entry vector and the persistence the operator installed were closed before the first restored host came online. CISA's #StopRansomware guidance is explicit that backups must be encrypted, immutable, tested, and stored in a physically separate segmented location — Gunra (AA26-222A) names the separate segmented location specifically, because a backup tier reachable from the compromised identity is a backup the operator can delete. The precondition that makes recovery a plan rather than a hope is a restore that has actually been exercised before the incident: an untested restore is a hypothesis, and the incident is the worst possible moment to test it.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `ransomware-response-recovery-and-restore` **THEN** start at parent class [`ransomware-response`](../ransomware-response/SKILL.md) first.
2. **IF** the restore point is later than the earliest pre-impact artifact **THEN** **STOP** — that backup restores the implant with the data; find an older point or restore data only into a rebuilt, verified-clean platform.
3. **IF** the entry vector's closure has not been demonstrated by a failed re-authentication attempt **THEN** take the vector-closure-first branch and hold restore; restoring into an open vector is a scheduled re-infection.
4. **IF** the backup target is reachable with the credentials the operator held **THEN** treat that backup as suspect regardless of its age, and validate it from an isolated copy before relying on it.
5. **IF** the estate is heterogeneous — domain services, file services, line-of-business applications, OT — **THEN** take the dependency-order branch: restore identity and DNS first, then the services that authenticate against them, then data, and record the order before starting.
6. **IF** a restored host re-encrypts or re-contacts a known-bad destination within the observation window **THEN** treat restore as failed, return to containment, and do not restore further hosts until the cause is identified.
7. **IF** telemetry covering the restore validation window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ransomware-response`](../ransomware-response/SKILL.md) | Onset clock and disclosure routing |
| Need the integrity and validation evidence classes | [`QUERIES.md`](QUERIES.md) | Restore-point provenance, immutability, post-restore observation |
| Need backup CLI and validation flags | [`TOOLS.md`](TOOLS.md) | Read-only catalog inspection and restore dry run |
| Need the recovery decision matrix and sequencing | [`PLAYBOOK.md`](PLAYBOOK.md) | Order, authority and rollback criteria |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Vector still open | [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) | Restore must not start before closure |
| Need to know which family's persistence to expect | [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) | Persistence shape varies by family |

## Procedure

1. **Confirm the evidence source for the restore decision before touching a backup.** Enumerate the backup catalogue, the immutability state of the target, the last verified restore test and the earliest pre-impact artifact on each host to be restored. A restore plan built without the last item is a plan to reinstate the intrusion.
2. **Choose the branch from the closure and dependency evidence.** Vector-closure-first when the entry path is unproven; dependency-order-first when the estate has identity and application tiers; data-only-first when platform rebuild is required and only the data can be trusted. Name the branch and the evidence behind it.
3. **Define the validation differential that separates a clean restore from a compromised one.** For each restored host compare the pre-restore state and the post-restore state on three dimensions: authentication events by principal, first-seen outbound destinations, and first-seen services or scheduled tasks. A restored host that reproduces the original host's pre-incident first-seen set has restored the compromise.
4. **Bound the observation window and name the stop condition.** State the observation period per restored host and the criteria that end it. Stop and declare `Inconclusive` when the restore point's provenance is unverifiable, when the backup target's immutability claim cannot be confirmed read-only, when the closure test was skipped under schedule pressure, or when post-restore telemetry is absent so the observation window cannot close.
5. **State what counts as proof.** Proof of a valid restore is: the point timestamp precedes the earliest pre-impact artifact, the target is immutable and separated, and the restored host shows no re-contact with the intrusion's indicators across the full observation window. Proof of closure is a re-authentication attempt through the original vector that fails for the right reason — account disabled, credential rotated, path removed — not a ticket marked done.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Restore-point timestamp versus earliest pre-impact artifact | backup provenance | Whether the backup is trustworthy at all, or whether it carries the implant |
| Immutability lock state and physical or network separation of the target | backup control plane | Whether the credentials the operator held could have reached and deleted the backup |
| Last successful restore test on record, with date and scope | recovery readiness | Whether the recovery path is exercised or merely assumed |
| Failed authentication through the original entry vector after closure | identity and edge audit | The vector is genuinely closed rather than believed closed |
| First-seen outbound destination or service on a restored host | post-restore observation | Whether the compromise survived the restore |
| Restored host re-encrypting inside the observation window | impact recurrence | Restore failed; the persistence or vector remained |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`backup integrity`):**

```powershell
# ANTI-PATTERN: "the job reports success, so the backup is good"
Get-VBRJob | Select-Object Name, LastResult
# Restores the newest point regardless of when the implant landed,
# and never checks whether the backup target is reachable from the compromised identity.
```

**Behavior-Anchored Detection & Guarded Triage (`backup integrity` — CWE-778):**

```powershell
# Restore readiness: provenance, immutability and closure, all read-only.
$firstImplant = Get-Date "2026-11-09T18:20:00Z"   # earliest pre-impact artifact, from triage
$points = Get-VBRBackup | ForEach-Object {
    $job = $_
    $job.GetAllStorages() | ForEach-Object {
        [pscustomobject]@{
            Job        = $job.JobName
            PointUtc   = $_.CreationTime.ToUniversalTime()
            SafeForData = $_.CreationTime.ToUniversalTime() -lt $firstImplant
        }
    }
}

$points | Sort-Object PointUtc -Descending | Select-Object -First 10 | Format-Table -AutoSize

if (-not ($points | Where-Object SafeForData)) {
    Write-Warning "No restore point predates the earliest pre-impact artifact -> data-only recovery only"
    exit 2
}

# Immutability is a property of the target, not of the job result. Read it, do not infer it.
Get-VBRBackupRepository | Select-Object Name, Type, MountHost, @{n='Immutable';e={$_.ImmutabilityInterval}}

# Closure: the vector must fail for the right reason before any host is restored.
Write-Output "Closure test required: re-authenticate through the original vector and record the failure reason."
```

**Why this matters:** the strong form derives the safe restore set from the earliest pre-impact artifact and requires both an immutable separated target and a demonstrated closure before any restore begins, so a successful job result is never mistaken for a usable backup; the brittle form reads the job status and restores the newest point, which is precisely the point most likely to contain the operator's persistence.

## When It Is NOT This Issue

- **Backup failure unrelated to the incident:** a tape library fault, an expired credential on the backup service account or a full repository produces the same "no recent point" symptom with no adversary involved. Check repository capacity and service-account expiry before concluding sabotage.
- **Restore point that is newer but still clean:** if the operator's access predated the backup but never touched the backed-up data tier, a post-intrusion point can still be safe for that tier. That is a per-tier judgement supported by the artifact trail, not a blanket rule either way.
- **Immutability that exists in policy but not in configuration:** a repository described as immutable in the runbook but configured with a short lock window is a documentation error, not an attack. Verify the configured interval, and fix the documentation separately.
- **Application-level data loss mistaken for ransomware impact:** a failed migration, a corrupted database or a bad deployment produces unrecoverable data and angry users with no encryption and no note. Check application and database logs before invoking the ransomware recovery path.
- **A restored host that re-encrypts because of a scheduled job:** a misconfigured backup agent writing encrypted archives into the share looks like re-infection. Confirm the writing process before returning to containment.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a restored host, backup tier or tenant is clean when telemetry covering the observation window was disabled, rotated out, or uncollected.**
- **NEVER present a successful backup job result as evidence of a usable restore point.**
- **NEVER assume immutability from documentation** — read the configured lock state, and treat an unverified claim as unverified.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Provenance established:** the restore point timestamp was compared against the earliest pre-impact artifact, not merely against the encryption onset.
- [ ] **Immutability and separation verified:** the target's configured lock state and its network or physical separation were read, not assumed from policy text.
- [ ] **Closure demonstrated:** the original entry vector was re-tested and failed for a stated, correct reason before restore was scheduled.
- [ ] **Observation window defined:** per-host observation criteria and duration were stated, with the failure condition that returns the incident to containment.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ransomware-response-recovery-and-restore
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`ransomware-response-containment-and-scoping`](../ransomware-response-containment-and-scoping/SKILL.md) - Incident Response (leaf)
- [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ransomware-response-recovery-and-restore` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Victim-side scope:** backup validation, restore ordering and closure verification only. No decryptor use, payment mechanics or actor communication.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (4), CYBER_CPT/osv (2), CYBER_CPT/gh_advisories (2), CYBER_CPT/go_exploitdb (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
