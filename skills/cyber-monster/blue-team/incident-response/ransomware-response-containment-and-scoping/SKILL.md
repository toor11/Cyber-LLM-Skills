---
name: ransomware-response-containment-and-scoping
description: Ransomware containment and scoping. Covers rapid containment decisions, identifying all encrypted and staging hosts, and preventing re-entry during recovery. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["ransomware containment", "ransomware scope", "stop spread"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ransomware-response, ransomware-response-recovery-and-restore, ransomware-response-strain-and-actor-identification, incident-response-playbooks]
parent: ransomware-response
---

# Ransomware Response Containment and Scoping - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

Containment in a ransomware incident is not the act of isolating the hosts that are visibly encrypting. By the time encryption is visible, the operator has had days to establish credentials, service accounts, remote-management paths and a second foothold, so the visible hosts are the symptom set and the operator's access is the actual target. Scoping therefore means answering three separate questions with evidence: which hosts carry encrypted or staged content, which credentials and management paths can still reach them, and which of those paths were created or modified during the intrusion rather than before it. The precondition that makes containment possible instead of theatre is a management plane the responders can still use — an out-of-band path, a separate credential, a tested break-glass account — because the fastest way to lose an incident is to isolate the network and discover the only route into the surviving infrastructure went through the hosts just isolated.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `ransomware-response-containment-and-scoping` **THEN** start at parent class [`ransomware-response`](../ransomware-response/SKILL.md) first.
2. **IF** encryption is still advancing **THEN** isolate at the segment, VLAN or share boundary first and accept partial host-level capture; **IF** encryption has stopped **THEN** capture volatile state on a representative host of each role before isolating anything.
3. **IF** the operator holds a live credential — a service account, a domain account, a VPN session — **THEN** take the identity-first branch and revoke sessions and reset credentials before host isolation, because an isolated host with a valid token is still an access path.
4. **IF** the affected estate spans multiple sites, hypervisor clusters or cloud accounts **THEN** take the control-plane branch: contain the management plane (hypervisor, backup console, identity provider) before the data plane, or the operator will simply move to the segment you have not reached yet.
5. **IF** a host appears clean but its share enumeration, backup agent or management service was modified inside the window **THEN** treat it as in-scope; staging is a scope signal, not an out-of-scope note.
6. **IF** the containment action would remove the responders' own access path **THEN** **STOP** and validate the alternate route first, and record the break-glass use.
7. **IF** telemetry covering the staging or spread window is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ransomware-response`](../ransomware-response/SKILL.md) | Onset clock, entry branch and disclosure routing |
| Need the scope and staging evidence classes | [`QUERIES.md`](QUERIES.md) | Share-write, staging, share-enumeration and re-entry queries |
| Need isolation, collection and share-enumeration flags | [`TOOLS.md`](TOOLS.md) | Read-only enumeration before any boundary change |
| Need the containment decision matrix | [`PLAYBOOK.md`](PLAYBOOK.md) | Authority, ordering and re-entry validation |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Vector closed, ready to restore | [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) | Restore ordering depends on closure evidence |
| Need to know which family expects which next move | [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) | Anticipating the next stage changes what you contain first |

## Procedure

1. **Confirm the evidence source per segment before drawing a boundary.** Enumerate which segments have endpoint telemetry, file-server object-access auditing, hypervisor logging and identity audit, and which do not. A segment with no collection path cannot be declared clean; it can only be declared unmeasured, and unmeasured segments are in scope for isolation.
2. **Choose the branch from what the operator holds, not from what is burning.** Segment-first when encryption is advancing and identity evidence is absent; identity-first when a live credential is confirmed; control-plane-first when the estate spans hypervisors, backup consoles or cloud accounts. State the branch in the output, because it determines the isolation sequence.
3. **Define the staging-versus-benign differential.** Staging looks like ordinary file activity until it is compared against the host's own history: a share enumeration that spans more directories than any baseline day, a compression or archive utility first-seen on that host, a write pattern that touches many source paths and few destinations. Run the comparison over the same window for a peer host that was not affected, and report the difference rather than the raw count.
4. **Bound the scope explicitly and name the stop condition.** State the earliest corroborated staging or encryption event, the latest observed event per host, and the containment timestamp. Stop and declare `Inconclusive` on scope when a segment's collection started after the intrusion window, when the file-server audit log was disabled during the window, or when the only evidence of staging is an archive utility's presence without a corresponding write pattern.
5. **State what counts as proof.** Proof of scope is a write or enumeration event on a monitored host inside the bounded window, or a file whose content differs from a known-good copy. Proof of containment is a verified absence of new encryption, staging or share-enumeration events after the isolation timestamp across every collection path that exists — not the successful dispatch of an isolation command, and not a host that merely stopped reporting.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Archive or compression utility first-seen on a server with a many-source few-destination write pattern | staging | Collection and packaging preceded encryption; the destination of that archive is the exfiltration question |
| Share enumeration spanning more directories than any baseline day for that account | discovery | The account was used to map data, which places the account in scope even if its host is clean |
| Share write burst by a service account on a host it never wrote to before | lateral spread | Encryption or staging reached this host through a machine account, not a human one |
| New local administrator or new remote-management service inside the window | persistence | A re-entry path exists that host isolation alone does not close |
| Segments whose collection started after the intrusion window | coverage gap | Nothing about that segment is provable; it stays in scope |
| Encrypted file whose content differs from the last known-good copy | impact | Encryption occurred on this host, bounding the per-host onset |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`isolate`):**

```powershell
# ANTI-PATTERN: isolate by hostname list, then declare the incident contained.
# No segment coverage check, no identity revocation, no re-entry path check.
Get-Content .\affected-hosts.txt | ForEach-Object {
    Invoke-Command -ComputerName $_ -ScriptBlock { Stop-Service -Name LanmanServer -Force }
}
Write-Output "Contained: all listed hosts isolated"
```

**Behavior-Anchored Detection & Guarded Triage (`isolate` — CWE-778):**

```powershell
# Scope and containment evidence, read-only until the boundary is justified.
$isolatedAt = Get-Date "2026-11-14T04:00:00Z"

# 1. Is this host carrying staged content? Compare write fan-out against its peer.
$probe = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145;
             StartTime=$isolatedAt.AddHours(-6)} -ErrorAction SilentlyContinue
if (-not $probe) {
    Write-Warning "No object-access events for the window -> scope INCONCLUSIVE for this host"
}

# 2. Does a re-entry path exist that isolation will not close?
Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue
Get-Service | Where-Object { $_.Name -match '^(remote|teamviewer|screenconnect|anydesk)' }

# 3. Confirm the isolation actually stopped writes: re-read after the boundary.
$after = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145; StartTime=$isolatedAt} `
             -ErrorAction SilentlyContinue
if ($after) { Write-Warning "Object writes still recorded after containment timestamp" }
```

**Why this matters:** the strong form treats coverage, re-entry paths and post-isolation writes as the containment evidence, so a host that stopped reporting is distinguished from a host that stopped encrypting; the brittle form equates a successful command with containment and leaves the operator's credential and persistence untouched.

## When It Is NOT This Issue

- **Ordinary bulk file movement:** a migration, a deduplication job or a legitimate archival run produces the same fan-out write pattern with no first-seen archive utility and no change record gap. Check the job scheduler before scoping the host.
- **A share enumeration by an approved inventory or DLP tool:** asset-inventory scanners and data-classification crawlers enumerate far more directories than any human. Verify the executing principal against the tool inventory.
- **An isolated host that stopped reporting for a benign reason:** a rebooted host, a reimaged machine or a network change after isolation looks identical to a contained host in a dashboard. Confirm with an out-of-band health check before counting it as contained.
- **Encryption that predates the incident:** a legacy encrypted volume, an application-level encryption feature or a filesystem-level encryption policy can look like mass renaming on first inspection. Compare the extension against the estate inventory from before the window.
- **A staging directory that is a sanctioned workflow:** an ETL landing zone, a media transcode cache or a backup spool directory is many-source few-destination by design. Establish the sanctioned spool set before treating a directory as staging.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host, segment or tenant is clean when telemetry covering the staging or spread window was disabled, rotated out, or uncollected.**
- **NEVER record a dispatched isolation command as containment** — containment requires verified absence of new activity after the boundary.
- **NEVER recommend isolating a management plane, domain controller or backup console without first validating an alternate responder access path.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Segment coverage declared:** every segment in scope has a named collection path, and segments without one are stated as unmeasured rather than clean.
- [ ] **Branch stated:** segment-first, identity-first or control-plane-first was chosen from what the operator holds and named in the output.
- [ ] **Staging differential defined:** write fan-out and enumeration breadth were compared against a peer host and the host's own baseline, not against a fixed threshold.
- [ ] **Re-entry paths enumerated:** new local administrators, new remote-management services and live credentials were listed before containment was declared complete.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: ransomware-response-containment-and-scoping
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`ransomware-response-recovery-and-restore`](../ransomware-response-recovery-and-restore/SKILL.md) - Incident Response (leaf)
- [`ransomware-response-strain-and-actor-identification`](../ransomware-response-strain-and-actor-identification/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ransomware-response-containment-and-scoping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Victim-side scope:** containment breadth, evidence preservation and re-entry closure only. No actor communication, payment or negotiation content.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/go_exploitdb (3), cyber-security/CyberSec-Dataset (1), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
