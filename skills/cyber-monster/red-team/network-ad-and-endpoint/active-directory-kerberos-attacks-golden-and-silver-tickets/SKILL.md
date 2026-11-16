---
name: active-directory-kerberos-attacks-golden-and-silver-tickets
description: Golden and silver ticket forgery. Covers forging TGTs with the krbtgt hash and service tickets with service account hashes, including domain SID and PAC considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["golden ticket", "silver ticket", "krbtgt forge", "ticket forgery"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks, active-directory-kerberos-attacks-kerberoasting, active-directory-kerberos-attacks-asrep-roasting, active-directory-kerberos-attacks-delegation]
parent: active-directory-kerberos-attacks
---

# Active Directory Kerberos Attacks Golden and Silver Tickets - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

A forged ticket works because services trust the KDC's signature rather than verifying entitlement. A golden ticket is a TGT signed with the krbtgt key, so it can assert any user and any group membership and is valid until the krbtgt password is rotated twice. A silver ticket is a service ticket signed with a service account's key, so it grants access to that one service without touching the KDC and without generating a 4769 event at all — the absence of a ticket request is precisely why silver tickets are harder to detect than golden ones.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the krbtgt key is not held **THEN** a golden ticket is not possible; look for a silver ticket path via a service account key, or for delegation instead
3. **IF** a service account key or password is held **THEN** silver ticket applies, and it produces no KDC event, so detection must come from the service host
4. **IF** the goal is durable access rather than a demonstration **THEN** that is persistence and belongs to [`active-directory-persistence`](../active-directory-persistence/SKILL.md)
5. **IF** a ticket is held and needs using **THEN** use [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-kerberos-attacks-golden-and-silver-tickets` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A real ticket is held rather than forged | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | Injection and pass-the-ticket |
| Access must survive remediation | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | Durable mechanisms and cleanup |
| Delegation provides the ticket instead | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | S4U chains without key material |
| A service key was recovered from a host | [`credential-dumping-lsass-and-memory`](../credential-dumping-lsass-and-memory/SKILL.md) | Where service keys are recoverable |
| Need the class-level branch table first | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the key material actually held.** A silver ticket needs the service account's key or password; a golden ticket needs the krbtgt hash. If neither is in hand, this branch does not apply, and saying so is the correct outcome.
2. **Determine key age and rotation state for the golden case.** Forge a TGT and use it. Success plus a `4768` event with an unexpected `TicketEncryptionType` proves the key is current; the krbtgt password last-set date tells you how long the window is, and a double rotation closes it.
3. **Choose the ticket type by what the evidence supports.** Golden for domain-wide assertion where krbtgt is held, silver for a single service where only its key is held. The two produce different telemetry, so the choice changes what the report can claim.
4. **Set the stop condition at first successful service access.** One successful authenticated request against the target service proves the forgery. Repeated access adds nothing and creates a usage trail that complicates cleanup.
5. **State the proof.** Golden: a TGT accepted by a domain controller with no corresponding legitimate 4768 for that principal. Silver: a service accepting a ticket for a principal that never requested one, visible in the service's own 4624 log with no matching 4769 on the DC.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `krbtgt` password last-set date | Proves how long a golden ticket remains valid and whether one rotation or two are needed to close the exposure; any AD. |
| 4768 with unexpected `TicketEncryptionType` | Proves a TGT was issued or accepted in a form inconsistent with the account's configuration; domain controllers. |
| Service 4624 with no matching DC 4769 | Proves a silver ticket, because the service authenticated a ticket that was never issued; the service host and the DC logs compared. |
| Service account SPN and key | Proves which services a silver ticket can target once that key is recovered; any AD. |
| `AllowedToAuthenticate` PAC groups | Proves the blast radius a forged PAC can assert, which is why krbtgt rotation is a two-step process; any AD. |

## Worked Contrast

**Weak configuration — krbtgt key unchanged for years, so any historical copy still forges valid TGTs:**

```powershell
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
# a key recovered from any backup or DC snapshot still signs TGTs accepted domain-wide
```

**Hardened configuration — krbtgt rotated twice with a replication interval between:**

```powershell
# rotate once, wait for full replication to every DC, then rotate again
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
# verification: both rotations visible in the attribute's history and a forged TGT from the old key now fails
```

**Why this matters:** the trust anchor is the krbtgt key, so rotation is the only control that invalidates previously forged TGTs, and it needs two passes because the previous key remains valid for the replication window.

## When It Is NOT This Issue

- **A 4768 anomaly with a legitimate cause.** Clock skew, a recently reimaged DC, or a service account using a non-default encryption type can produce unusual `TicketEncryptionType` values; correlate with change records first.
- **A silver-ticket-looking gap caused by log shipping delay.** Service logs and DC logs arrive at different times; compare with a time window wide enough for the collector lag before concluding a ticket was never issued.
- **Backup or restore artefacts.** A restored DC can replay historical 4768 events, which look like forged TGT issuance; check for a restore in the same window.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks-golden-and-silver-tickets` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks-golden-and-silver-tickets` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks-golden-and-silver-tickets
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1558]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks-golden-and-silver-tickets` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 34 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/oxdf (9), cyber-security/CyberSec-Dataset (8), CYBER_CPT/hacktricks (5), CYBER_CPT/atomic_red_team (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
