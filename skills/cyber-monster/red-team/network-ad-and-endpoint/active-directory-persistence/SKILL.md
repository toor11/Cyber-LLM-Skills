---
name: active-directory-persistence
description: "Establishes durable AD access: golden and diamond tickets, SID history, AdminSDHolder, skeleton keys, DCShadow, and certificate-based persistence, with cleanup considerations. Use when demonstrating persistence impact in a red team engagement."
family: network-ad-and-endpoint
tier: core
triggers: ["ad persistence", "golden ticket persistence", "sid history", "adminsdholder", "skeleton key", "dcshadow"]
cwe: [CWE-269]
owasp: []
attack: [T1098]
capec: [CAPEC-563]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Active Directory Persistence - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

AD persistence is the set of mechanisms that survive a password reset, a host rebuild, or a normal remediation cycle. Each mechanism exploits a different trust: a forged TGT exploits the krbtgt key, SID history exploits the PAC's group list, AdminSDHolder exploits a scheduled ACL propagation, DCShadow exploits replication rights, and a certificate exploits the CA's trust in a previously issued key. The methodology is to identify which trust the mechanism abuses, because remediation is always the removal of that trust rather than the removal of the artefact.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the mechanism relies on a key **THEN** krbtgt or a service key; remediation is rotation, which is why key age is the first thing to read
2. **IF** the mechanism relies on an ACE that is re-applied **THEN** AdminSDHolder or a default ACL; remediation is the source ACE, not the propagated copy
3. **IF** the mechanism relies on a replication right **THEN** DCShadow; remediation is the replication permissions and the rogue DC registration
4. **IF** the mechanism relies on a certificate **THEN** remediation is revocation plus CA-side cleanup, since the key material remains valid until then
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-persistence` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The artefact is a forged ticket | [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | Key material and rotation |
| The artefact is a certificate | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | CA trust and revocation |
| The artefact is a scheduled task or service | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Host-level rather than directory-level |
| The artefact is an ACL grant | [`active-directory-acl-and-delegation-abuse`](../active-directory-acl-and-delegation-abuse/SKILL.md) | The ACE that produces the access |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the trust the mechanism abuses.** Every directory persistence mechanism rests on exactly one trust: a key, an ACE source, a replication permission, or a certificate issuance. Naming the trust determines the remediation and the evidence.
2. **Read the current state of that trust.** krbtgt `PasswordLastSet` and `msDS-KeyVersionNumber`, the `AdminSDHolder` DACL, the `Replicating Directory Changes All` right holders, and the issued-certificate inventory. These four reads cover the whole family.
3. **Baseline against a domain that has never been compromised.** A clean domain has a recent double krbtgt rotation, an `AdminSDHolder` DACL matching the default, replication rights only for DCs and sanctioned tooling, and a certificate inventory without unexpected templates.
4. **Set the stop condition.** Stop at the first mechanism whose trust is demonstrably still valid, because that is the one that survives remediation. Enumerating mechanisms whose trusts have already been rotated adds nothing.
5. **State the proof.** Proof is the trust's current state plus the artefact that depends on it — for example, a krbtgt key version that has not advanced since a known compromise, or an `AdminSDHolder` ACE naming a non-tier-0 trustee. The artefact alone does not prove persistence; the valid trust does.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `msDS-KeyVersionNumber` on krbtgt | Proves how many times the key has been rotated, which is the only way to invalidate previously forged TGTs; any AD. |
| `AdminSDHolder` DACL | Proves which ACEs will be re-applied to every protected account on the next propagation cycle; any AD. |
| `Replicating Directory Changes All` right holders | Proves who can perform a DCShadow-style replication write, which is persistence as a replication partner; any AD. |
| Certificate inventory per template | Proves which certificates remain valid and for how long, since revocation is the only way to withdraw them; AD CS. |
| `SIDHistory` on any account | Proves an injected group claim that survives group membership review; any AD. |

## Worked Contrast

**Weak configuration — krbtgt rotated once after an incident, leaving the previous key valid:**

```powershell
Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber
# a single rotation leaves the previous key valid for the replication window,
# so any TGT forged before the rotation still authenticates
```

**Hardened configuration — two rotations separated by full replication, with key version advanced by two:**

```powershell
# first rotation, wait for replication to every DC, then rotate again
Get-ADUser krbtgt -Properties msDS-KeyVersionNumber
# verification: msDS-KeyVersionNumber advanced by two and repadmin shows the change on every DC
repadmin /syncall /AdeP
```

**Why this matters:** the KDC accepts TGTs signed with either the current or the previous krbtgt key, so a single rotation does not close forged-ticket persistence and the key version is the only honest verification.

## When It Is NOT This Issue

- **An old krbtgt date with no compromise history.** A domain that has never been compromised can legitimately have an old krbtgt; the finding requires a reason to believe the key was exposed.
- **`SIDHistory` used for a documented migration.** SID history is a supported migration feature; check for a migration project before treating it as persistence.
- **Replication rights held by backup software.** Backup and monitoring tools legitimately hold replication rights; verify the tool's service account before reporting it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-persistence` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-persistence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-persistence
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1098]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-persistence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1098`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (8), CYBER_CPT/atomic_red_team (2), CYBER_CPT/sigmahq (1), CYBER_CPT/hacktricks (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 6 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
