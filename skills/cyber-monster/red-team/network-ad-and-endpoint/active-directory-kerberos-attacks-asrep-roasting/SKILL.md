---
name: active-directory-kerberos-attacks-asrep-roasting
description: AS-REP roasting. Covers enumerating accounts without pre-authentication and cracking the returned AS-REP blob offline, including targeted discovery. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["asrep roast", "as-rep roasting", "no preauth"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks, active-directory-kerberos-attacks-kerberoasting, active-directory-kerberos-attacks-golden-and-silver-tickets, active-directory-kerberos-attacks-delegation]
parent: active-directory-kerberos-attacks
---

# Active Directory Kerberos Attacks Asrep Roasting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

When an account has pre-authentication disabled, the KDC will return an AS-REP encrypted with that account's key to anyone who asks, with no credential required. The reply contains a ciphertext that can be attacked offline exactly like a service ticket, and the only precondition is the `DONT_REQ_PREAUTH` flag on the account. This is the only roasting variant reachable from a completely unauthenticated position, which makes it the highest-value enumeration target in a domain.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** no account list exists **THEN** enumerate usernames first; the roasting request needs a valid `sAMAccountName` and returns a distinguishable error for invalid ones
3. **IF** the account list is large **THEN** request in a bounded batch and stop at the first AS-REP; every request logs a 4768 event
4. **IF** accounts with SPNs are the target **THEN** that is [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md); AS-REP applies only to pre-auth-disabled accounts
5. **IF** the account is AES-restricted **THEN** the AS-REP is AES-encrypted and not practically recoverable; record the exposure and downgrade the severity
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-kerberos-attacks-asrep-roasting` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| An SPN account is the target | [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) | Requires a credential, different ticket type |
| Usernames are unknown | [`active-directory-enumeration-unauthenticated-enumeration`](../active-directory-enumeration-unauthenticated-enumeration/SKILL.md) | Username discovery precedes this step |
| Offline recovery is authorised | [`password-cracking-and-wordlists`](../password-cracking-and-wordlists/SKILL.md) | Mode 18200 and rule strategy |
| The account is privileged and no crack is possible | [`active-directory-acl-targeted-kerberoast-shadow-credentials`](../active-directory-acl-targeted-kerberoast-shadow-credentials/SKILL.md) | Alternative path when the ciphertext is AES |
| Need the class-level branch table first | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the flag before requesting anything.** `userAccountControl` bit 0x400000 (`DONT_REQ_PREAUTH`) is the precondition. Reading it requires a credential or a readable anonymous attribute set; if neither is available, the request itself is the enumeration.
2. **Distinguish the error classes.** An AS-REP for a valid pre-auth-disabled account, `KDC_ERR_PREAUTH_REQUIRED` for a normal account, and `KDC_ERR_C_PRINCIPAL_UNKNOWN` for a missing one. The three errors are the technique's whole signal, so capture the exact error rather than a tool's summary.
3. **Request one account at a time in a bounded batch.** Each request produces a 4768 event. A batch against every user in the domain is a loud, unmistakable pattern; a short list of candidate accounts is sufficient to prove the exposure.
4. **Set the stop condition at the first AS-REP.** One returned AS-REP proves the account is roastable without credentials. Continuing through the list after that adds events without adding proof.
5. **State the proof.** Proof is an AS-REP returned for a named account, the `userAccountControl` value showing the flag, and the encryption type of the returned blob. The recovered password, if any, is a separate finding about password strength.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `impacket-GetNPUsers ... -no-pass` | Proves the AS-REP is returned with no credential and shows the encrypted blob's format; any AD with a pre-auth-disabled account. |
| `userAccountControl` 0x400000 | Proves the account-level flag that enables the technique; any AD. |
| `KDC_ERR_PREAUTH_REQUIRED` versus an AS-REP | Proves the account's pre-authentication state per username, which is also an account-existence oracle; any KDC. |
| AS-REP blob format `$krb5asrep$23$` | Proves the blob is RC4-encrypted and therefore in the cheap-to-attack class; any AD. |
| `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}` | Proves the complete roastable set from directory metadata alone; any AD. |

## Worked Contrast

**Weak configuration — an account with pre-authentication disabled and RC4 permitted:**

```powershell
Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth $true
Set-ADUser svc_legacy -Replace @{'msDS-SupportedEncryptionTypes'=4}
# an unauthenticated host receives an RC4 AS-REP for svc_legacy on request
```

**Hardened configuration — pre-authentication required and AES-only types:**

```powershell
Set-ADAccountControl -Identity svc_legacy -DoesNotRequirePreAuth $false
Set-ADUser svc_legacy -Replace @{'msDS-SupportedEncryptionTypes'=24}
# verification: the same unauthenticated request now returns KDC_ERR_PREAUTH_REQUIRED
```

**Why this matters:** the KDC only hands out the blob because the account opted out of pre-authentication, so the flag is the control and the KDC error change is the verification.

## When It Is NOT This Issue

- **A pre-auth-disabled account that is AES-only.** The AS-REP is still returned, but AES256 blob recovery is not practical; describe the exposure as an information leak rather than a credential path.
- **A disabled account with the flag set.** A disabled account cannot be used even if the password is recovered; check `ACCOUNTDISABLE` before assigning severity.
- **`KDC_ERR_PREAUTH_REQUIRED` read as failure.** That error is the hardened, expected answer for a normal account; treating it as an error in the tooling leads to false 'no accounts found' conclusions.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks-asrep-roasting` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks-asrep-roasting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks-asrep-roasting
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
- [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks-asrep-roasting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 7 |
| Top sources | cyber-security/CyberSec-Dataset (8), CYBER_CPT/github_security_md (8), CYBER_CPT/oxdf (3), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
