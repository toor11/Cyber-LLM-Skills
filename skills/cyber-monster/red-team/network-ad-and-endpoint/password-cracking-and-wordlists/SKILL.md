---
name: password-cracking-and-wordlists
description: "Recovers passwords from hashes and captures: hash identification, rule and mask strategy, wordlist sourcing, and GPU versus CPU tradeoffs plus network capture cracking. Use when you hold hashes, tickets or handshakes."
family: network-ad-and-endpoint
tier: core
triggers: ["password cracking", "hashcat", "john the ripper", "wordlist", "rule based cracking", "ntlm crack"]
cwe: [CWE-521]
owasp: []
attack: [T1110]
capec: [CAPEC-55]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Password Cracking and Wordlists - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Offline recovery is a search problem with a measurable cost per candidate, and the cost is set by the hash type rather than by the tool. Kerberos RC4 service tickets and NTLM hashes sit in the fast class; Kerberos AES and modern password hashes sit in the slow class. The methodology is therefore to identify the hash type first, then choose an attack mode whose expected search space fits the engagement window, and to treat the recovered plaintext as evidence about password policy rather than as an end in itself.

- **CWE-521 (Weak Password Requirements):** The product does not require that users should have strong passwords.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the hash is a Kerberos RC4 service ticket **THEN** mode 13100; the fast class, where rule-based attacks are viable
2. **IF** the hash is an AS-REP blob **THEN** mode 18200; the same fast class but with a pre-authentication-derived salt
3. **IF** the hash is a Kerberos AES ticket **THEN** recovery is not practical at commodity scale; report the exposure, not a crack
4. **IF** the plaintext is already known and the question is reuse **THEN** that is a policy finding, not a cracking task; check the password policy and spray controls instead
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `password-cracking-and-wordlists` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The hash came from a kerberoast | [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) | How the ticket was obtained |
| The hash came from an AS-REP | [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) | No credential needed |
| The hash is local, from SAM or NTDS | [`credential-dumping-sam-and-ntds`](../credential-dumping-sam-and-ntds/SKILL.md) | Where local hashes come from |
| The password must be used rather than recovered | [`windows-lateral-movement-pass-the-hash-and-ticket`](../windows-lateral-movement-pass-the-hash-and-ticket/SKILL.md) | Reuse without cracking |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the hash type from its own header.** `$krb5tgs$23$` is RC4, `$krb5tgs$18$` is AES256, `$krb5asrep$23$` is RC4 AS-REP, and a bare 32-hex string is NTLM. The mode follows from the header, and choosing a mode by guess produces silent zero-result runs.
2. **Set a cost budget before starting.** GPU count, hash rate for that mode, and the search space of the intended rule or mask. A budget that cannot cover the space is a decision to report the hash as unbroken, which is a legitimate outcome and should be stated as one.
3. **Pick the mode that matches the evidence, not the tool default.** Dictionary plus best64 rules against a fast hash, mask attack against a known policy shape, and combinator attacks where two wordlists are relevant. Each has a different expected yield and a different time profile.
4. **Name the stop condition.** A wall-clock limit, a recovered-plaintext limit, or the end of the wordlist. A run without a limit consumes hardware indefinitely and produces a report with no closure.
5. **State the proof.** Proof is the recovered plaintext matching the hash, verified by re-hashing, plus the mode and the rule set used so the result is reproducible. A partial or candidate-only match is not a finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `hashcat -m 13100` | Proves offline recovery of an RC4 Kerberos service ticket; the fast class where rule attacks are practical; any platform with a GPU. |
| `hashcat -m 18200` | Proves recovery of an AS-REP blob, which is obtainable with no credential; any platform. |
| `hashcat -m 1000` | Proves recovery of an NTLM hash, the mode that matters after a SAM or NTDS extraction; any platform. |
| `john --format=krb5tgs` | Proves recovery on CPU where GPU access is unavailable, at much lower throughput; any platform. |
| Password policy from `Get-ADDefaultDomainPasswordPolicy` | Proves the search space the policy permits, which is what makes a mask attack's cost predictable; any AD. |

## Worked Contrast

**Weak configuration — eight-character minimum with no banned-password list, so the search space is small:**

```powershell
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength,PasswordHistoryCount,LockoutThreshold
# MinPasswordLength 8, no lockout, no banned list: a mask attack covers the space in hours
```

**Hardened configuration — length floor raised, banned-password list enforced, lockout configured:**

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity corp.example -MinPasswordLength 14 `
    -PasswordHistoryCount 24 -LockoutThreshold 5 -LockoutDuration 00:30:00
# plus a banned-password list in the password filter or Entra Password Protection
# verification: the same mask attack no longer covers the permitted space
```

**Why this matters:** offline recovery cost is a function of the permitted search space, so the policy values are the control and a re-run with the same rule set is the verification.

## When It Is NOT This Issue

- **AES tickets reported as crackable.** An AES256 service ticket is not practically recoverable; stating otherwise misrepresents both the finding and the effort.
- **A hash that recovers to a machine-account value.** Machine account passwords are long random strings; recovering one is a curiosity, not a credential finding.
- **A wordlist hit on a test account.** Lab and service accounts with documented passwords are not evidence that the policy fails; check the account's purpose before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `password-cracking-and-wordlists` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `password-cracking-and-wordlists` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: password-cracking-and-wordlists
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-521 | Mapping: T1110]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `password-cracking-and-wordlists` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-521, T1110`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 32 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/L5/ctf_search (11), CYBER_CPT/blackhills (8), OffsecCyber (4), CYBER_CPT/oxdf (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 1 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
