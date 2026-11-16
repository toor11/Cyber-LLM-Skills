---
name: active-directory-certificate-services-esc1-through-esc4
description: ADCS ESC1 to ESC4 template abuse. Covers template misconfigurations that permit requester-supplied subject, client authentication EKU abuse, enrollment agent rights and template ACL control. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["esc1 esc2 esc3 esc4", "adcs template abuse", "requester supplied subject"]
cwe: [CWE-269]
owasp: []
attack: [T1649]
capec: [CAPEC-122]
related: [active-directory-certificate-services, active-directory-certificate-services-esc5-through-esc8, network-recon-and-port-scanning, service-enumeration]
parent: active-directory-certificate-services
---

# Active Directory Certificate Services Esc1 Through Esc4 - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md)

## Mechanism and Preconditions

The first four ESC classes share one root cause: the template lets the requester decide something the CA should decide. ESC1 permits an enrollee-supplied subject so a certificate can name any user. ESC2 permits any-purpose EKU, which makes the certificate usable for client authentication regardless of intent. ESC3 permits enrollment-agent certificates, which let one principal request certificates on behalf of others. ESC4 is the container case: write access to the template object itself, which lets the trustee grant themselves any of the above.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the template supplies the subject and permits client auth **THEN** ESC1; the direct impersonation path
3. **IF** the template permits any-purpose EKU **THEN** ESC2; the certificate becomes usable for logon even if the EKU list looks harmless
4. **IF** the template is an enrollment agent template **THEN** ESC3; the agent certificate is the pivot, and the target template defines the blast radius
5. **IF** a non-tier-0 group can write the template object **THEN** ESC4; treat it as equivalent to controlling every certificate that template issues
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-certificate-services-esc1-through-esc4` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| CA permissions, relay and web enrollment | [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) | CA object rights and HTTP enrollment |
| The CA has newer classes: v1 templates, SID extension, server auth | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | ESC15, ESC16 and ESC17 conditions |
| The relay is the delivery mechanism | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Coercion into enrollment |
| The certificate is obtained and needs using | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | PKINIT to a TGT |
| Need the class-level branch table first | [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the template is published and you can enroll.** An ESC condition on an unpublished template or one your principal cannot enroll in has no path. Read the CA's `certificateTemplates` list and the template's `nTSecurityDescriptor` for the `Enroll` and `AutoEnroll` extended rights.
2. **Distinguish the four classes by their deciding attribute.** ESC1: `msPKI-Certificate-Name-Flag` bit 1 plus a client-auth EKU plus no approval. ESC2: `pKIExtendedKeyUsage` containing any-purpose. ESC3: the enrollment-agent EKU plus a writable target template. ESC4: write ACEs on the template object. Record which one applies, because the remediation differs.
3. **Check the approval and signature requirements.** `msPKI-Enrollment-Flag` bits for manager approval and the `msPKI-RA-Signature` count decide whether a second principal is required. A template with ESC1 conditions but manager approval is a weaker finding, and saying so is more accurate than an unconditional severity.
4. **Baseline against a hardened template set.** A hardened set has no v1 templates, no enrollee-supplied subject on client-auth templates, no any-purpose EKU, and enrollment restricted to named groups. Deviation is the finding, and the deviation class is the ESC number.
5. **State the proof.** Proof is the template attribute tuple, the enrollment ACE, and — for ESC4 — the write ACE on the template container. The certificate itself is only needed when the report must show the resulting identity.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ENROLLEE_SUPPLIES_SUBJECT` on a client-auth template | Proves ESC1: any enrollee can request a certificate naming another user; AD CS on any Windows Server CA. |
| `pKIExtendedKeyUsage` = `2.5.29.37.0` (any purpose) | Proves ESC2: the certificate is accepted wherever any EKU is required, including smart-card logon; AD CS. |
| Enrollment agent EKU `1.3.6.1.4.1.311.20.2.1` | Proves ESC3 preconditions, where the agent certificate defines whose certificates can be requested; AD CS. |
| `WriteProperty` or `GenericWrite` on a `pKICertificateTemplate` object | Proves ESC4: the trustee can enable any of the other conditions at will; AD CS. |
| `msPKI-RA-Signature` count above zero | Proves an issuance policy or RA signature is required, which changes ESC1 and ESC3 from direct to two-step; AD CS. |

## Worked Contrast

**Weak configuration — client-auth template that allows the enrollee to supply the subject:**

```powershell
$t = Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp' `
    -Filter {cn -eq 'Corp-User'}
# msPKI-Certificate-Name-Flag = 1 (ENROLLEE_SUPPLIES_SUBJECT)
# pKIExtendedKeyUsage includes 1.3.6.1.5.5.7.3.2 (Client Authentication)
# any domain user can request a certificate for Administrator
```

**Hardened configuration — subject fixed by the directory and enrollment restricted:**

```powershell
$t = Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp' `
    -Filter {cn -eq 'Corp-User'}
Set-ADObject $t -Replace @{'msPKI-Certificate-Name-Flag'=0}
# plus: require manager approval, or unpublish and reissue from a v2 template
# verification: the template's name flag reads 0 and a SAN-supplied request is rejected
```

**Why this matters:** ESC1 is exactly the enrollee-supplied-subject flag, so clearing it and verifying that a supplied SAN is rejected is the only test that proves the fix.

## When It Is NOT This Issue

- **Template with supply-subject but no client-auth EKU.** Without an EKU usable for logon, the certificate cannot authenticate to a service; check the EKU list before calling it ESC1.
- **Template requiring manager approval.** The approval step breaks the direct path; the finding becomes 'excess enrollment rights plus approval dependency', which is a different risk statement.
- **Template you cannot enroll in.** If the enrollment ACE excludes your principal, the condition exists but the path does not; report it as a latent exposure and name the group that can enroll.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-certificate-services-esc1-through-esc4` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-certificate-services-esc1-through-esc4` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-certificate-services-esc1-through-esc4
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1649]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-certificate-services`](../active-directory-certificate-services/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-certificate-services-esc1-through-esc4` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1649`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/oxdf (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
