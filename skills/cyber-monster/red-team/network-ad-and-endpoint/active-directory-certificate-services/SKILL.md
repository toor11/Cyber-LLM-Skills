---
name: active-directory-certificate-services
description: "Exploits AD CS misconfigurations: ESC1 through ESC8, certificate template abuse, CA permission flaws, NTLM relay to HTTP enrollment, and certificate-based persistence. Use when a Certificate Authority is present in the domain."
family: network-ad-and-endpoint
tier: core
triggers: ["adcs", "ad certificate services", "esc1", "esc8", "certificate template", "certipy"]
cwe: [CWE-269]
owasp: []
attack: [T1649]
capec: [CAPEC-122]
related: [active-directory-certificate-services-esc1-through-esc4, active-directory-certificate-services-esc5-through-esc8, network-recon-and-port-scanning, service-enumeration]
---

# Active Directory Certificate Services - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md)

## Mechanism and Preconditions

AD CS turns a template configuration into an authentication primitive, because a certificate chaining to the enterprise CA is accepted as proof of the identity in its SAN. The numbering scheme (ESC1 through ESC17) is a taxonomy of how a template or CA setting lets a requester obtain a certificate for an identity they do not control. Since 2024 the field has moved twice: ESC15 covers schema-version-1 templates accepting requester-supplied application policies, and ESC16 covers a CA that disables the SID security extension, which weakens certificate-to-account binding for every template on that CA.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the template allows the requester to supply the subject **THEN** that is the ESC1 family; go to [`active-directory-certificate-services-esc1-through-esc4`](../active-directory-certificate-services-esc1-through-esc4/SKILL.md)
2. **IF** the weakness is in CA permissions or the enrollment endpoint **THEN** go to [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md)
3. **IF** the CA has been patched recently and templates are v2 or later **THEN** check the newer classes: ESC15 (v1 templates and application policy injection), ESC16 (SID extension disabled), ESC17 (server-auth template with enrollee-supplied subject)
4. **IF** the question is whether certificates can be revoked **THEN** that is a response question; pair with the paired Blue skill rather than enumerating further
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `active-directory-certificate-services` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Template subject and enrollment-agent flaws | [`active-directory-certificate-services-esc1-through-esc4`](../active-directory-certificate-services-esc1-through-esc4/SKILL.md) | SAN supply, EKU, enrollment agent and ACL |
| CA permissions, relay and web enrollment | [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) | CA object rights and HTTP enrollment |
| The relay path is the vehicle | [`ntlm-relay-and-coercion-relay-targets`](../ntlm-relay-and-coercion-relay-targets/SKILL.md) | Coercion and relay into enrollment |
| The certificate becomes a Kerberos ticket | [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](../active-directory-kerberos-attacks-ticket-abuse-and-forgery/SKILL.md) | PKINIT and ticket use |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the CA and every published template first.** Read the `pKIEnrollmentService` object for the CA name and the `pKICertificateTemplate` objects for the published set. A template that is not published cannot be enrolled, so publication is the first filter.
2. **Rank templates by the four attributes that matter.** `msPKI-Certificate-Name-Flag` (enrollee supplies subject), `pKIExtendedKeyUsage` (client authentication or any purpose), `msPKI-Enrollment-Flag` (requires approval or manager approval), and the enrollment ACL. The combination decides which ESC number applies.
3. **Check the CA-level settings that override templates.** The policy module's `DisableExtensionList` for the SID extension OID `1.3.6.1.4.1.311.25.2` (ESC16), the CA's patch level for `CVE-2024-49019` (ESC15), and whether request-attribute and SAN handling is restricted on the CA object.
4. **Baseline against a hardened CA.** A CA with the November 2024 or later update, no v1 templates published, SID extension enabled, and enrollment restricted to named groups is the reference. Every deviation is a specific ESC class rather than a generic 'AD CS misconfigured'.
5. **State the proof and stop condition.** Proof is the template attribute values, the ACL entry, or the CA setting, read from the live directory, plus the published status that makes it reachable. Stop at the first template that yields a client-authentication certificate for an identity the requester does not control.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `msPKI-Certificate-Name-Flag` bit 1 | Proves the enrollee may supply the subject, the common precondition across ESC1, ESC15 and ESC17; any AD CS. |
| `pKIExtendedKeyUsage` containing `1.3.6.1.5.5.7.3.2` | Proves client authentication is permitted, without which the certificate cannot be used for logon; any AD CS. |
| `DisableExtensionList` containing `1.3.6.1.4.1.311.25.2` | Proves the CA omits the SID extension, weakening binding for every template it publishes (ESC16); AD CS on Windows Server with the policy module configured. |
| `msPKI-Template-Schema-Version` value 1 | Proves a schema-version-1 template, which on an unpatched CA accepts requester-supplied application policies (ESC15); AD CS. |
| `pKIEnrollmentService` `dNSHostName` and `certificateTemplates` | Proves the CA endpoint and which templates are actually published, the reachability filter; any AD CS. |

## Worked Contrast

**Weak configuration — the CA disables the SID security extension, weakening binding for every template:**

```powershell
$ca = Get-ADObject -SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example' -Filter *
# policy module DisableExtensionList includes 1.3.6.1.4.1.311.25.2
# every certificate from this CA omits the SID, so mapping falls back to weaker rules
certutil -getreg policy\DisableExtensionList
```

**Hardened configuration — SID extension enabled and strong certificate binding enforced:**

```powershell
# remove 1.3.6.1.4.1.311.25.2 from the policy module DisableExtensionList, then restart CertSvc
certutil -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2
Restart-Service CertSvc
# enforce strong binding on domain controllers
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2
# verification: a newly issued certificate carries the SID extension
```

**Why this matters:** ESC16 is a CA-wide setting rather than a per-template one, so the control is the extension list plus the KDC's binding enforcement, and the verification is inspecting a freshly issued certificate's extensions.

## When It Is NOT This Issue

- **An unpublished vulnerable template.** If the template is not in the CA's `certificateTemplates` list, it cannot be enrolled; check publication before ranking.
- **A template requiring manager approval.** The enrollment flag that requires approval breaks the direct path; an approver becomes part of the chain and must be accounted for.
- **Client authentication EKU with no subject supply.** A template that fixes the subject to the requester's own identity cannot be used to impersonate anyone else, whatever its EKU.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-certificate-services` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-certificate-services` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-certificate-services
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1649]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-certificate-services-esc1-through-esc4`](../active-directory-certificate-services-esc1-through-esc4/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-certificate-services-esc5-through-esc8`](../active-directory-certificate-services-esc5-through-esc8/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-certificate-services` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1649`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (20), SecEval/attck (1), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
